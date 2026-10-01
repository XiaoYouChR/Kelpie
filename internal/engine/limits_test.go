package engine

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/disk"
	"github.com/XiaoYouChR/Kelpie/internal/identity"
	"github.com/XiaoYouChR/Kelpie/internal/peer"
	"github.com/XiaoYouChR/Kelpie/internal/piece"
	"github.com/XiaoYouChR/Kelpie/internal/wire"
	"github.com/XiaoYouChR/Kelpie/internal/wire/client"
)

// openRaw opens a TCP connection from a new host at ip to n, for tests that
// write bytes no well-behaved client would.
func (w *world) openRaw(ip string, n *node) net.Conn {
	w.t.Helper()
	host := w.network.AddHost(netip.MustParseAddr(ip))
	w.t.Cleanup(host.Close)
	conn, err := host.OpenTCP(context.Background(), n.endpoint())
	if err != nil {
		w.t.Fatal(err)
	}
	return conn
}

// requireClosed reads conn until the engine closes it.
func requireClosed(t *testing.T, conn net.Conn) {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(waitTimeout))
	if _, err := io.Copy(io.Discard, conn); err != nil {
		t.Fatalf("connection not closed by the engine: %v", err)
	}
}

func TestOversizedFrameClosesConnection(t *testing.T) {
	w := buildWorld(t)
	b := w.addNode("198.51.100.2")
	b.start()
	conn := w.openRaw("198.51.100.9", b)
	head := []byte{wire.ProtocolEDonkey, 0, 0, 0, 0, 0x01}
	binary.LittleEndian.PutUint32(head[1:5], wire.MaxFrameSize+1)
	conn.Write(head)
	requireClosed(t, conn)
}

// rawPeer is a client whose reads the test controls: it reads only while a
// readUntil runs, so it can stop reading like a stalled peer.
type rawPeer struct {
	w       *world
	conn    net.Conn
	session *peer.Session
	mu      sync.Mutex
	events  []peer.Event
}

func (w *world) openRawPeer(ip string, n *node) *rawPeer {
	w.t.Helper()
	addr := netip.MustParseAddr(ip)
	self, err := identity.CreateSelf()
	if err != nil {
		w.t.Fatal(err)
	}
	cfg := peer.Config{
		Self:     self,
		Version:  "0.50.0",
		ClientID: wire.ToClientID(addr),
		PublicIP: addr,
		Port:     peerPort,
		UDPPort:  peerPort + 10,
		Pipeline: pipeline,
		Random:   rand.New(rand.NewPCG(7, 7)),
	}
	p := &rawPeer{w: w, conn: w.openRaw(ip, n)}
	session, out := peer.BuildOutgoing(cfg, n.endpoint(), w.clock.Now())
	p.session = session
	p.send(out.Send...)
	return p
}

func (p *rawPeer) send(packets ...wire.Packet) {
	for _, packet := range packets {
		p.conn.Write(wire.BuildPacket(nil, packet))
	}
}

// readUntil reads and answers packets until the session reports an event
// that match accepts, then stops reading.
func (p *rawPeer) readUntil(what string, match func(peer.Event) bool) {
	p.w.t.Helper()
	p.conn.SetReadDeadline(time.Time{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		r := bufio.NewReader(p.conn)
		for {
			frame, err := wire.ParseFrameFrom(r)
			if err != nil {
				return
			}
			packet, err := client.Parse(frame.Protocol, frame.Opcode, frame.Body)
			if err != nil {
				return
			}
			p.mu.Lock()
			out := p.session.OnPacket(packet, func(wire.Hash) (peer.Share, bool) { return peer.Share{}, false }, p.w.clock.Now())
			p.events = append(p.events, out.Events...)
			p.mu.Unlock()
			p.send(out.Send...)
		}
	}()
	p.w.waitFor(what, func() bool {
		p.mu.Lock()
		defer p.mu.Unlock()
		return slices.ContainsFunc(p.events, match)
	})
	p.conn.SetReadDeadline(time.Now())
	<-done
}

func isEvent[T peer.Event](ev peer.Event) bool {
	_, ok := ev.(T)
	return ok
}

// A peer that keeps asking without reading the answers is dropped once its
// writer backlog is full, instead of growing it without end.
func TestFloodWithoutReadingCloses(t *testing.T) {
	w := buildWorld(t)
	a := w.addNode("198.51.100.1")
	a.start()
	f := buildTestFile("flood.bin", 100_000, 3)
	a.seed(1, f)
	p := w.openRawPeer("198.51.100.9", a)
	p.readUntil("the handshake", isEvent[peer.HandshakeCompleted])
	go func() {
		for range 40_000 {
			if _, err := p.conn.Write(wire.BuildPacket(nil, client.SetRequestFileID{Hash: f.hash})); err != nil {
				return
			}
		}
	}()
	requireClosed(t, p.conn)
}

// countingDisk counts the bytes read from its files.
type countingDisk struct {
	disk.Disk
	read atomic.Int64
}

func (d *countingDisk) Open(path string, mode disk.Mode) (disk.File, error) {
	file, err := d.Disk.Open(path, mode)
	if err != nil {
		return nil, err
	}
	return countingFile{file, &d.read}, nil
}

type countingFile struct {
	disk.File
	read *atomic.Int64
}

func (f countingFile) ReadAt(b []byte, offset int64) (int, error) {
	n, err := f.File.ReadAt(b, offset)
	f.read.Add(int64(n))
	return n, err
}

// startOn is node.start with d as the disk.
func (n *node) startOn(d disk.Disk) {
	t := n.w.t
	t.Helper()
	n.events = buildRecorder()
	ports := Ports{Transport: n.host, Disk: d, Clock: n.w.clock, Rand: rand.New(rand.NewPCG(uint64(n.ip.As4()[3]), 1))}
	e, err := build(n.config, ports, n.events, n.w.caps, nil)
	if err != nil {
		t.Fatal(err)
	}
	n.engine = e
	t.Cleanup(func() { e.Close() })
}

// A downloader that requests many blocks and does not read gets only
// uploadBufferSize read ahead, not every block it asked for.
func TestUploadReadAheadIsBounded(t *testing.T) {
	w := buildWorld(t)
	a := w.addNode("198.51.100.1")
	counting := &countingDisk{Disk: a.disk}
	a.startOn(counting)
	f := buildTestFile("big.bin", 34*int(piece.BlockSize), 4)
	a.seed(1, f)
	before := counting.read.Load()

	p := w.openRawPeer("198.51.100.9", a)
	size := int64(len(f.data))
	p.session.Add(f.hash, size, make(piece.Set, piece.PartCount(size)))
	p.session.Start(f.hash)
	p.readUntil("a slot", isEvent[peer.SlotGranted])
	for i := int64(0); i < 33; i += 3 {
		request := client.RequestParts{Hash: f.hash}
		for j := range int64(3) {
			request.Starts[j] = uint32((i + j) * piece.BlockSize)
			request.Ends[j] = uint32((i + j + 1) * piece.BlockSize)
		}
		p.send(request)
	}
	settle := w.clock.Now().Add(10 * time.Second)
	w.waitFor("ten seconds", func() bool { return !w.clock.Now().Before(settle) })

	// The fake connection buffers 256 KiB before a write blocks.
	limit := int64(uploadBufferSize + piece.BlockSize + 256<<10)
	if read := counting.read.Load() - before; read == 0 || read > limit {
		t.Fatalf("read %d bytes for a peer that stopped reading, want 1 to %d", read, limit)
	}
}

// Connections that never send their first bytes hold at most
// maxIncomingHandshakes accepts; the rest wait in the listener's backlog or
// are refused, and the listener serves again once they go.
func TestSilentIncomingConnectionsAreBounded(t *testing.T) {
	w := buildWorld(t)
	a := w.addNode("198.51.100.1")
	a.start()
	silent := w.network.AddHost(netip.MustParseAddr("198.51.100.9"))
	opened := 0
	for range 300 {
		if _, err := silent.OpenTCP(context.Background(), a.endpoint()); err == nil {
			opened++
		}
	}
	// The fake listener's backlog holds 128 connections.
	if opened > maxIncomingHandshakes+128 || opened == 300 {
		t.Fatalf("%d of 300 silent connections opened, want at most %d", opened, maxIncomingHandshakes+128)
	}
	silent.Close()

	p := w.openRawPeer("198.51.100.10", a)
	p.readUntil("the handshake after the silent ones went", isEvent[peer.HandshakeCompleted])
}

// Closing the engine does not wait for an incoming connection's handshake
// to time out.
func TestCloseDoesNotWaitForHandshakes(t *testing.T) {
	w := buildWorld(t)
	a := w.addNode("198.51.100.1")
	a.start()
	w.openRaw("198.51.100.9", a)
	time.Sleep(50 * time.Millisecond)
	begin := time.Now()
	a.close()
	if took := time.Since(begin); took > 5*time.Second {
		t.Fatalf("Close took %v", took)
	}
}

// Each connection runs a reader and a writer, and both end when it closes.
func TestConnectionGoroutinesExit(t *testing.T) {
	w := buildWorld(t)
	a := w.addNode("198.51.100.1")
	a.start()
	baseline := runtime.NumGoroutine()
	var peers []*rawPeer
	for i := range 20 {
		p := w.openRawPeer(fmt.Sprintf("198.51.100.%d", 100+i), a)
		p.readUntil("the handshake", isEvent[peer.HandshakeCompleted])
		peers = append(peers, p)
	}
	if extra := runtime.NumGoroutine() - baseline; extra > 2*len(peers) {
		t.Fatalf("%d goroutines for %d connections", extra, len(peers))
	}
	for _, p := range peers {
		p.conn.Close()
	}
	w.waitFor("the connection goroutines to end", func() bool {
		return runtime.NumGoroutine() <= baseline
	})
}
