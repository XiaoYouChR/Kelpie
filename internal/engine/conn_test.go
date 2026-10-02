package engine

import (
	"bufio"
	"context"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/identity"
	"github.com/XiaoYouChR/Kelpie/internal/peer"
	"github.com/XiaoYouChR/Kelpie/internal/piece"
	"github.com/XiaoYouChR/Kelpie/internal/transport"
	"github.com/XiaoYouChR/Kelpie/internal/wire"
	"github.com/XiaoYouChR/Kelpie/internal/wire/client"
)

// scriptedPeer is another eD2k client, driven by a peer.Session over the fake
// network, for tests that look at the packets an engine sends. It shares one
// file and answers every upload request with a queue rank.
type scriptedPeer struct {
	w     *world
	host  *transport.Host
	cfg   peer.Config
	share peer.Share
	file  wire.Hash
	// others are more files the peer shares, set before it connects.
	others map[wire.Hash]peer.Share
	mu     sync.Mutex
	conns  []*scriptedConn
	accept chan *scriptedConn
}

type scriptedConn struct {
	net      net.Conn
	session  *peer.Session
	received []wire.Packet
	// receivedAt is when each packet in received arrived, on the fake clock.
	receivedAt []time.Time
	events     []peer.Event
}

func (w *world) addScriptedPeer(ip string, f testFile) *scriptedPeer {
	w.t.Helper()
	addr := netip.MustParseAddr(ip)
	self, err := identity.CreateSelf()
	if err != nil {
		w.t.Fatal(err)
	}
	p := &scriptedPeer{
		w:    w,
		host: w.network.AddHost(addr),
		cfg: peer.Config{
			Self:     self,
			Version:  "0.50.0",
			ClientID: wire.ToClientID(addr),
			PublicIP: addr,
			Port:     peerPort,
			UDPPort:  peerPort + 10,
			Random:   rand.New(rand.NewPCG(9, 9)),
		},
		share: peer.Share{Name: f.name, Size: int64(len(f.data)), Parts: piece.BuildFullSet(piece.PartCount(int64(len(f.data))))},
		file:  f.hash,
	}
	p.cfg.ShareByHash = p.shareByHash
	p.cfg.SourcesByHash = func(wire.Hash, piece.Set) []peer.Source { return nil }
	p.cfg.CanAskSlot = func(_, _ wire.Hash) bool { return true }
	listener, err := p.host.OpenListener(peerPort)
	if err != nil {
		w.t.Fatal(err)
	}
	w.t.Cleanup(p.host.Close)
	go func() {
		for {
			netConn, remote, err := listener.Accept()
			if err != nil {
				return
			}
			p.run(netConn, peer.BuildIncoming(p.cfg, remote, w.clock.Now()), peer.Output{})
		}
	}()
	return p
}

func (p *scriptedPeer) endpoint() netip.AddrPort {
	return netip.AddrPortFrom(p.cfg.PublicIP, peerPort)
}

// open connects to n and sends our Hello.
func (p *scriptedPeer) open(n *node) {
	p.w.t.Helper()
	p.openSession(n, peer.BuildOutgoing(n.endpoint()))
}

// download connects to n and queues for p's file, telling n it has parts.
func (p *scriptedPeer) download(n *node, parts piece.Set) {
	p.w.t.Helper()
	session := peer.BuildOutgoing(n.endpoint())
	session.Add(p.file, p.share.Size, parts)
	p.openSession(n, session)
}

func (p *scriptedPeer) openSession(n *node, session *peer.Session) {
	p.w.t.Helper()
	netConn, err := p.host.OpenTCP(context.Background(), n.endpoint())
	if err != nil {
		p.w.t.Fatal(err)
	}
	p.run(netConn, session, session.OnOpened(p.cfg, p.w.clock.Now()))
}

func (p *scriptedPeer) run(netConn net.Conn, session *peer.Session, first peer.Output) {
	c := &scriptedConn{net: netConn, session: session}
	p.mu.Lock()
	p.conns = append(p.conns, c)
	p.perform(c, first)
	p.mu.Unlock()
	go func() {
		r := bufio.NewReader(netConn)
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
			c.received = append(c.received, packet)
			c.receivedAt = append(c.receivedAt, p.w.clock.Now())
			p.perform(c, session.OnPacket(packet, p.w.clock.Now()))
			p.mu.Unlock()
		}
	}()
}

func (p *scriptedPeer) shareByHash(file wire.Hash) (peer.Share, bool) {
	if share, ok := p.others[file]; ok {
		return share, true
	}
	return p.share, file == p.file
}

func (p *scriptedPeer) perform(c *scriptedConn, out peer.Output) {
	for _, packet := range out.Send {
		c.net.Write(wire.BuildPacket(nil, packet))
	}
	for _, ev := range out.Events {
		c.events = append(c.events, ev)
		if _, ok := ev.(peer.UploadRequested); ok {
			p.perform(c, c.session.SendQueueRank(5))
		}
	}
	if out.Close != "" {
		c.net.Close()
	}
}

// matchConn tells whether connection i exists and match holds for it.
func (p *scriptedPeer) matchConn(i int, match func(c *scriptedConn) bool) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return i < len(p.conns) && match(p.conns[i])
}

func (p *scriptedPeer) closeConn(i int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.conns[i].net.Close()
}

func hasEvent[T peer.Event](c *scriptedConn) bool {
	for _, ev := range c.events {
		if _, ok := ev.(T); ok {
			return true
		}
	}
	return false
}

// countFileRequests counts the packets that ask the peer about a file.
func countFileRequests(c *scriptedConn) int {
	n := 0
	for _, packet := range c.received {
		switch packet.(type) {
		case client.FileRequest, client.SetRequestFileID, client.MultiPacket, client.MultiPacketExt, client.StartUploadRequest:
			n++
		}
	}
	return n
}

// A source we are queued on that connects to us, here to start a download
// of its own, does not get our file request and upload request again before
// the reask is due.
func TestIncomingSourceIsNotReasked(t *testing.T) {
	w := buildWorld(t)
	b := w.addNode("198.51.100.2")
	b.start()
	f := buildTestFile("queued.bin", 500_000, 12)
	p := w.addScriptedPeer("198.51.100.5", f)
	b.download(1, f, p.endpoint())
	w.waitFor("B to queue on the peer", func() bool {
		return p.matchConn(0, hasEvent[peer.UploadRequested])
	})
	p.closeConn(0)
	w.waitFor("B to notice the close", func() bool {
		return matchTrace(b.loadTrace(), "closed", p.endpoint().String())
	})

	p.open(b)
	w.waitFor("the peer's handshake", func() bool {
		return p.matchConn(1, hasEvent[peer.HandshakeCompleted])
	})
	settle := w.clock.Now().Add(5 * time.Second)
	w.waitFor("a few seconds", func() bool { return !w.clock.Now().Before(settle) })
	if !p.matchConn(1, func(c *scriptedConn) bool { return countFileRequests(c) == 0 }) {
		t.Fatal("B asked the queued source again on its incoming connection")
	}
}

// A seed answers Source Exchange with the peers queued for the file on it
// that have a part the asker lacks.
func TestSeedAnswersSourceExchange(t *testing.T) {
	w := buildWorld(t)
	a, c := w.addNode("198.51.100.1"), w.addNode("198.51.100.3")
	a.config.UploadLimit = 100_000
	a.start()
	c.start()
	f := buildTestFile("sx.bin", 3*int(piece.PartSize), 13)
	a.seed(1, f)
	useful, useless := w.addScriptedPeer("198.51.100.5", f), w.addScriptedPeer("198.51.100.6", f)
	useful.download(a, piece.Set{true, false, false})
	useless.download(a, piece.Set{false, false, false})
	for _, p := range []*scriptedPeer{useful, useless} {
		w.waitFor("the peer to queue on the seed", func() bool {
			return p.matchConn(0, func(c *scriptedConn) bool {
				return hasEvent[peer.Queued](c) || hasEvent[peer.SlotGranted](c)
			})
		})
	}

	c.download(2, f, a.endpoint())
	w.waitFor("C to learn the useful peer from the seed", func() bool {
		return matchTrace(c.loadTrace(), "found", useful.endpoint().String())
	})
	if matchTrace(c.loadTrace(), "found", useless.endpoint().String()) {
		t.Fatal("the seed named a peer with nothing C needs")
	}
}
