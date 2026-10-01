package engine

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/kad"
	"github.com/XiaoYouChR/Kelpie/internal/store"
	"github.com/XiaoYouChR/Kelpie/internal/wire"
	"github.com/XiaoYouChR/Kelpie/internal/wire/client"
	kadwire "github.com/XiaoYouChR/Kelpie/internal/wire/kad"
)

const kadPort = peerPort

// kadNode is a Kad node a test node knows from the start.
type kadNode struct {
	id      wire.Hash
	addr    netip.AddrPort
	version byte
}

// setKad turns Kad on for n with Kad ID id and the given known nodes,
// before its engine starts.
func (n *node) setKad(id wire.Hash, known ...kadNode) {
	n.w.t.Helper()
	n.config.EnableKad = true
	state := store.State{Kad: store.Kad{ID: id}}
	for _, k := range known {
		state.Kad.Nodes = append(state.Kad.Nodes, store.KadNode{ID: k.id, Addr: k.addr, Version: k.version})
	}
	if err := store.Save(n.folder, state); err != nil {
		n.w.t.Fatal(err)
	}
}

func (n *node) kadNode(id wire.Hash) kadNode {
	return kadNode{id: id, addr: netip.AddrPortFrom(n.ip, kadPort), version: kadwire.Version}
}

// joinKad turns Kad on for nodes and gives each a Kad ID and all the
// others as known contacts.
func (w *world) joinKad(nodes ...*node) {
	ids := make([]wire.Hash, len(nodes))
	for i, n := range nodes {
		ids[i] = wire.Hash{0x40 + byte(i)*0x11, n.ip.As4()[3], 0x77}
	}
	for i, n := range nodes {
		var known []kadNode
		for j, other := range nodes {
			if j != i {
				known = append(known, other.kadNode(ids[j]))
			}
		}
		n.setKad(ids[i], known...)
	}
}

// startBareKad runs a Kad node without an engine at ip.
func (w *world) startBareKad(ip string, id wire.Hash, known ...kadNode) kadNode {
	addr := netip.MustParseAddr(ip)
	state := store.Kad{ID: id, UDPKey: uint32(addr.As4()[3])}
	for _, k := range known {
		state.Nodes = append(state.Nodes, store.KadNode{ID: k.id, Addr: k.addr, Version: k.version})
	}
	k := kad.BuildKad(kad.Config{
		Transport: w.network.AddHost(addr), Clock: w.clock, Port: kadPort, TCPPort: peerPort,
		UserHash: wire.Hash{0xBA, addr.As4()[3]}, State: state,
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		k.Run(ctx)
	}()
	w.t.Cleanup(func() {
		cancel()
		<-done
	})
	return kadNode{id: id, addr: netip.AddrPortFrom(addr, kadPort), version: kadwire.Version}
}

// guideVersion keeps the guide's datagrams plain: nodes obfuscate only to
// Kad 6 and up.
const guideVersion = 5

// startTesterGuide runs a scripted Kad node at ip that answers every
// routing request with two clients the asker has not heard of yet, from
// testers, the way the real network keeps naming strangers. Those clients
// become the asker's UDP test clients.
func (w *world) startTesterGuide(ip string, id wire.Hash, testers []netip.Addr) kadNode {
	addr := netip.MustParseAddr(ip)
	conn, err := w.network.AddHost(addr).OpenUDP(kadPort)
	if err != nil {
		w.t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		named := map[netip.Addr]int{}
		buf := make([]byte, 65536)
		for {
			n, from, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			frame, err := wire.ParseDatagram(buf[:n])
			if err != nil {
				continue
			}
			p, _ := kadwire.Parse(frame.Protocol, frame.Opcode, frame.Body)
			var reply wire.Packet
			switch p := p.(type) {
			case kadwire.BootstrapReq:
				reply = kadwire.BootstrapRes{ID: id, TCPPort: peerPort, Version: guideVersion}
			case kadwire.HelloReq:
				reply = kadwire.HelloRes{ID: id, TCPPort: peerPort, Version: guideVersion}
			case kadwire.Ping:
				reply = kadwire.Pong{UDPPort: from.Port()}
			case kadwire.Req:
				res := kadwire.Res{Target: p.Target}
				for range 2 {
					i := named[from.Addr()] % len(testers)
					named[from.Addr()]++
					res.Contacts = append(res.Contacts, kadwire.Contact{
						ID: wire.Hash{0x7E, byte(i)}, Addr: testers[i], UDPPort: kadPort, TCPPort: peerPort, Version: kadwire.Version,
					})
				}
				reply = res
			}
			if reply != nil {
				conn.WriteTo(wire.BuildPacketDatagram(nil, reply), from)
			}
		}
	}()
	w.t.Cleanup(func() {
		conn.Close()
		wg.Wait()
	})
	return kadNode{id: id, addr: netip.AddrPortFrom(addr, kadPort), version: guideVersion}
}

// TestKadFirewallChecksBetweenEngines: engines answer each other's Kad
// firewall checks by connecting to the asker, so open nodes see themselves
// open and a LowID node stays firewalled.
func TestKadFirewallChecksBetweenEngines(t *testing.T) {
	w := buildWorld(t)
	a, b, c := w.addNode("198.51.100.1"), w.addNode("198.51.100.2"), w.addNode("198.51.100.3")
	low := w.addNode("198.51.100.4")
	low.host.SetLowID(true)
	w.joinKad(a, b, c, low)
	for _, n := range []*node{a, b, c, low} {
		n.start()
	}
	w.waitFor("open nodes to pass the firewall check", func() bool {
		for _, n := range []*node{a, b, c} {
			if net := n.events.lastNetwork(); net.KadNodes == 0 || net.IsKadFirewalled {
				return false
			}
		}
		return true
	})
	if !low.events.lastNetwork().IsKadFirewalled {
		t.Fatal("the LowID node passed the firewall check")
	}
}

func invert(id wire.Hash) wire.Hash {
	for i := range id {
		id[i] = ^id[i]
	}
	return id
}

// kadWorld is a small Kad network around a LowID seeder: an open Kelpie
// whose Kad ID makes it the seeder's buddy candidate,
// a downloader, a bare Kad node near the file that stores sources, and a
// guide that names six UDP test clients.
type kadWorld struct {
	seeder, buddy, downloader *node
	seederID                  wire.Hash
}

func (w *world) buildKadWorld(f testFile, isSeederUDPFirewalled bool) kadWorld {
	nearFile := func(b byte) wire.Hash {
		id := f.hash
		id[15] ^= b
		return id
	}
	var testerIPs []netip.Addr
	for i := range 6 {
		tester := w.addNode(fmt.Sprintf("198.51.100.%d", 21+i))
		tester.setKad(wire.Hash{0x7E, byte(i)})
		tester.start()
		testerIPs = append(testerIPs, tester.ip)
	}
	k := kadWorld{seeder: w.addNode("198.51.100.1"), buddy: w.addNode("198.51.100.2"), downloader: w.addNode("198.51.100.3"), seederID: wire.Hash{0x10, 0x01}}
	k.seeder.host.SetLowID(true)
	k.seeder.host.SetUDPFirewalled(isSeederUDPFirewalled)
	buddyID := invert(k.seederID)
	buddyID[15] ^= 1
	ids := map[*node]wire.Hash{k.seeder: k.seederID, k.buddy: buddyID, k.downloader: nearFile(2)}
	storer := w.startBareKad("198.51.100.10", nearFile(1), k.seeder.kadNode(k.seederID), k.buddy.kadNode(buddyID), k.downloader.kadNode(nearFile(2)))
	guide := w.startTesterGuide("198.51.100.11", wire.Hash{0x60}, testerIPs)
	for _, n := range []*node{k.buddy, k.downloader, k.seeder} {
		known := []kadNode{storer, guide}
		for other, otherID := range ids {
			if other != n {
				known = append(known, other.kadNode(otherID))
			}
		}
		n.setKad(ids[n], known...)
		n.start()
	}
	return k
}

// downloadFromKad has the downloader fetch f knowing no source, and checks
// that Kad named the seeder as a firewalled source, one reached by a
// callback.
func (k kadWorld) downloadFromKad(f testFile) {
	w := k.downloader.w
	if net := k.downloader.events.lastNetwork(); net.IsKadFirewalled {
		w.t.Fatalf("downloader network %+v, want Kad open", net)
	}
	path := k.downloader.download(2, f)
	requireEndedOK(w.t, w.waitEnded(k.downloader, 2))
	k.downloader.requireData(path, f.data)
	isFoundOnKad := false
	for _, line := range k.downloader.loadTrace() {
		source, _ := line["source"].(string)
		isFoundOnKad = isFoundOnKad || line["event"] == "found" && line["channel"] == "kad" && strings.HasPrefix(source, "kad:")
	}
	if !isFoundOnKad {
		w.t.Fatal("the downloader did not find the seeder on Kad")
	}
}

// TestFirewalledSeederServesThroughBuddy: a seeder nobody can reach, over
// TCP or UDP, gets an open Kelpie as Kad buddy and publishes itself behind
// it; a downloader's callback request travels through the buddy, and the
// seeder connects out to the downloader.
func TestFirewalledSeederServesThroughBuddy(t *testing.T) {
	w := buildWorld(t)
	f := buildTestFile("buddy.bin", 900_000, 6)
	k := w.buildKadWorld(f, true)
	seeder, buddy := k.seeder, k.buddy
	seederID := k.seederID
	seeder.seed(1, f)
	w.waitFor("the seeder to have looked for a buddy", func() bool {
		return w.clock.Now().Sub(start) >= 8*time.Minute
	})
	if net := seeder.events.lastNetwork(); !net.IsKadFirewalled {
		t.Fatalf("seeder network %+v, want Kad firewalled", net)
	}
	k.downloadFromKad(f)

	asker, err := w.network.AddHost(netip.MustParseAddr("198.51.100.40")).OpenUDP(kadPort)
	if err != nil {
		t.Fatal(err)
	}
	defer asker.Close()
	answers := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 1500)
		if n, _, err := asker.ReadFrom(buf); err == nil {
			answers <- buf[:n]
		}
	}()
	reask := client.ReaskCallbackUDP{BuddyID: invert(seederID), Ping: client.ReaskFilePing{Hash: wire.Hash{0xAB}}}
	asker.WriteTo(wire.BuildPacketDatagram(nil, reask), netip.AddrPortFrom(buddy.ip, kadPort))
	var answer []byte
	w.waitFor("the seeder to answer a reask passed on by its buddy", func() bool {
		select {
		case answer = <-answers:
			return true
		default:
			return false
		}
	})
	if !bytes.Equal(answer, wire.BuildPacketDatagram(nil, client.FileNotFound{})) {
		t.Fatalf("reask answer %x, want OP_FILENOTFOUND", answer)
	}
}

// TestFirewalledSeederTakesDirectCallback: a seeder nobody reaches over
// TCP but anybody over UDP publishes itself as a direct callback source,
// and connects out when the downloader asks it over UDP.
func TestFirewalledSeederTakesDirectCallback(t *testing.T) {
	w := buildWorld(t)
	f := buildTestFile("direct.bin", 700_000, 7)
	k := w.buildKadWorld(f, false)
	k.seeder.seed(1, f)
	w.waitFor("the seeder to finish its UDP test and publish", func() bool {
		return w.clock.Now().Sub(start) >= 3*time.Minute
	})
	k.downloadFromKad(f)
}
