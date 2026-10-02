package engine

import (
	"bytes"
	"fmt"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/store"
	"github.com/XiaoYouChR/Kelpie/internal/transport"
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

// guideVersion keeps the guide's datagrams plain: nodes obfuscate only to
// Kad 6 and up.
const guideVersion = 5

// startTesterGuide runs a scripted Kad node at ip that answers every
// routing request with all of testers. Those clients become the asker's UDP
// test clients.
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
				for i, tester := range testers {
					res.Contacts = append(res.Contacts, kadwire.Contact{
						ID: wire.Hash{0x7E, byte(i)}, Addr: tester, UDPPort: kadPort, TCPPort: peerPort, Version: kadwire.Version,
					})
				}
				reply = res
			}
			if reply != nil {
				conn.WriteTo(reply.Build(nil), from)
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
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
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
	})
}

func invert(id wire.Hash) wire.Hash {
	for i := range id {
		id[i] = ^id[i]
	}
	return id
}

// kadWorld is a small Kad network around a LowID seeder: an open Kelpie
// whose Kad ID makes it the seeder's buddy candidate, a downloader, a storer
// near the file that stores sources, a checker, and a guide that names six
// UDP test clients.
//
// In a network this small the open nodes ask each other for firewall
// checks at once, and a node does not acknowledge over a connection the
// asker opened. So that each open node still gets its two
// acknowledgements, the storer and the checker are LowID, which nobody can
// connect to first, and the testers are behind a UDP NAT that only the
// guide gets through: nobody else hears back from them, so nobody verifies
// them or asks them for a check.
//
// Each node has a /24 of its own, but the testers share one: Kad lets at
// most two contacts of a /24 into a leaf of its routing table, so however
// often the guide names them, most testers stay strangers, as a UDP test
// needs. The testers know only the guide, so that they stay connected to Kad
// rather than bootstrapping through the Kad port of an asker.
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
		testerIPs = append(testerIPs, netip.MustParseAddr(fmt.Sprintf("198.51.106.%d", 21+i)))
	}
	guide := w.startTesterGuide("198.51.105.11", wire.Hash{0x60}, testerIPs)
	for i, ip := range testerIPs {
		tester := w.addNode(ip.String())
		tester.host.SetUDPFirewalled(true)
		tester.setKad(wire.Hash{0x7E, byte(i)}, guide)
		tester.start()
	}
	k := kadWorld{seeder: w.addNode("198.51.100.1"), buddy: w.addNode("198.51.101.2"), downloader: w.addNode("198.51.102.3"), seederID: wire.Hash{0x10, 0x01}}
	storer, checker := w.addNode("198.51.103.10"), w.addNode("198.51.104.12")
	for _, n := range []*node{k.seeder, storer, checker} {
		n.host.SetLowID(true)
	}
	k.seeder.host.SetUDPFirewalled(isSeederUDPFirewalled)
	buddyID := invert(k.seederID)
	buddyID[15] ^= 1
	ids := map[*node]wire.Hash{k.seeder: k.seederID, k.buddy: buddyID, k.downloader: nearFile(2), storer: nearFile(1), checker: wire.Hash{0x30}}
	for n := range ids {
		known := []kadNode{guide}
		for other, otherID := range ids {
			if other != n {
				known = append(known, other.kadNode(otherID))
			}
		}
		n.setKad(ids[n], known...)
		n.start()
	}
	w.waitFor("the open nodes to pass the firewall check", func() bool {
		for _, n := range []*node{k.buddy, k.downloader} {
			if net := n.events.lastNetwork(); net.KadNodes == 0 || net.IsKadFirewalled {
				return false
			}
		}
		return true
	})
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
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
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
		asker.WriteTo(reask.Build(nil), netip.AddrPortFrom(buddy.ip, kadPort))
		var answer []byte
		w.waitFor("the seeder to answer a reask passed on by its buddy", func() bool {
			select {
			case answer = <-answers:
				return true
			default:
				return false
			}
		})
		if !bytes.Equal(answer, client.FileNotFound{}.Build(nil)) {
			t.Fatalf("reask answer %x, want OP_FILENOTFOUND", answer)
		}
	})
}

// TestFirewalledSeederTakesDirectCallback: a seeder nobody reaches over
// TCP but anybody over UDP publishes itself as a direct callback source,
// and connects out when the downloader asks it over UDP.
func TestFirewalledSeederTakesDirectCallback(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		w := buildWorld(t)
		f := buildTestFile("direct.bin", 700_000, 7)
		k := w.buildKadWorld(f, false)
		k.seeder.seed(1, f)
		w.waitFor("the seeder to finish its UDP test and publish", func() bool {
			return w.clock.Now().Sub(start) >= 3*time.Minute
		})
		k.downloadFromKad(f)
	})
}

// TestKadTurnsOffAndOnWhileRunning: turning Kad off ends its goroutines
// and leaves the UDP port to the engine, which still answers eD2k UDP on
// it; turning Kad on again bootstraps it from the nodes it knew.
func TestKadTurnsOffAndOnWhileRunning(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := buildWorld(t)
		a, b := w.addNode("198.51.100.1"), w.addNode("198.51.100.2")
		w.joinKad(a, b)
		a.start()
		b.start()
		w.waitFor("b to know a Kad node", func() bool { return b.events.lastNetwork().KadNodes > 0 })
		asker, err := w.network.AddHost(netip.MustParseAddr("198.51.100.40")).OpenUDP(kadPort)
		if err != nil {
			t.Fatal(err)
		}
		defer asker.Close()
		kads := countKadGoroutines()

		b.engine.Post(Settings{})
		w.waitFor("b's Kad to stop", func() bool {
			net := b.events.lastNetwork()
			return net.KadNodes == 0 && !net.IsKadFirewalled
		})
		if got := countKadGoroutines(); got != kads-2 {
			t.Fatalf("%d Kad goroutines after turning Kad off, want %d", got, kads-2)
		}
		w.requireReaskAnswered(asker, b)

		b.engine.Post(Settings{EnableKad: true})
		w.waitFor("b's Kad to bootstrap again", func() bool { return b.events.lastNetwork().KadNodes > 0 })
		if got := countKadGoroutines(); got != kads {
			t.Fatalf("%d Kad goroutines after turning Kad on, want %d", got, kads)
		}
		w.requireReaskAnswered(asker, b)
	})
}

// TestKadTurnsOffWithABuddyLink: Kad turns off on both ends of a buddy
// link, and later events on that link find no Kad to tell.
func TestKadTurnsOffWithABuddyLink(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		w := buildWorld(t)
		f := buildTestFile("buddyoff.bin", 300_000, 11)
		k := w.buildKadWorld(f, true)
		k.seeder.seed(1, f)
		w.waitFor("the seeder to have looked for a buddy", func() bool {
			return w.clock.Now().Sub(start) >= 8*time.Minute
		})
		k.downloadFromKad(f)

		k.seeder.engine.Post(Settings{})
		k.buddy.engine.Post(Settings{})
		turnedOff := w.clock.Now()
		w.waitFor("the buddy links to be checked", func() bool {
			return w.clock.Now().Sub(turnedOff) >= time.Minute
		})
		for _, n := range []*node{k.seeder, k.buddy} {
			if net := n.events.lastNetwork(); net.KadNodes != 0 || net.IsKadFirewalled {
				t.Fatalf("network %+v with Kad off", net)
			}
		}
		k.seeder.engine.Post(Settings{EnableKad: true})
		w.waitFor("the seeder's Kad to bootstrap again", func() bool { return k.seeder.events.lastNetwork().KadNodes > 0 })
	})
}

// countKadGoroutines counts the goroutines in Kad.Run and its reader.
func countKadGoroutines() int {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			stacks := string(buf[:n])
			return strings.Count(stacks, "kad.(*Kad).Run(") + strings.Count(stacks, "kad.runReader(")
		}
		buf = make([]byte, 2*len(buf))
	}
}

// requireReaskAnswered sends n a reask for a file it does not share from
// asker and waits for OP_FILENOTFOUND.
func (w *world) requireReaskAnswered(asker transport.PacketConn, n *node) {
	w.t.Helper()
	answers := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 1500)
		if size, _, err := asker.ReadFrom(buf); err == nil {
			answers <- buf[:size]
		}
	}()
	asker.WriteTo(client.ReaskFilePing{Hash: wire.Hash{0xAB}}.Build(nil), netip.AddrPortFrom(n.ip, kadPort))
	var answer []byte
	w.waitFor("an answer to a reask", func() bool {
		select {
		case answer = <-answers:
			return true
		default:
			return false
		}
	})
	if !bytes.Equal(answer, client.FileNotFound{}.Build(nil)) {
		w.t.Fatalf("reask answer %x, want OP_FILENOTFOUND", answer)
	}
}

// While Kad has no node and no server is logged in, a source that failed is
// not marked dead and not dialled again.
func TestOfflineSourceWaitsForTheNetwork(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		w := buildWorld(t)
		a, b := w.addNode("198.51.100.1"), w.addNode("198.51.100.2")
		b.config.EnableKad = true
		a.start()
		b.start()
		f := buildTestFile("offline.bin", 500_000, 8)
		a.seed(1, f)
		a.host.SetUnreachable(true)
		b.download(2, f, a.endpoint())
		failures := func() int {
			count := 0
			for _, line := range b.loadTrace() {
				if line["event"] == "failed" && line["source"] == a.endpoint().String() {
					count++
				}
			}
			return count
		}
		w.waitFor("the first dial to fail", func() bool { return failures() == 1 })
		a.host.SetUnreachable(false)
		for range 120 {
			w.advance(time.Minute)
		}
		if got := failures(); got != 1 || matchTrace(b.loadTrace(), "connected", a.endpoint().String()) {
			t.Fatalf("source dialled again in two offline hours (%d failures)", got)
		}
	})
}

// TestKadBootstrapsFromEd2kPeer: a node that knows no Kad node reaches Kad
// through the Kad port an eD2k peer names in its hello.
func TestKadBootstrapsFromEd2kPeer(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		w := buildWorld(t)
		f := buildTestFile("peer.bin", 300_000, 9)
		seeder, other, lost := w.addNode("198.51.100.1"), w.addNode("198.51.100.2"), w.addNode("198.51.100.3")
		w.joinKad(seeder, other)
		lost.setKad(wire.Hash{0x33, 0x01})
		for _, n := range []*node{seeder, other, lost} {
			n.start()
		}
		seeder.seed(1, f)
		lost.download(2, f, seeder.endpoint())
		w.waitFor("the node to join Kad through the seeder", func() bool {
			return lost.events.lastNetwork().KadNodes > 0
		})
	})
}
