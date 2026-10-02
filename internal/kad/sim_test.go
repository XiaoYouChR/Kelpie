package kad

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/wire"
	kadwire "github.com/XiaoYouChR/Kelpie/internal/wire/kad"
)

type simNode struct {
	c     *core
	addr  netip.AddrPort
	found []SourcesFound
	// isFirewalled nodes take no TCP connections; isUDPFirewalled nodes
	// only hear datagrams from IPs they sent to, as behind a NAT.
	isFirewalled    bool
	isUDPFirewalled bool
	sentTo          map[netip.Addr]bool
}

type simEnded struct {
	asker *simNode
	ip    netip.Addr
}

type simDatagram struct {
	from, to netip.AddrPort
	data     []byte
}

// sim is a lossless in-process Kad network: every datagram goes through
// its wire form and arrives before the clock moves again. The sim also
// plays each node's engine: a TCP connection succeeds unless it goes to a
// firewalled node, so a FirewallCheck makes the asker hear an
// OP_KAD_FWTCPCHECK_ACK, a UDPCheck reaches the tester as its
// OP_FWCHECKUDPREQ, and a node that finds a buddy links to it at once.
type sim struct {
	t      *testing.T
	now    time.Time
	nodes  []*simNode
	byAddr map[netip.AddrPort]*simNode
	queue  []simDatagram
	// ended are UDP checks whose connection closes after the test packets
	// had their chance to arrive.
	ended []simEnded
	// callbacks are the OP_CALLBACKs buddies passed on.
	callbacks []CallbackRequested
	// isObfuscated: some datagram went out obfuscated.
	isObfuscated bool
	// acks are the HELLO_RES_ACKs delivered, sender first.
	acks [][2]netip.AddrPort
}

// buildSim makes a node for each ID; every node but the first knows only
// the first.
func buildSim(t *testing.T, ids []wire.Hash) *sim {
	s := &sim{t: t, now: start, byAddr: map[netip.AddrPort]*simNode{}}
	for _, id := range ids {
		s.addNode(id)
	}
	for _, n := range s.nodes[1:] {
		s.addSeed(n)
	}
	return s
}

func (s *sim) addNode(id wire.Hash) *simNode {
	i := len(s.nodes)
	var user wire.Hash
	user[0], user[14], user[15] = 0xEE, byte(i>>8), byte(i)
	addr := netip.MustParseAddrPort(fmt.Sprintf("10.0.%d.%d:4672", i/250, i%250+1))
	n := &simNode{addr: addr, sentTo: map[netip.Addr]bool{}, c: buildCore(coreConfig{
		ID: id, UserHash: user, TCPPort: 4662, UDPPort: 4672, UDPKey: uint32(i)*7919 + 1, Rand: rand.New(rand.NewPCG(uint64(i), 3)),
	}, s.now)}
	s.nodes = append(s.nodes, n)
	s.byAddr[addr] = n
	return n
}

func (s *sim) addSeed(n *simNode) {
	n.c.addNodes([]Node{{ID: s.nodes[0].c.id, Addr: s.nodes[0].addr, TCPPort: 4662, Version: kadwire.Version}}, s.now)
}

// buildIDs makes count random IDs; isNearFile keeps them all within
// SEARCHTOLERANCE of fileHash.
func buildIDs(count int, isNearFile bool) []wire.Hash {
	rng := rand.New(rand.NewPCG(7, 7))
	ids := make([]wire.Hash, count)
	for i := range ids {
		for j := range ids[i] {
			ids[i][j] = byte(rng.UintN(256))
		}
		if isNearFile {
			copy(ids[i][:2], fileHash[:2])
		}
	}
	return ids
}

func (s *sim) record(n *simNode, out output) {
	n.found = append(n.found, out.found...)
	for _, d := range out.datagrams {
		n.sentTo[d.to.Addr()] = true
		s.queue = append(s.queue, simDatagram{from: n.addr, to: d.to, data: n.c.buildDatagram(d)})
	}
	for _, r := range out.requests {
		switch r := r.(type) {
		case FirewallCheck:
			if asker := s.byAddr[netip.AddrPortFrom(r.Addr.Addr(), r.KadPort)]; asker != nil && !asker.isFirewalled {
				asker.c.onFirewallAck(n.addr.Addr())
			}
		case BuddyFound:
			if buddy := s.nodeByIP(r.Addr.Addr()); buddy != nil && !n.c.buddy.IsConnected {
				n.c.setBuddy(Buddy{IsConnected: true, Addr: buddy.addr})
				buddy.c.setBuddy(Buddy{IsConnected: true})
			}
		case CallbackRequested:
			s.callbacks = append(s.callbacks, r)
		case UDPCheck:
			if tester := s.nodeByIP(r.Addr.Addr()); tester != nil {
				s.record(tester, tester.c.onMessage(FirewallUDP{IP: n.addr.Addr(), InternPort: r.InternPort, ExternPort: r.ExternPort, Key: r.Key}))
			}
			s.ended = append(s.ended, simEnded{n, r.Addr.Addr()})
		}
	}
}

func (s *sim) nodeByIP(ip netip.Addr) *simNode {
	for _, n := range s.nodes {
		if n.addr.Addr() == ip {
			return n
		}
	}
	return nil
}

func (s *sim) drain() {
	for len(s.queue) > 0 {
		d := s.queue[0]
		s.queue = s.queue[1:]
		to := s.byAddr[d.to]
		if to == nil || to.isUDPFirewalled && !to.sentTo[d.from.Addr()] {
			continue
		}
		p, keys, isKad := to.c.parseDatagram(Datagram{Addr: d.from, Data: d.data})
		if !isKad || p == nil {
			s.t.Fatalf("undecodable datagram %x", d.data)
		}
		s.isObfuscated = s.isObfuscated || d.data[0] != wire.ProtocolKad
		if _, ok := p.(kadwire.HelloResAck); ok {
			s.acks = append(s.acks, [2]netip.AddrPort{d.from, d.to})
		}
		s.record(to, to.c.onPacket(d.from, p, keys, s.now))
	}
}

func (s *sim) run(d time.Duration) {
	for end := s.now.Add(d); s.now.Before(end); {
		s.now = s.now.Add(time.Second)
		for _, n := range s.nodes {
			s.record(n, n.c.onTick(s.now))
			s.drain()
		}
		for len(s.ended) > 0 {
			e := s.ended[0]
			s.ended = s.ended[1:]
			s.record(e.asker, e.asker.c.onMessage(UDPCheckEnded{IP: e.ip}))
			s.drain()
		}
	}
}

func TestSimulatedNetwork(t *testing.T) {
	s := buildSim(t, buildIDs(12, true))
	s.run(10 * time.Minute)
	if !s.isObfuscated {
		t.Fatal("no datagram was obfuscated")
	}

	for i, n := range s.nodes {
		if got := n.c.status(); got.Nodes < 6 || got.IsFirewalled {
			t.Fatalf("node %d status %+v, want a filled table and an open firewall", i, got)
		}
		var closest *simNode
		for _, other := range s.nodes {
			if other == n {
				continue
			}
			d, best := distance(other.c.id, n.c.id), wire.Hash{}
			if closest != nil {
				best = distance(closest.c.id, n.c.id)
			}
			if closest == nil || bytes.Compare(d[:], best[:]) < 0 {
				closest = other
			}
		}
		if c := n.c.table.byID[closest.c.id]; c == nil || !c.isVerified {
			t.Fatalf("node %d does not know its closest neighbour", i)
		}
	}

	publisher, searcher := s.nodes[5], s.nodes[9]
	publisher.c.setWanted(Wanted{{Hash: fileHash, Size: 123456, IsComplete: true, IsShared: true}}, s.now)
	s.run(3 * time.Minute)
	stored := 0
	for _, n := range s.nodes {
		if _, ok := n.c.index.files[fileHash][publisher.c.userHash]; ok {
			stored++
		}
	}
	if stored == 0 || stored > storeFileTotal+alphaQuery {
		t.Fatalf("publisher stored on %d nodes", stored)
	}

	searcher.c.setWanted(Wanted{{Hash: fileHash, Size: 123456}}, s.now)
	s.run(time.Minute)
	want := Source{Type: sourceOpen, UserHash: publisher.c.userHash, Addr: netip.AddrPortFrom(publisher.addr.Addr(), 4662), UDPPort: 4672, CryptOptions: connectOptions}
	var got []Source
	for _, f := range searcher.found {
		if f.Hash == fileHash {
			got = append(got, f.Sources...)
		}
	}
	if len(got) != 1 || got[0] != want {
		t.Fatalf("searcher found %+v, want [%+v]", got, want)
	}
}

// TestNewcomerFillsItsTable joins a settled network through one seed. Like
// eMule, the newcomer keeps looking up sparse leaves every 10 s, and its
// table grows past one bucket of K per level.
func TestNewcomerFillsItsTable(t *testing.T) {
	ids := buildIDs(400, false)
	s := buildSim(t, ids[:len(ids)-1])
	s.run(15 * time.Minute)
	newcomer := &simNode{addr: netip.MustParseAddrPort("10.9.9.9:4672"), sentTo: map[netip.Addr]bool{}, c: buildCore(coreConfig{
		ID: ids[len(ids)-1], UserHash: wire.Hash{0xEF}, TCPPort: 4662, UDPPort: 4672, UDPKey: 99, Rand: rand.New(rand.NewPCG(9, 9)),
	}, s.now)}
	s.nodes = append(s.nodes, newcomer)
	s.byAddr[newcomer.addr] = newcomer
	s.addSeed(newcomer)
	s.run(3 * time.Minute)

	contacts, verified := 0, newcomer.c.table.verifiedCount()
	for i := range newcomer.c.table.buckets {
		contacts += len(newcomer.c.table.buckets[i].contacts)
	}
	if first := len(newcomer.c.table.buckets[0].contacts); first <= bucketSize {
		t.Fatalf("bucket 0 holds %d contacts, want more than one leaf's K", first)
	}
	if contacts < 150 || verified < 50 {
		t.Fatalf("newcomer knows %d contacts, %d verified, after 3 minutes", contacts, verified)
	}
}

// TestSimulatedUDPCheck: nodes joining a running network find test clients
// among strangers; a test confirms the open nodes and never one behind a
// NAT. A lookup starts from verified contacts only, so a node looks for
// test clients through the contacts of its seed's bootstrap answer; the
// first nodes, whose seed knew nobody yet, are left out. The running
// network is large enough that those contacts know strangers.
func TestSimulatedUDPCheck(t *testing.T) {
	ids := buildIDs(220, false)
	s := buildSim(t, ids[:100])
	s.run(2 * time.Minute)
	for i, id := range ids[100:] {
		n := s.addNode(id)
		n.isUDPFirewalled = i%10 == 5
		s.addSeed(n)
	}
	s.run(10 * time.Minute)
	open, closed := 0, 0
	for i, n := range s.nodes[100:] {
		u := &n.c.udp
		switch {
		case n.isUDPFirewalled && u.isOpen():
			t.Fatalf("node %d behind a NAT verified open", i)
		case n.isUDPFirewalled && u.isVerified && u.isFirewalledNow():
			closed++
		case !n.isUDPFirewalled && u.isOpen():
			open++
		}
	}
	if open < 90 || closed < 8 {
		t.Fatalf("%d of 108 open nodes verified open, %d of 12 behind a NAT verified firewalled", open, closed)
	}
}

// TestSimulatedBuddy: a node nobody can reach finds an open node near its
// inverted ID as buddy, publishes itself through it, and a downloader's
// callback request reaches the buddy.
func TestSimulatedBuddy(t *testing.T) {
	ids := buildIDs(80, false)
	for i := range 10 {
		copy(ids[i][:2], fileHash[:2])
	}
	for i := range ids[11] {
		ids[11][i] = ^ids[10][i]
	}
	ids[11][15] ^= 1
	s := buildSim(t, ids)
	firewalled, buddy, searcher := s.nodes[10], s.nodes[11], s.nodes[3]
	firewalled.isFirewalled, firewalled.isUDPFirewalled = true, true
	// In a network this small every tester soon knows every asker (the
	// HELLO_RES_ACK verifies newcomers at the seed at once, and the seed
	// spreads them), so most UDP tests come back "already known" and do
	// not count. The open nodes start with the verdict of an earlier test.
	for _, n := range s.nodes {
		n.c.udp.isVerified = n != firewalled
	}
	firewalled.c.setWanted(Wanted{{Hash: fileHash, Size: 123456, IsComplete: true, IsShared: true}}, s.now)
	s.run(12 * time.Minute)
	if firewalled.c.buddy.Addr != buddy.addr {
		t.Fatalf("firewalled node's buddy %v, want %v", firewalled.c.buddy.Addr, buddy.addr)
	}

	searcher.c.setWanted(Wanted{{Hash: fileHash, Size: 123456}}, s.now)
	s.run(time.Minute)
	var got []Source
	for _, f := range searcher.found {
		for _, src := range f.Sources {
			if src.UserHash == firewalled.c.userHash {
				got = append(got, src)
			}
		}
	}
	if len(got) != 1 || got[0].Type != sourceFirewalled || got[0].Buddy != buddy.addr || got[0].BuddyID != firewalled.c.buddyTarget() {
		t.Fatalf("searcher found %+v, want the firewalled node behind its buddy", got)
	}
	s.record(searcher, searcher.c.onMessage(Callback{Buddy: got[0].Buddy, BuddyID: got[0].BuddyID, Hash: fileHash}))
	s.drain()
	want := CallbackRequested{BuddyID: firewalled.c.buddyTarget(), Hash: fileHash, Addr: netip.AddrPortFrom(searcher.addr.Addr(), 4662)}
	if len(s.callbacks) != 1 || s.callbacks[0] != want {
		t.Fatalf("callbacks %+v, want %+v", s.callbacks, want)
	}
}

func (s *sim) isVerifiedBy(n, by *simNode) bool {
	c := by.c.table.byID[n.c.id]
	return c != nil && c.isVerified
}

// TestSimulatedHelloResAck: a newcomer's first hello carries no key of the
// seed's, so the seed asks for a HELLO_RES_ACK and verifies the newcomer at
// once, before greeting it itself; the newcomers then verify each other.
func TestSimulatedHelloResAck(t *testing.T) {
	s := buildSim(t, buildIDs(3, false))
	seed, a, b := s.nodes[0], s.nodes[1], s.nodes[2]
	s.run(time.Second)
	for _, n := range []*simNode{a, b} {
		if !s.isVerifiedBy(n, seed) || !slices.Contains(s.acks, [2]netip.AddrPort{n.addr, seed.addr}) {
			t.Fatalf("seed did not verify %v by its ACK (acks %v)", n.addr, s.acks)
		}
	}
	s.run(time.Minute)
	for _, n := range s.nodes {
		for _, by := range s.nodes {
			if n != by && !s.isVerifiedBy(n, by) {
				t.Fatalf("%v did not verify %v", by.addr, n.addr)
			}
		}
	}
}

// TestSimulatedVersion7Node: a version 7 node is never asked for an ACK and
// its own request for one is ignored (KademliaUDPListener.cpp:406); it is
// verified by the hellos of the others, and verifies them.
func TestSimulatedVersion7Node(t *testing.T) {
	s := buildSim(t, buildIDs(3, false))
	legacy := s.nodes[2]
	legacy.c.version = 7
	s.run(3 * time.Minute)
	for _, ack := range s.acks {
		if ack[0] == legacy.addr || ack[1] == legacy.addr {
			t.Fatalf("ACK %v involves the version 7 node", ack)
		}
	}
	for _, n := range s.nodes {
		for _, by := range s.nodes {
			if n != by && !s.isVerifiedBy(n, by) {
				t.Fatalf("%v did not verify %v", by.addr, n.addr)
			}
		}
	}
	if ct := s.nodes[0].c.table.byID[legacy.c.id]; ct.Version != 7 {
		t.Fatalf("seed has the version 7 node as version %d", ct.Version)
	}
}
