package kad

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"testing"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/wire"
	kadwire "github.com/XiaoYouChR/Kelpie/internal/wire/kad"
)

type simNode struct {
	c     *core
	addr  netip.AddrPort
	found []SourcesFound
	// isUDPFirewalled nodes only hear datagrams from IPs they sent to, as
	// behind a NAT.
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
// plays each node's engine: a TCP connection always succeeds, so a
// FirewallCheck makes the asker hear an OP_KAD_FWTCPCHECK_ACK and a
// UDPCheck reaches the tester as its OP_FWCHECKUDPREQ.
type sim struct {
	t      *testing.T
	now    time.Time
	nodes  []*simNode
	byAddr map[netip.AddrPort]*simNode
	queue  []simDatagram
	// ended are UDP checks whose connection closes after the test packets
	// had their chance to arrive.
	ended []simEnded
	// isObfuscated: some datagram went out obfuscated.
	isObfuscated bool
}

// buildSim makes a node for each ID; every node but the first knows only
// the first.
func buildSim(t *testing.T, ids []wire.Hash) *sim {
	s := &sim{t: t, now: start, byAddr: map[netip.AddrPort]*simNode{}}
	for i, id := range ids {
		var user wire.Hash
		user[0], user[14], user[15] = 0xEE, byte(i>>8), byte(i)
		addr := netip.MustParseAddrPort(fmt.Sprintf("10.0.%d.%d:4672", i/250, i%250+1))
		n := &simNode{addr: addr, sentTo: map[netip.Addr]bool{}, c: buildCore(coreConfig{
			ID: id, UserHash: user, TCPPort: 4662, UDPPort: 4672, UDPKey: uint32(i)*7919 + 1, Rand: rand.New(rand.NewPCG(uint64(i), 3)),
		}, s.now)}
		s.nodes = append(s.nodes, n)
		s.byAddr[addr] = n
	}
	for _, n := range s.nodes[1:] {
		s.addSeed(n)
	}
	return s
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
			if asker := s.byAddr[netip.AddrPortFrom(r.Addr.Addr(), r.KadPort)]; asker != nil {
				asker.c.onFirewallAck(n.addr.Addr())
			}
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
		p, senderKey, isKad := to.c.parseDatagram(Datagram{Addr: d.from, Data: d.data})
		if !isKad || p == nil {
			s.t.Fatalf("undecodable datagram %x", d.data)
		}
		s.isObfuscated = s.isObfuscated || d.data[0] != wire.ProtocolKad
		s.record(to, to.c.onPacket(d.from, p, senderKey, s.now))
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
	publisher.c.setWanted(Wanted{Publish: []Publish{{Hash: fileHash, Size: 123456}}}, s.now)
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

	searcher.c.setWanted(Wanted{Find: []Search{{Hash: fileHash, Size: 123456}}}, s.now)
	s.run(time.Minute)
	want := Source{Type: SourceOpen, UserHash: publisher.c.userHash, Addr: netip.AddrPortFrom(publisher.addr.Addr(), 4662), UDPPort: 4672}
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

// TestSimulatedUDPCheck: nodes find test clients among strangers; a test
// confirms the open nodes and never one behind a NAT.
func TestSimulatedUDPCheck(t *testing.T) {
	s := buildSim(t, buildIDs(120, false))
	for i, n := range s.nodes {
		n.isUDPFirewalled = i%10 == 5
	}
	s.run(10 * time.Minute)
	open, closed := 0, 0
	for i, n := range s.nodes {
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
