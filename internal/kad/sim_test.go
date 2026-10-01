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
}

type simDatagram struct {
	from, to netip.AddrPort
	data     []byte
}

// sim is a lossless in-process Kad network: every datagram goes through
// its wire form and arrives before the clock moves again. A
// firewall request stands for the TCP check the asked node's engine runs: it
// always reaches the asker, which hears an OP_KAD_FWTCPCHECK_ACK.
type sim struct {
	t      *testing.T
	now    time.Time
	nodes  []*simNode
	byAddr map[netip.AddrPort]*simNode
	queue  []simDatagram
}

// buildSim makes count nodes whose IDs all lie within SEARCHTOLERANCE of
// fileHash; every node but the first knows only the first.
func buildSim(t *testing.T, count int) *sim {
	s := &sim{t: t, now: start, byAddr: map[netip.AddrPort]*simNode{}}
	rng := rand.New(rand.NewPCG(7, 7))
	for i := range count {
		id := fileHash
		for j := 2; j < len(id); j++ {
			id[j] = byte(rng.UintN(256))
		}
		var user wire.Hash
		user[0], user[15] = 0xEE, byte(i)
		addr := netip.MustParseAddrPort(fmt.Sprintf("10.0.0.%d:4672", i+1))
		n := &simNode{addr: addr, c: buildCore(coreConfig{
			ID: id, UserHash: user, TCPPort: 4662, UDPPort: 4672, Rand: rand.New(rand.NewPCG(uint64(i), 3)),
		}, s.now)}
		s.nodes = append(s.nodes, n)
		s.byAddr[addr] = n
	}
	seed := Node{ID: s.nodes[0].c.id, Addr: s.nodes[0].addr, TCPPort: 4662, Version: kadwire.Version}
	for _, n := range s.nodes[1:] {
		n.c.addNodes([]Node{seed}, s.now)
	}
	return s
}

func (s *sim) record(n *simNode, out output) {
	n.found = append(n.found, out.found...)
	for _, d := range out.datagrams {
		s.queue = append(s.queue, simDatagram{from: n.addr, to: d.to, data: wire.BuildPacketDatagram(nil, d.packet)})
	}
}

func (s *sim) drain() {
	for len(s.queue) > 0 {
		d := s.queue[0]
		s.queue = s.queue[1:]
		to := s.byAddr[d.to]
		if to == nil {
			continue
		}
		p, ok := parsePacket(d.data)
		if !ok {
			s.t.Fatalf("undecodable datagram %x", d.data)
		}
		switch p.(type) {
		case kadwire.FirewalledReq, kadwire.LegacyFirewalledReq:
			s.byAddr[d.from].c.onFirewallAck(d.to.Addr())
		}
		s.record(to, to.c.onPacket(d.from, p, s.now))
	}
}

func (s *sim) run(d time.Duration) {
	for end := s.now.Add(d); s.now.Before(end); {
		s.now = s.now.Add(time.Second)
		for _, n := range s.nodes {
			s.record(n, n.c.onTick(s.now))
			s.drain()
		}
	}
}

func TestSimulatedNetwork(t *testing.T) {
	s := buildSim(t, 12)
	s.run(10 * time.Minute)

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
