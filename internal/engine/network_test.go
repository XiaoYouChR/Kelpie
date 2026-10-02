package engine

import (
	"context"
	"math/rand/v2"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestMatchCarrierNAT(t *testing.T) {
	cases := []struct {
		mapped, public string
		want           bool
	}{
		{"", "", false},
		{"0.0.0.0", "", false},
		{"100.64.0.1", "", true},
		{"100.127.255.254", "", true},
		{"10.0.0.2", "", true},
		{"192.168.1.1", "", true},
		{"203.0.113.9", "", false},
		{"203.0.113.9", "203.0.113.9", false},
		{"203.0.113.9", "198.51.100.7", true},
		{"100.128.0.1", "", false},
	}
	for _, c := range cases {
		var mapped, public netip.Addr
		if c.mapped != "" {
			mapped = netip.MustParseAddr(c.mapped)
		}
		if c.public != "" {
			public = netip.MustParseAddr(c.public)
		}
		if got := matchCarrierNAT(mapped, public); got != c.want {
			t.Errorf("matchCarrierNAT(%q, %q) = %v, want %v", c.mapped, c.public, got, c.want)
		}
	}
}

// gateway maps the ports at once and reports external as its address.
// While held is open, deleting a mapping waits for it.
type gateway struct {
	external     netip.Addr
	held         chan struct{}
	mu           sync.Mutex
	maps, unmaps int
}

func (g *gateway) open(context.Context, int, int) (func(context.Context) error, netip.Addr, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.maps++
	held := g.held
	return func(context.Context) error {
		if held != nil {
			<-held
		}
		g.mu.Lock()
		defer g.mu.Unlock()
		g.unmaps++
		return nil
	}, g.external, nil
}

func (g *gateway) counts() (maps, unmaps int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.maps, g.unmaps
}

// startMapped is node.start with port mapping on, behind a gateway that
// reports external as its address.
func (n *node) startMapped(external string) *gateway {
	t := n.w.t
	n.events = buildRecorder()
	n.config.EnableUPnP = true
	ports := seams{Transport: n.host, Disk: n.disk, Clock: n.w.clock, Rand: rand.New(rand.NewPCG(1, 1))}
	g := &gateway{external: netip.MustParseAddr(external)}
	e, err := build(n.config, ports, n.events, n.w.caps, g.open)
	if err != nil {
		t.Fatal(err)
	}
	n.engine = e
	events := n.events
	t.Cleanup(func() {
		if err := e.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
		events.check(t)
	})
	return g
}

// TestPortMappingTurnsOffAndOnWhileRunning: turning port mapping off
// deletes the mapping and forgets the gateway's address; turning it on
// maps the ports again, and Close deletes that mapping too.
func TestPortMappingTurnsOffAndOnWhileRunning(t *testing.T) {
	w := buildWorld(t)
	a := w.addNode("198.51.100.1")
	g := a.startMapped("100.64.3.4")
	w.waitFor("carrier NAT", func() bool { return a.events.lastNetwork().IsBehindCarrierNat })

	a.engine.Post(Settings{})
	w.waitFor("the mapping to be deleted", func() bool {
		maps, unmaps := g.counts()
		return maps == 1 && unmaps == 1 && !a.events.lastNetwork().IsBehindCarrierNat
	})

	g.mu.Lock()
	g.held = make(chan struct{})
	g.mu.Unlock()
	a.engine.Post(Settings{EnableUPnP: true})
	w.waitFor("the second mapping", func() bool {
		maps, _ := g.counts()
		return maps == 2 && a.events.lastNetwork().IsBehindCarrierNat
	})

	a.engine.Post(Settings{})
	a.engine.Post(Settings{EnableUPnP: true})
	for range 20 {
		w.clock.Advance(step)
		time.Sleep(stepPause)
	}
	maps, _ := g.counts()
	close(g.held)
	if maps != 2 {
		t.Fatal("mapped again before the last mapping was deleted")
	}
	w.waitFor("the third mapping", func() bool {
		maps, _ := g.counts()
		return maps == 3
	})
	a.close()
	if maps, unmaps := g.counts(); maps != 3 || unmaps != 3 {
		t.Fatalf("%d mappings, %d deleted; want 3 and 3", maps, unmaps)
	}
}

// A report from a mapping turned off and on before it arrived is not taken
// for the new mapping's.
func TestStaleNATReportIsIgnored(t *testing.T) {
	e := &Engine{stopNAT: func() {}, natDone: make(chan struct{})}
	e.onNATOpened(natOpened{netip.MustParseAddr("203.0.113.9"), make(chan struct{})})
	if e.mappedIP.IsValid() {
		t.Fatalf("stale report taken: %v", e.mappedIP)
	}
}

func TestSharedAddressOnTheGatewayIsCarrierNAT(t *testing.T) {
	w := buildWorld(t)
	a := w.addNode("198.51.100.1")
	a.startMapped("100.64.3.4")
	w.waitFor("carrier NAT", func() bool { return a.events.lastNetwork().IsBehindCarrierNat })
}

func TestPeerSeeingAnotherAddressIsCarrierNAT(t *testing.T) {
	w := buildWorld(t)
	a, b := w.addNode("198.51.100.1"), w.addNode("198.51.100.2")
	a.start()
	b.startMapped("203.0.113.9")
	f := buildTestFile("nat.bin", 300_000, 10)
	a.seed(1, f)
	if b.events.lastNetwork().IsBehindCarrierNat {
		t.Fatal("carrier NAT before any peer saw us")
	}
	b.download(2, f, a.endpoint())
	requireEndedOK(t, w.waitEnded(b, 2))
	if !b.events.lastNetwork().IsBehindCarrierNat {
		t.Fatalf("network %+v, want carrier NAT", b.events.lastNetwork())
	}
}
