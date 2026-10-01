package engine

import (
	"context"
	"math/rand/v2"
	"net/netip"
	"testing"
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

// startMapped is node.start with a gateway that maps the ports and reports
// external as its address.
func (n *node) startMapped(external string) {
	t := n.w.t
	n.events = buildRecorder()
	ports := seams{Transport: n.host, Disk: n.disk, Clock: n.w.clock, Rand: rand.New(rand.NewPCG(1, 1))}
	mapPorts := func(context.Context, int, int) (func(context.Context) error, netip.Addr, error) {
		return func(context.Context) error { return nil }, netip.MustParseAddr(external), nil
	}
	e, err := build(n.config, ports, n.events, n.w.caps, mapPorts)
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
