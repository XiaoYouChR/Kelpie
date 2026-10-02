package kad

import (
	"net/netip"
	"testing"
	"time"

	kadwire "github.com/XiaoYouChR/Kelpie/internal/wire/kad"
)

// A BootstrapReq costs its sender two bytes and us twenty contacts, so
// each IP gets two answers a minute, as from aMule.
func TestBootstrapRequestsAreRateLimited(t *testing.T) {
	h := buildHarness(t)
	h.connect(fileHash, 5)
	victim := netip.MustParseAddrPort("198.51.100.7:4672")
	for range 5 {
		h.receive(victim, kadwire.BootstrapReq{})
	}
	if got := len(packetsOf[kadwire.BootstrapRes](h)); got != 2 {
		t.Fatalf("%d bootstrap answers to a burst of 5, want 2", got)
	}
	h.clearSent()
	h.receive(netip.MustParseAddrPort("198.51.100.8:4672"), kadwire.BootstrapReq{})
	if got := len(packetsOf[kadwire.BootstrapRes](h)); got != 1 {
		t.Fatal("another IP's request was dropped")
	}
	// Dropped requests count too: the burst of five holds the IP off for two
	// minutes, and the one dropped at 119 s for 30 s more.
	h.clearSent()
	h.now = h.now.Add(119 * time.Second)
	h.receive(victim, kadwire.BootstrapReq{})
	h.now = h.now.Add(31 * time.Second)
	h.receive(victim, kadwire.BootstrapReq{})
	if got := len(packetsOf[kadwire.BootstrapRes](h)); got != 1 {
		t.Fatalf("%d answers as the burst drained, want 1", got)
	}
}

// A FirewalledReq has the engine connect to the datagram's IP; both kinds
// share two a minute per IP, so a spoofed sender cannot aim us at a third
// party faster than that.
func TestFirewallRequestsAreRateLimited(t *testing.T) {
	h := buildHarness(t)
	asker := netip.MustParseAddrPort("198.51.100.7:4672")
	h.receive(asker, kadwire.FirewalledReq{TCPPort: 4662})
	h.receive(asker, kadwire.LegacyFirewalledReq{TCPPort: 4663})
	h.receive(asker, kadwire.FirewalledReq{TCPPort: 4664})
	if len(h.requests) != 2 {
		t.Fatalf("requests %+v, want two connects", h.requests)
	}
	for _, r := range h.requests {
		if r.(FirewallCheck).Addr.Addr() != asker.Addr() {
			t.Fatalf("connect to %v, want only the datagram's IP", r)
		}
	}
}

// Five times the limit bans the IP from Kad for CLIENTBANTIME: even
// answers to our own requests are dropped until then.
func TestFloodBansIP(t *testing.T) {
	h := buildHarness(t)
	n := h.connect(fileHash, 1)[0]
	for range 2*floodBanFactor + 1 {
		h.receive(n.Addr, kadwire.Ping{})
	}
	h.clearSent()
	h.now = h.now.Add(time.Hour)
	h.c.rpcs.add(&rpc{kind: rpcHello, node: n, sent: h.now})
	h.receive(n.Addr, kadwire.HelloRes{ID: n.ID, TCPPort: 4662, Version: 8})
	if h.c.rpcs.count(rpcHello) != 1 {
		t.Fatal("handled an answer from a banned IP")
	}
	h.now = h.now.Add(floodBan)
	h.receive(n.Addr, kadwire.Ping{})
	if len(packetsOf[kadwire.Pong](h)) != 1 {
		t.Fatal("still banned after the ban ended")
	}
}

// aMule drops plain datagrams from port 53 against DNS protocol confusion.
func TestPlainDatagramFromDNSPortIsDropped(t *testing.T) {
	h := buildHarness(t)
	dns := netip.MustParseAddrPort("198.51.100.7:53")
	h.receive(dns, kadwire.Ping{})
	if len(h.sent) != 0 {
		t.Fatal("answered a plain datagram from port 53")
	}
	h.record(h.c.onPacket(dns, kadwire.Ping{}, keys{sender: 0x1234}, h.now))
	if len(packetsOf[kadwire.Pong](h)) != 1 {
		t.Fatal("dropped an obfuscated datagram from port 53")
	}
}
