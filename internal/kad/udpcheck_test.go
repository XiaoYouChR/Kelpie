package kad

import (
	"net/netip"
	"testing"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/obfuscation"
	"github.com/XiaoYouChR/Kelpie/internal/wire"
	kadwire "github.com/XiaoYouChR/Kelpie/internal/wire/kad"
)

func requestsOf[T Event](out output) []T {
	var got []T
	for _, r := range out.requests {
		if r, ok := r.(T); ok {
			got = append(got, r)
		}
	}
	return got
}

func TestFirewallChecksAreAnswered(t *testing.T) {
	h := buildHarness(t)
	asker := netip.MustParseAddrPort("10.9.9.9:5000")
	user := wire.Hash{0xAB}
	out := h.c.onPacket(asker, kadwire.FirewalledReq{TCPPort: 4111, ID: user, Options: 0x03}, keys{}, h.now)
	h.record(out)
	if res := packetsOf[kadwire.FirewalledRes](h); len(res) != 1 || res[0].to != asker || res[0].packet.Addr != asker.Addr() {
		t.Fatalf("firewall answer %+v, want the asker's address", res)
	}
	want := FirewallCheck{Addr: netip.AddrPortFrom(asker.Addr(), 4111), KadPort: 5000, UserHash: user, CryptOptions: 0x03}
	if got := requestsOf[FirewallCheck](out); len(got) != 1 || got[0] != want {
		t.Fatalf("requests %+v, want %+v", got, want)
	}

	out = h.c.onPacket(asker, kadwire.LegacyFirewalledReq{TCPPort: 4111}, keys{}, h.now)
	if got := requestsOf[FirewallCheck](out); len(got) != 1 || got[0].UserHash != (wire.Hash{}) {
		t.Fatalf("legacy check requests %+v", got)
	}

	h.clearSent()
	h.record(h.c.onMessage(FirewallAck{asker}))
	if len(h.sent) != 1 || h.sent[0].to != asker || h.sent[0].packet.Build(nil)[1] != opFirewalledAck {
		t.Fatalf("sent %+v, want KADEMLIA_FIREWALLED_ACK_RES to the asker", h.sent)
	}
}

func TestFirewallUDPIsAnswered(t *testing.T) {
	h := buildHarness(t)
	known := h.connect(fileHash, 1)[0]
	client := netip.MustParseAddr("10.9.9.9")
	h.record(h.c.onMessage(FirewallUDP{IP: client, InternPort: 4672, ExternPort: 30000}))
	got := packetsOf[kadwire.FirewalledUDP](h)
	if len(got) != 2 || got[0].to != netip.AddrPortFrom(client, 4672) || got[0].packet != (kadwire.FirewalledUDP{Port: 4672}) ||
		got[1].to != netip.AddrPortFrom(client, 30000) || got[1].packet != (kadwire.FirewalledUDP{Port: 30000}) {
		t.Fatalf("test packets %+v, want one to each port", got)
	}

	h.clearSent()
	h.record(h.c.onMessage(FirewallUDP{IP: known.Addr.Addr(), InternPort: 4672, ExternPort: 4672}))
	if got := packetsOf[kadwire.FirewalledUDP](h); len(got) != 1 || got[0].packet.ErrorCode != 1 {
		t.Fatalf("test packets %+v, want one flagged as known", got)
	}
}

// startUDPCheck connects the harness, hands the test-client lookup three
// fresh clients and learns the extern port from the pongs of two nodes;
// the first UDPCheck goes out once the port is known.
func startUDPCheck(t *testing.T, h *harness) UDPCheck {
	t.Helper()
	nodes := h.connect(fileHash, 4)
	for _, n := range nodes {
		delete(h.answering, n.Addr)
	}
	h.tick(time.Second)
	l := h.c.udp.lookup
	if l == nil || l.kind != udpCheckLookup {
		t.Fatal("no test-client lookup after connecting")
	}
	var asked netip.AddrPort
	for _, r := range packetsOf[kadwire.Req](h) {
		if r.packet.Target == l.target {
			asked = r.to
			break
		}
	}
	fresh := []kadwire.Contact{
		{ID: wire.Hash{1}, Addr: netip.MustParseAddr("10.50.0.1"), UDPPort: 4672, TCPPort: 4662, Version: 5},
		{ID: wire.Hash{2}, Addr: netip.MustParseAddr("10.50.0.2"), UDPPort: 4672, TCPPort: 4662, Version: 8},
		{ID: wire.Hash{3}, Addr: netip.MustParseAddr("10.50.0.3"), UDPPort: 4672, TCPPort: 4662, Version: 8},
	}
	h.receive(asked, kadwire.Res{Target: l.target, Contacts: fresh})
	for _, ct := range fresh {
		if h.c.table.byID[ct.ID] != nil {
			t.Fatal("a test client entered the routing table")
		}
	}
	if len(requestsOf[UDPCheck](output{requests: h.requests})) != 0 {
		t.Fatal("asked a test client before knowing the extern port")
	}
	for i := 0; h.c.udp.isFindingExternPort(); i++ {
		pings := packetsOf[kadwire.Ping](h)
		if len(pings) != i+1 || i > 10 {
			t.Fatalf("%d pings for the extern port after %d gaps, want one every 15 s", len(pings), i)
		}
		h.receive(pings[i].to, kadwire.Pong{UDPPort: 30000})
		h.tick(externPortGap)
	}
	checks := requestsOf[UDPCheck](output{requests: h.requests})
	want := UDPCheck{
		Addr: netip.MustParseAddrPort("10.50.0.3:4662"), InternPort: 4672, ExternPort: 30000,
		Key: obfuscation.BuildKadVerifyKey(h.c.udpKey, netip.MustParseAddr("10.50.0.3")),
	}
	if len(checks) != 1 || checks[0] != want {
		t.Fatalf("checks %+v, want %+v", checks, want)
	}
	h.clearSent()
	return checks[0]
}

func TestUDPCheckOpens(t *testing.T) {
	h := buildHarness(t)
	if h.c.udp.isOpen() {
		t.Fatal("open before any test")
	}
	tester := startUDPCheck(t, h).Addr
	h.receive(netip.AddrPortFrom(tester.Addr(), 4672), kadwire.FirewalledUDP{Port: 9999})
	if next := requestsOf[UDPCheck](output{requests: h.requests}); h.c.udp.isOpen() || h.c.udp.finished != 0 || len(next) != 1 {
		t.Fatalf("after a packet to a port that is not ours: %+v, asked %+v; want the test cancelled", h.c.udp, next)
	}
	if got := requestsOf[UDPCheck](h.c.onMessage(UDPCheckEnded{IP: netip.MustParseAddr("10.50.0.1")})); len(got) != 0 {
		t.Fatal("an unasked client's end counted")
	}

	h = buildHarness(t)
	tester = startUDPCheck(t, h).Addr
	h.receive(netip.AddrPortFrom(tester.Addr(), 4672), kadwire.FirewalledUDP{Port: 4672})
	if !h.c.udp.isOpen() || h.c.udp.useExternPort || h.c.udp.isRunning() {
		t.Fatalf("udp check %+v, want open on our own port", h.c.udp)
	}
}

func TestUDPCheckFails(t *testing.T) {
	h := buildHarness(t)
	tester := startUDPCheck(t, h).Addr
	out := h.c.onMessage(UDPCheckEnded{IP: tester.Addr()})
	next := requestsOf[UDPCheck](out)
	if len(next) != 1 || next[0].Addr.Addr() != netip.MustParseAddr("10.50.0.2") {
		t.Fatalf("after one failure asked %+v, want the next client", next)
	}
	h.c.onMessage(UDPCheckEnded{IP: next[0].Addr.Addr()})
	if h.c.udp.isOpen() || !h.c.udp.isFirewalledNow() || !h.c.udp.isVerified {
		t.Fatalf("udp check %+v, want firewalled after two failures", h.c.udp)
	}
}

// TestUDPCheckSkipsClientsWeTested: our test packets to a client opened our
// NAT to it, so its test would prove nothing.
func TestUDPCheckSkipsClientsWeTested(t *testing.T) {
	h := buildHarness(t)
	tester := startUDPCheck(t, h).Addr
	h.c.onMessage(FirewallUDP{IP: netip.MustParseAddr("10.50.0.2"), InternPort: 4672})
	if next := requestsOf[UDPCheck](h.c.onMessage(UDPCheckEnded{IP: tester.Addr()})); len(next) != 0 {
		t.Fatalf("asked %+v, a client we sent test packets to", next)
	}
}

// Status names the Kad port our Hello tells peers: the one our NAT shows
// once a UDP test came through it, else our own (aMule
// BaseClient.cpp:1182-1197).
func TestStatusNamesTheKadPortOthersReach(t *testing.T) {
	h := buildHarness(t)
	tester := startUDPCheck(t, h).Addr
	if got := h.c.status().UDPPort; got != h.c.udpPort {
		t.Fatalf("port %d before a test passed, want our own %d", got, h.c.udpPort)
	}
	h.receive(netip.AddrPortFrom(tester.Addr(), 4672), kadwire.FirewalledUDP{Port: 30000})
	if got := h.c.status().UDPPort; got != 30000 {
		t.Fatalf("port %d after a test came through the NAT's port, want 30000", got)
	}

	h = buildHarness(t)
	tester = startUDPCheck(t, h).Addr
	h.receive(netip.AddrPortFrom(tester.Addr(), 4672), kadwire.FirewalledUDP{Port: h.c.udpPort})
	if got := h.c.status().UDPPort; got != h.c.udpPort {
		t.Fatalf("port %d after a test came to our own port", got)
	}
}
