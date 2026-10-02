package peer

import (
	"net/netip"
	"testing"

	"github.com/XiaoYouChR/Kelpie/internal/identity"
	"github.com/XiaoYouChR/Kelpie/internal/wire"
	"github.com/XiaoYouChR/Kelpie/internal/wire/client"
)

// greet runs a peer's Hello into a session it opened from remote and
// returns the session and its answer.
func greet(t *testing.T, remote string, hello client.Hello) (*Session, Output) {
	t.Helper()
	s := BuildIncoming(buildConfig(t, 1), netip.MustParseAddrPort(remote), start)
	hello.UserHash = hashOf(7)
	out := s.OnPacket(hello, start)
	if out.Close != "" {
		t.Fatalf("closed: %s", out.Close)
	}
	return s, out
}

// A peer is LowID only by a LowID it names: an ID of 0 is a HighID with no
// server, and an ID equal to its address a HighID like a.b.c.0 that only
// looks low (aMule BaseClient.cpp:772).
func TestPeerClientIDFollowsAMule(t *testing.T) {
	for _, c := range []struct {
		remote string
		id     uint32
		want   uint32
	}{
		{"1.2.3.4:4662", wire.ToClientID(netip.MustParseAddr("1.2.3.4")), 0},
		{"1.2.3.0:4662", wire.ToClientID(netip.MustParseAddr("1.2.3.0")), 0},
		{"1.2.3.4:4662", 0, 0},
		{"1.2.3.4:4662", wire.ToClientID(netip.MustParseAddr("5.6.7.8")), 0},
		{"1.2.3.4:4662", 1234, 1234},
		{"1.2.3.4:4662", 1, 1},
		{"[2a01:4f8::1]:4662", 1234, 1234},
	} {
		s, _ := greet(t, c.remote, client.Hello{ClientID: c.id})
		if got := s.Capabilities().ClientID; got != c.want {
			t.Errorf("id %d from %s: %d, want %d", c.id, c.remote, got, c.want)
		}
	}
}

// A peer's own IPv6 is passed on to others in Source Exchange, so only a
// global unicast one is kept (ipv6-spec §3.2).
func TestPeerIPv6MustBePublic(t *testing.T) {
	for addr, isKept := range map[string]bool{
		"2a01:4f8::1":    true,
		"fe80::1":        false,
		"fd00::1":        false,
		"::1":            false,
		"::ffff:1.2.3.4": false,
		"ff02::1":        false,
	} {
		ip, _ := netip.ParseAddr(addr)
		s, _ := greet(t, "1.2.3.4:4662", client.Hello{IPv6: ip})
		if got := s.Capabilities().IPv6.IsValid(); got != isKept {
			t.Errorf("hello %s kept %v", addr, got)
		}
		s.OnPacket(client.IPv6Changed{Addr: ip}, start)
		if got := s.Capabilities().IPv6.IsValid(); got != isKept {
			t.Errorf("change to %s kept %v", addr, got)
		}
	}
}

func TestPeerDirectCallbackCapability(t *testing.T) {
	s, _ := greet(t, "1.2.3.4:4662", client.Hello{ClientID: 1234, KadPort: 4672, Misc2: client.MiscOptions2{HasDirectUDPCallback: true}})
	if caps := s.Capabilities(); !caps.HasDirectCallback || caps.KadPort != 4672 {
		t.Fatalf("capabilities %+v", caps)
	}
}

// SUI v2 signs an IPv4 address both ends must agree on, which a connection
// over IPv6 does not give: there we offer v1 only and sign no v2
// challenge (aMule SecIdentPolicy.h).
func TestIdentityOverIPv6IsV1(t *testing.T) {
	v2Only := client.MiscOptions1{SecureIdentVersion: 2}
	s, out := greet(t, "[2a01:4f8::1]:4662", client.Hello{Misc1: v2Only})
	answer := out.Send[0].(client.HelloAnswer)
	if answer.Misc1.SecureIdentVersion != 1 {
		t.Fatalf("offered SUI %d over IPv6", answer.Misc1.SecureIdentVersion)
	}
	out = s.OnPacket(client.SecureIdentState{State: client.SecureIdentNeedsKeyAndSignature, Challenge: 9}, start)
	out = s.OnPacket(client.PublicKey{Key: buildConfig(t, 3).Self.PublicKey()}, start)
	if len(out.Send) != 0 {
		t.Fatalf("answered a v2 challenge over IPv6: %#v", out.Send)
	}

	_, out = greet(t, "1.2.3.4:4662", client.Hello{Misc1: v2Only})
	if got := out.Send[0].(client.HelloAnswer).Misc1.SecureIdentVersion; got != identity.Support {
		t.Fatalf("offered SUI %d over IPv4", got)
	}
}

// OP_PUBLICIP_REQ is answered with the IPv4 address we see; a peer on
// IPv6 has none (aMule ClientTCPSocket.cpp:1731-1752).
func TestPublicIPRequestIsAnswered(t *testing.T) {
	s, _ := greet(t, "1.2.3.4:4662", client.Hello{})
	out := s.OnPacket(client.PublicIPRequest{}, start)
	if len(out.Send) != 1 || out.Send[0] != (client.PublicIPAnswer{Addr: netip.MustParseAddr("1.2.3.4")}) {
		t.Fatalf("answer %#v", out.Send)
	}
	s, _ = greet(t, "[2a01:4f8::1]:4662", client.Hello{})
	if out := s.OnPacket(client.PublicIPRequest{}, start); len(out.Send) != 0 {
		t.Fatalf("answered over IPv6: %#v", out.Send)
	}
}

// A peer's client and version read as aMule's client list shows them.
func TestPeerSoftware(t *testing.T) {
	version := func(compatible, major, minor, update uint32) uint32 {
		return compatible<<24 | major<<17 | minor<<10 | update<<7
	}
	for _, c := range []struct {
		hello client.Hello
		want  string
	}{
		{client.Hello{EmuleVersion: version(0, 0, 70, 1)}, "eMule 0.70b"},
		{client.Hello{EmuleVersion: version(0, 0, 50, 0), ModName: "MorphXT v12.7"}, "eMule 0.50a [MorphXT v12.7]"},
		{client.Hello{EmuleVersion: version(3, 2, 3, 3), ModName: "aMule SVN"}, "aMule 2.3.3"},
		{client.Hello{EmuleVersion: wire.ToEmuleVersion("v0.4.2"), ModName: "Kelpie 0.4.2"}, "Kelpie 0.4.2"},
		{client.Hello{EmuleVersion: version(0xF0, 1, 0, 0), ModName: "Leecher 1.0"}, "Leecher 1.0"},
		{client.Hello{EmuleVersion: version(0xF0, 1, 0, 0)}, ""},
		{client.Hello{}, ""},
	} {
		s, _ := greet(t, "1.2.3.4:4662", c.hello)
		if got := s.Capabilities().Software; got != c.want {
			t.Errorf("%#x %q: %q, want %q", c.hello.EmuleVersion, c.hello.ModName, got, c.want)
		}
	}
}

// A client older than CT_EMULE_VERSION tells its version in OP_EMULEINFO.
func TestPeerSoftwareFromEmuleInfo(t *testing.T) {
	s := BuildIncoming(buildConfig(t, 1), netip.MustParseAddrPort("1.2.3.4:4662"), start)
	s.OnPacket(client.EmuleInfo{Version: 0x44, Tags: []wire.Tag{{Type: wire.TagUint32, ID: client.InfoCompatibleClient, Uint: 4}}}, start)
	s.OnPacket(client.Hello{UserHash: hashOf(7)}, start)
	if got := s.Capabilities().Software; got != "Shareaza 0.44a" {
		t.Fatalf("software %q", got)
	}
}
