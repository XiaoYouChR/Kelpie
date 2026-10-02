package engine

import (
	"net/netip"
	"testing"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/peer"
	"github.com/XiaoYouChR/Kelpie/internal/wire"
	"github.com/XiaoYouChR/Kelpie/internal/wire/client"
)

// A buddy passes a reask from an IPv6 downloader on, in the sentinel form,
// only to a client that announced an IPv6 address: another reads it as
// coming from 255.255.255.255 (ipv6-spec §3.5.1).
func TestBuddyPassesIPv6ReaskOnlyToIPv6Client(t *testing.T) {
	served := wire.Hash{0x42}
	for _, c := range []struct {
		clientIPv6 string
		from       string
		isPassed   bool
	}{
		{"", "198.51.100.40:4672", true},
		{"", "[2a01:4f8::40]:4672", false},
		{"2a01:4f8::7", "[2a01:4f8::40]:4672", true},
	} {
		session := peer.BuildIncoming(peer.Config{}, netip.MustParseAddrPort("198.51.100.7:4662"), time.Time{})
		hello := client.Hello{ClientID: 1234}
		if c.clientIPv6 != "" {
			hello.IPv6 = netip.MustParseAddr(c.clientIPv6)
		}
		session.OnPacket(hello, time.Time{})
		link := &conn{session: session, handshakenAt: start, control: buildLeafQueue[outItem](1), data: buildLeafQueue[outItem](1)}
		e := &Engine{buddy: buddy{conn: link, isServing: true, id: served}}

		from := netip.MustParseAddrPort(c.from)
		e.onReaskCallbackUDP(from, client.ReaskCallbackUDP{BuddyID: served, Ping: client.ReaskFilePing{Hash: wire.Hash{0xAB}}})
		select {
		case item := <-link.control.items:
			if !c.isPassed || item.packet.(client.ReaskCallbackTCP).Endpoint != from {
				t.Fatalf("from %v passed on %+v", from, item.packet)
			}
		default:
			if c.isPassed {
				t.Fatalf("reask from %v to a client with IPv6 %q not passed on", from, c.clientIPv6)
			}
		}
	}
}
