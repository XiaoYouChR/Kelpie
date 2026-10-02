package engine

import (
	"net/netip"
	"testing"

	"github.com/XiaoYouChR/Kelpie/internal/kad"
	"github.com/XiaoYouChR/Kelpie/internal/wire"
)

// Our Hello names the ID aMule's GetID picks (amule.cpp:3170-3187).
func TestHelloIDFollowsAMule(t *testing.T) {
	kadIP := netip.MustParseAddr("198.51.100.7")
	serverHigh := wire.ToClientID(netip.MustParseAddr("203.0.113.9"))
	open := kad.Status{Nodes: 5, PublicIP: kadIP}
	firewalled := kad.Status{Nodes: 5, IsFirewalled: true, PublicIP: kadIP}
	for _, c := range []struct {
		name     string
		serverID uint32
		status   kad.Status
		want     uint32
	}{
		{"open Kad beats a server LowID", 1234, open, wire.ToClientID(kadIP)},
		{"open Kad beats a server HighID", serverHigh, open, wire.ToClientID(kadIP)},
		{"open Kad alone", 0, open, wire.ToClientID(kadIP)},
		{"firewalled Kad leaves the server's", 1234, firewalled, 1234},
		{"firewalled Kad alone is 1", 0, firewalled, 1},
		{"server alone", serverHigh, kad.Status{}, serverHigh},
		{"Kad without nodes is not connected", 0, kad.Status{IsFirewalled: true}, 0},
		{"nothing", 0, kad.Status{}, 0},
	} {
		if got := toHelloID(c.serverID, c.status); got != c.want {
			t.Errorf("%s: %d, want %d", c.name, got, c.want)
		}
	}
}
