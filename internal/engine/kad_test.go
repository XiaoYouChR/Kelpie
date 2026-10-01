package engine

import (
	"testing"

	"github.com/XiaoYouChR/Kelpie/internal/store"
	"github.com/XiaoYouChR/Kelpie/internal/wire"
	kadwire "github.com/XiaoYouChR/Kelpie/internal/wire/kad"
)

// joinKad turns Kad on for nodes and gives each a Kad ID and all the
// others as known contacts, before their engines start.
func (w *world) joinKad(nodes ...*node) {
	w.t.Helper()
	ids := make([]wire.Hash, len(nodes))
	for i, n := range nodes {
		ids[i] = wire.Hash{0x40 + byte(i)*0x11, n.ip.As4()[3], 0x77}
	}
	for i, n := range nodes {
		n.config.EnableKad = true
		state := store.State{Kad: store.Kad{ID: ids[i]}}
		for j, other := range nodes {
			if j != i {
				state.Kad.Nodes = append(state.Kad.Nodes, store.KadNode{ID: ids[j], Addr: other.endpoint(), Version: kadwire.Version})
			}
		}
		if err := store.Save(n.folder, state); err != nil {
			w.t.Fatal(err)
		}
	}
}

// TestKadFirewallChecksBetweenEngines: engines answer each other's Kad
// firewall checks by connecting to the asker, so open nodes see themselves
// open and a LowID node stays firewalled.
func TestKadFirewallChecksBetweenEngines(t *testing.T) {
	w := buildWorld(t)
	a, b, c := w.addNode("198.51.100.1"), w.addNode("198.51.100.2"), w.addNode("198.51.100.3")
	low := w.addNode("198.51.100.4")
	low.host.SetLowID(true)
	w.joinKad(a, b, c, low)
	for _, n := range []*node{a, b, c, low} {
		n.start()
	}
	w.waitFor("open nodes to pass the firewall check", func() bool {
		for _, n := range []*node{a, b, c} {
			if net := n.events.lastNetwork(); net.KadNodes == 0 || net.IsKadFirewalled {
				return false
			}
		}
		return true
	})
	if !low.events.lastNetwork().IsKadFirewalled {
		t.Fatal("the LowID node passed the firewall check")
	}
}
