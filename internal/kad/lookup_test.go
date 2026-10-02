package kad

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	kadwire "github.com/XiaoYouChR/Kelpie/internal/wire/kad"
)

// TestSourceSearchAsksForMoreWhenClosestAreDead follows CSearch::JumpStart:
// with the two closest nodes silent after six were tried, the closest node
// that answered is asked once for eleven contacts, and its longer answer
// is taken.
func TestSourceSearchAsksForMoreWhenClosestAreDead(t *testing.T) {
	h := buildHarness(t)
	nodes := h.connect(fileHash, 8)
	delete(h.answering, nodes[0].Addr)
	delete(h.answering, nodes[1].Addr)
	h.c.setWanted(Wanted{{Hash: fileHash, Size: 1000}}, h.now)
	h.tick(time.Second)
	delete(h.answering, nodes[2].Addr)
	for range 40 {
		h.tick(time.Second)
	}
	var more []sent[kadwire.Req]
	for _, r := range packetsOf[kadwire.Req](h) {
		if r.packet.Target == fileHash && r.packet.SearchType == findValueMore {
			more = append(more, r)
		}
	}
	if len(more) != 1 || more[0].to != nodes[2].Addr {
		t.Fatalf("asked for more %+v, want once, of %v", more, nodes[2].Addr)
	}

	var contacts []kadwire.Contact
	for i := range findValueMore {
		n := buildNear(fileHash, 50+i)
		contacts = append(contacts, kadwire.Contact{ID: n.ID, Addr: n.Addr.Addr(), UDPPort: n.Addr.Port(), TCPPort: 4662, Version: 9})
	}
	h.receive(nodes[2].Addr, kadwire.Res{Target: fileHash, Contacts: contacts})
	if h.c.table.byID[contacts[10].ID] == nil {
		t.Fatal("the longer answer was dropped")
	}
}

// One answer brings at most two contacts of a /24, counting the answering
// node's own.
func TestAnswerSubnetLimitCountsResponder(t *testing.T) {
	h := buildHarness(t)
	responder := buildNear(fileHash, 0)
	responder.Addr = netip.MustParseAddrPort("198.51.100.1:4672")
	h.c.table.add(responder, true, h.now)
	l := h.c.startLookup(nodeLookup, fileHash, 0, h.now)
	h.c.out = output{}
	var contacts []kadwire.Contact
	for i := range 3 {
		n := buildNear(fileHash, 10+i)
		contacts = append(contacts, kadwire.Contact{ID: n.ID, Addr: netip.MustParseAddr(fmt.Sprintf("198.51.100.%d", 2+i)), UDPPort: 4672, Version: 9})
	}
	h.receive(responder.Addr, kadwire.Res{Target: fileHash, Contacts: contacts})
	if got := len(l.known); got != 2 {
		t.Fatalf("%d candidates after the answer, want the responder and one of its /24", got)
	}
}
