package kad

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"testing"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/wire"
)

var start = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// buildNode makes a node in the first leaf of bucket index of self, with a
// distinct address.
func buildNode(self wire.Hash, index, n int) Node {
	rng := rand.New(rand.NewPCG(uint64(index), uint64(n)))
	return Node{
		ID:      buildRandomID(self, index, 0, rng),
		Addr:    netip.MustParseAddrPort(fmt.Sprintf("10.%d.%d.%d:4672", index, n/250, n%250+1)),
		TCPPort: 4662,
		Version: 8,
	}
}

func TestBuildRandomIDLandsInLeaf(t *testing.T) {
	self := mustHash("23A8CEFF57A7A32D562D649ED7893796")
	rng := rand.New(rand.NewPCG(1, 2))
	for index := range 128 {
		for leaf := range leafCount(index) {
			for range 20 {
				id := buildRandomID(self, index, leaf, rng)
				if got := bucketIndex(self, id); got != index {
					t.Fatalf("random ID for bucket %d lands in %d", index, got)
				}
				if got := leafIndex(distance(self, id), index); got != leaf && index < 125 {
					t.Fatalf("random ID for leaf %d of bucket %d lands in leaf %d", leaf, index, got)
				}
			}
		}
	}
}

// TestTableHoldsLeavesLikeEMule checks the table's capacity against eMule's
// zone splitting: eight leaves of K in bucket 0, five in every other.
func TestTableHoldsLeavesLikeEMule(t *testing.T) {
	self := mustHash("23A8CEFF57A7A32D562D649ED7893796")
	tb := buildTable(self, start)
	rng := rand.New(rand.NewPCG(3, 4))
	n := 0
	for _, index := range []int{0, 1, 6} {
		for leaf := range leafCount(index) {
			for range bucketSize + 2 {
				n++
				tb.add(Node{ID: buildRandomID(self, index, leaf, rng), Addr: netip.MustParseAddrPort(fmt.Sprintf("10.9.%d.%d:4672", n/250, n%250+1)), Version: 8}, true, start)
			}
		}
	}
	for index, want := range map[int]int{0: 8 * bucketSize, 1: 5 * bucketSize, 6: 5 * bucketSize} {
		if got := len(tb.buckets[index].contacts); got != want {
			t.Fatalf("bucket %d holds %d contacts, want %d", index, got, want)
		}
	}
}

func TestTablePromotesReplacementOnFailure(t *testing.T) {
	self := mustHash("23A8CEFF57A7A32D562D649ED7893796")
	tb := buildTable(self, start)
	var nodes []Node
	for i := range bucketSize + 1 {
		nodes = append(nodes, buildNode(self, 3, i))
		tb.add(nodes[i], true, start)
	}
	if len(tb.closestContacts(self, 100, false)) != bucketSize {
		t.Fatal("bucket holds more than K contacts")
	}
	for range maxFailures {
		tb.onTimeout(nodes[0].Addr)
	}
	contacts := tb.closestContacts(self, 100, false)
	if len(contacts) != bucketSize {
		t.Fatalf("%d contacts after failure, want the replacement promoted", len(contacts))
	}
	for _, c := range contacts {
		if c.ID == nodes[0].ID {
			t.Fatal("failed contact still in the bucket")
		}
	}
}

func TestTableVerifiedContactDisplacesHearsay(t *testing.T) {
	self := mustHash("23A8CEFF57A7A32D562D649ED7893796")
	tb := buildTable(self, start)
	for i := range bucketSize {
		tb.add(buildNode(self, 5, i), false, start)
	}
	verified := buildNode(self, 5, 99)
	tb.add(verified, true, start)
	contacts := tb.closestContacts(verified.ID, 1, true)
	if len(contacts) != 1 || contacts[0].ID != verified.ID {
		t.Fatalf("verified contact not in the full bucket: %v", contacts)
	}
	if tb.verifiedCount() != 1 || len(tb.byID) != bucketSize+1 {
		t.Fatalf("verified %d, known %d", tb.verifiedCount(), len(tb.byID))
	}
}

func TestTableHearsayCannotMoveVerifiedContact(t *testing.T) {
	self := mustHash("23A8CEFF57A7A32D562D649ED7893796")
	tb := buildTable(self, start)
	n := buildNode(self, 7, 1)
	tb.add(n, true, start)
	moved := n
	moved.Addr = netip.MustParseAddrPort("10.99.99.99:4672")
	tb.add(moved, false, start)
	if got := tb.byID[n.ID].Addr; got != n.Addr {
		t.Fatalf("hearsay moved a verified contact to %v", got)
	}
	tb.add(moved, true, start)
	if got := tb.byID[n.ID].Addr; got != moved.Addr || tb.byIP[n.Addr.Addr()] != nil {
		t.Fatalf("verified move not applied: %v", got)
	}
}

func TestTableUnverifiedContactLeavesOnFirstFailure(t *testing.T) {
	self := mustHash("23A8CEFF57A7A32D562D649ED7893796")
	tb := buildTable(self, start)
	heard, seen := buildNode(self, 9, 1), buildNode(self, 9, 2)
	tb.add(heard, false, start)
	tb.add(seen, true, start)
	tb.onTimeout(heard.Addr)
	tb.onTimeout(seen.Addr)
	if tb.byID[heard.ID] != nil || tb.byID[seen.ID] == nil {
		t.Fatal("want unverified gone and verified kept after one failure")
	}
}

func TestRPCMatchesOnlyRequestedResponses(t *testing.T) {
	var p rpcs
	to := netip.MustParseAddrPort("1.2.3.4:4672")
	target := mustHash("0102030405060708090A0B0C0D0E0F10")
	p.add(&rpc{kind: rpcFind, node: Node{Addr: to}, target: target, sent: start})
	if p.match(to, rpcFind, wire.Hash{}) != nil || p.match(netip.MustParseAddrPort("1.2.3.5:4672"), rpcFind, target) != nil {
		t.Fatal("matched a response to another request")
	}
	if p.match(netip.MustParseAddrPort("1.2.3.4:9999"), rpcFind, target) == nil {
		t.Fatal("response from the same IP on another port not matched")
	}
	if p.match(to, rpcFind, target) != nil {
		t.Fatal("one request matched twice")
	}
	p.add(&rpc{kind: rpcHello, node: Node{Addr: to}, sent: start})
	if len(p.removeExpired(start.Add(responseTimeout-time.Second))) != 0 || len(p.removeExpired(start.Add(responseTimeout))) != 1 {
		t.Fatal("expiry off")
	}
}

// TestTableLimitsIPsAndSubnets follows aMule's CRoutingBin: one contact per
// IP whatever its port, ten per public /24 in the table and two in one
// leaf; a contact that answered from an IP takes it over.
func TestTableLimitsIPsAndSubnets(t *testing.T) {
	self := mustHash("23A8CEFF57A7A32D562D649ED7893796")
	rng := rand.New(rand.NewPCG(3, 3))
	tb := buildTable(self, start)
	first := Node{ID: buildRandomID(self, 3, 0, rng), Addr: netip.MustParseAddrPort("198.51.100.1:4672"), Version: 8}
	tb.add(first, false, start)
	sameIP := Node{ID: buildRandomID(self, 4, 0, rng), Addr: netip.MustParseAddrPort("198.51.100.1:4673"), Version: 8}
	if tb.add(sameIP, false, start) != nil {
		t.Fatal("hearsay added a second ID at one IP")
	}
	if tb.add(sameIP, true, start) == nil || tb.byID[first.ID] != nil || len(tb.byID) != 1 {
		t.Fatal("a verified ID did not take its IP over")
	}

	leaf := func(n int) Node {
		return Node{ID: buildRandomID(self, 6, 0, rng), Addr: netip.MustParseAddrPort(fmt.Sprintf("203.0.113.%d:4672", n)), Version: 8}
	}
	tb.add(leaf(1), true, start)
	tb.add(leaf(2), true, start)
	if tb.add(leaf(3), true, start) != nil {
		t.Fatal("a third contact of one /24 entered a leaf")
	}
	for i := range 8 {
		n := Node{ID: buildRandomID(self, 10+i, 0, rng), Addr: netip.MustParseAddrPort(fmt.Sprintf("203.0.113.%d:4672", 10+i)), Version: 8}
		if tb.add(n, true, start) == nil {
			t.Fatalf("contact %d of a /24 refused below the table limit", 3+i)
		}
	}
	if tb.add(Node{ID: buildRandomID(self, 30, 0, rng), Addr: netip.MustParseAddrPort("203.0.113.99:4672"), Version: 8}, true, start) != nil {
		t.Fatal("an eleventh contact of one /24 entered the table")
	}
	moved := sameIP
	moved.Addr = netip.MustParseAddrPort("203.0.113.100:4672")
	if tb.add(moved, true, start); tb.byID[sameIP.ID].Addr != sameIP.Addr {
		t.Fatal("a contact moved into a full /24")
	}
	for i := range 12 {
		n := Node{ID: buildRandomID(self, 40+i, 0, rng), Addr: netip.MustParseAddrPort(fmt.Sprintf("10.0.0.%d:4672", i+1)), Version: 8}
		if tb.add(n, true, start) == nil {
			t.Fatal("LAN addresses are subject to the subnet limit")
		}
	}
}

// Kad 1 nodes and pre-obfuscation nodes on port 53 stay out, as in aMule.
func TestTableRefusesOldNodes(t *testing.T) {
	self := mustHash("23A8CEFF57A7A32D562D649ED7893796")
	tb := buildTable(self, start)
	for _, n := range []Node{
		{ID: wire.Hash{1}, Addr: netip.MustParseAddrPort("198.51.100.1:4672"), Version: 1},
		{ID: wire.Hash{2}, Addr: netip.MustParseAddrPort("198.51.100.2:53"), Version: 5},
	} {
		if tb.add(n, true, start) != nil {
			t.Fatalf("added %+v", n)
		}
	}
	if tb.add(Node{ID: wire.Hash{3}, Addr: netip.MustParseAddrPort("198.51.100.3:53"), Version: 6}, true, start) == nil {
		t.Fatal("refused an obfuscating node on port 53")
	}
}
