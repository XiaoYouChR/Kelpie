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

// buildNode makes a node in bucket index of self, with a distinct address.
func buildNode(self wire.Hash, index, n int) Node {
	rng := rand.New(rand.NewPCG(uint64(index), uint64(n)))
	return Node{
		ID:      buildRandomID(self, index, rng),
		Addr:    netip.MustParseAddrPort(fmt.Sprintf("10.%d.%d.%d:4672", index, n/250, n%250+1)),
		TCPPort: 4662,
		Version: 8,
	}
}

func TestBuildRandomIDLandsInBucket(t *testing.T) {
	self := mustHash("23A8CEFF57A7A32D562D649ED7893796")
	rng := rand.New(rand.NewPCG(1, 2))
	for index := range 128 {
		for range 20 {
			if got := bucketIndex(self, buildRandomID(self, index, rng)); got != index {
				t.Fatalf("random ID for bucket %d lands in %d", index, got)
			}
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
	if got := tb.byID[n.ID].Addr; got != moved.Addr || tb.byAddr[n.Addr] != nil {
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
