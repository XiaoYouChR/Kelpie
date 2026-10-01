package upload

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/identity"
	"github.com/XiaoYouChR/Kelpie/internal/wire"
)

var (
	t0    = time.Unix(1_700_000_000, 0)
	file  = wire.Hash{0xF1}
	other = wire.Hash{0xF2}
)

type world struct {
	ratios     map[wire.Hash]float64
	banned     map[wire.Hash]bool
	identified map[wire.Hash]netip.Addr
}

func buildWorld() (*world, *Queue) {
	w := &world{ratios: map[wire.Hash]float64{}, banned: map[wire.Hash]bool{}, identified: map[wire.Hash]netip.Addr{}}
	q := BuildQueue(
		func(user wire.Hash, _ netip.Addr) float64 {
			if r, ok := w.ratios[user]; ok {
				return r
			}
			return 1
		},
		func(user wire.Hash, ip netip.Addr) identity.Trust {
			at, ok := w.identified[user]
			switch {
			case !ok:
				return identity.TrustUnproven
			case at == ip:
				return identity.TrustIdentified
			default:
				return identity.TrustImpostor
			}
		},
		func(user wire.Hash, _ netip.Addr) bool { return w.banned[user] },
	)
	q.AddFile(file)
	q.AddFile(other)
	return w, q
}

func buildPeer(n int) Peer {
	return Peer{
		User:    wire.Hash{byte(n), byte(n >> 8), byte(n >> 16), 0xAA},
		IP:      netip.AddrFrom4([4]byte{10, byte(n >> 16), byte(n >> 8), byte(n)}),
		UDPPort: 4672,
	}
}

func toTime(seconds float64) time.Time {
	return t0.Add(time.Duration(seconds * float64(time.Second)))
}

func matchActions(t *testing.T, got []Action, want ...Action) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Fatalf("actions = %#v, want %#v", got, want)
	}
}

// startSlots gives peers 1 and 2 the two minimum slots, one second apart.
func startSlots(t *testing.T, q *Queue) {
	t.Helper()
	matchActions(t, q.OnRequest(1, buildPeer(1), file, toTime(0)), Grant{1, file})
	matchActions(t, q.OnRequest(2, buildPeer(2), file, toTime(1)), Grant{2, file})
}

func TestFirstRequestsGetSlotsOneSecondApart(t *testing.T) {
	_, q := buildWorld()
	matchActions(t, q.OnRequest(1, buildPeer(1), file, toTime(0)), Grant{1, file})
	matchActions(t, q.OnRequest(2, buildPeer(2), file, toTime(0.5)), SendRank{2, 1})
	matchActions(t, q.OnTick(toTime(0.9)))
	matchActions(t, q.OnTick(toTime(1.1)), Grant{2, file})
	matchActions(t, q.OnRequest(3, buildPeer(3), file, toTime(3)), SendRank{3, 1})
	matchActions(t, q.OnTick(toTime(5)))
}

func TestRequestFromSlotHolderSwitchesFile(t *testing.T) {
	_, q := buildWorld()
	startSlots(t, q)
	matchActions(t, q.OnRequest(1, buildPeer(1), other, toTime(2)), Grant{1, other})
}

func TestUnsharedFileAndBannedPeerAreIgnored(t *testing.T) {
	w, q := buildWorld()
	matchActions(t, q.OnRequest(1, buildPeer(1), wire.Hash{0xEE}, toTime(0)))
	w.banned[buildPeer(2).User] = true
	matchActions(t, q.OnRequest(2, buildPeer(2), file, toTime(0)))
}

func TestCreditsOutrankWaitingTime(t *testing.T) {
	w, q := buildWorld()
	startSlots(t, q)
	w.ratios[buildPeer(4).User] = 3
	matchActions(t, q.OnRequest(3, buildPeer(3), file, toTime(10)), SendRank{3, 1})
	matchActions(t, q.OnRequest(4, buildPeer(4), file, toTime(20)), SendRank{4, 2})

	if got := q.OnReask(buildPeer(4).IP, 4672, file, toTime(60)); got != (ReaskAck{1}) {
		t.Fatalf("reask = %#v, want rank 1 for the credited peer", got)
	}
	if got := q.OnReask(buildPeer(3).IP, 4672, file, toTime(60)); got != (ReaskAck{2}) {
		t.Fatalf("reask = %#v, want rank 2", got)
	}

	q.OnSent(1, sessionMaxTrans+1)
	matchActions(t, q.OnTick(toTime(60)), Revoke{1, ReasonRotated}, SendRank{1, 3}, Grant{4, file})
}

func TestRotationWaitsForSomeoneQueued(t *testing.T) {
	_, q := buildWorld()
	startSlots(t, q)
	q.OnSent(1, sessionMaxTrans+1)
	matchActions(t, q.OnTick(toTime(2)))
	matchActions(t, q.OnTick(toTime(2*3600)))
}

func TestRotationAfterSessionTime(t *testing.T) {
	_, q := buildWorld()
	startSlots(t, q)
	matchActions(t, q.OnRequest(3, buildPeer(3), file, toTime(10)), SendRank{3, 1})
	matchActions(t, q.OnTick(toTime(3600)))
	q.OnReask(buildPeer(3).IP, 4672, file, toTime(3600))
	matchActions(t, q.OnTick(toTime(3600.5)), Revoke{1, ReasonRotated}, SendRank{1, 2}, Grant{3, file})
}

func TestDisconnectedHighIDWaiterIsCalled(t *testing.T) {
	_, q := buildWorld()
	startSlots(t, q)
	p := buildPeer(3)
	matchActions(t, q.OnRequest(3, p, file, toTime(10)), SendRank{3, 1})
	q.OnConnectionGone(3)
	q.OnConnectionGone(1)
	matchActions(t, q.OnTick(toTime(20)), Connect{p})
	matchActions(t, q.OnConnected(30, p, toTime(25)), Grant{30, file})
	q.OnSent(30, 100)
}

func TestCallThatNeverConnectsFreesSlot(t *testing.T) {
	_, q := buildWorld()
	startSlots(t, q)
	matchActions(t, q.OnRequest(3, buildPeer(3), file, toTime(10)), SendRank{3, 1})
	matchActions(t, q.OnRequest(4, buildPeer(4), file, toTime(11)), SendRank{4, 2})
	q.OnConnectionGone(3)
	q.OnConnectionGone(1)
	matchActions(t, q.OnTick(toTime(20)), Connect{buildPeer(3)})
	matchActions(t, q.OnTick(toTime(50)))
	matchActions(t, q.OnTick(toTime(61)), Grant{4, file})
}

func TestLowIDWaiterTakesSlotWhenItReconnects(t *testing.T) {
	_, q := buildWorld()
	startSlots(t, q)
	low := buildPeer(3)
	low.IsLowID = true
	matchActions(t, q.OnRequest(3, low, file, toTime(10)), SendRank{3, 1})
	matchActions(t, q.OnRequest(4, buildPeer(4), file, toTime(50)), SendRank{4, 2})
	q.OnConnectionGone(3)
	q.OnConnectionGone(1)
	matchActions(t, q.OnTick(toTime(60)), Grant{4, file})

	matchActions(t, q.OnRequest(5, buildPeer(5), file, toTime(61)), SendRank{5, 2})
	matchActions(t, q.OnRequest(33, low, file, toTime(70)), Grant{33, file})
}

func TestWaiterThatStopsReaskingIsPurged(t *testing.T) {
	_, q := buildWorld()
	low := buildPeer(2)
	low.IsLowID = true
	matchActions(t, q.OnRequest(1, buildPeer(1), file, toTime(0)), Grant{1, file})
	matchActions(t, q.OnRequest(2, low, file, toTime(0)), SendRank{2, 1})
	q.OnConnectionGone(2)
	q.OnConnectionGone(1)

	if got := q.OnReask(low.IP, 4672, file, toTime(50*60)); got != (ReaskAck{1}) {
		t.Fatalf("reask = %#v, want rank 1", got)
	}
	matchActions(t, q.OnTick(toTime(100*60)))
	if got := q.OnReask(low.IP, 4672, file, toTime(100*60)); got != (ReaskAck{1}) {
		t.Fatalf("reask = %#v, want rank 1 within an hour of the last reask", got)
	}
	matchActions(t, q.OnTick(toTime(161*60)))
	if got := q.OnReask(low.IP, 4672, file, toTime(161*60)); got != nil {
		t.Fatalf("reask = %#v, want silence for a purged peer", got)
	}
}

func TestReaskAnswers(t *testing.T) {
	_, q := buildWorld()
	startSlots(t, q)
	matchActions(t, q.OnRequest(3, buildPeer(3), file, toTime(10)), SendRank{3, 1})

	if got := q.OnReask(buildPeer(3).IP, 4672, wire.Hash{0xEE}, toTime(20)); got != (FileNotFound{}) {
		t.Fatalf("unshared file: %#v", got)
	}
	if got := q.OnReask(buildPeer(3).IP, 4672, other, toTime(20)); got != nil {
		t.Fatalf("different file: %#v", got)
	}
	if got := q.OnReask(buildPeer(3).IP, 9999, file, toTime(20)); got != (ReaskAck{1}) {
		t.Fatalf("only waiter at the IP: %#v", got)
	}
	if got := q.OnReask(buildPeer(9).IP, 4672, file, toTime(20)); got != nil {
		t.Fatalf("unknown peer with room in the queue: %#v", got)
	}

	twin := buildPeer(3)
	twin.User = wire.Hash{0x77}
	twin.UDPPort = 5000
	matchActions(t, q.OnRequest(4, twin, file, toTime(11)), SendRank{4, 2})
	if got := q.OnReask(twin.IP, 4672, file, toTime(20)); got != (ReaskAck{1}) {
		t.Fatalf("exact port: %#v", got)
	}
	if got := q.OnReask(twin.IP, 6000, file, toTime(20)); got != nil {
		t.Fatalf("ambiguous IP: %#v", got)
	}
}

func TestAtMostThreeWaitersPerIP(t *testing.T) {
	_, q := buildWorld()
	startSlots(t, q)
	for i := range 4 {
		p := buildPeer(3)
		p.User = wire.Hash{byte(i), 0x55}
		got := q.OnRequest(uint64(10+i), p, file, toTime(10))
		if (i < 3) != (len(got) == 1) {
			t.Fatalf("waiter %d from one IP: %#v", i+1, got)
		}
	}
}

func TestQueueFull(t *testing.T) {
	w, q := buildWorld()
	matchActions(t, q.OnRequest(1, buildPeer(1), file, toTime(0)), Grant{1, file})
	for n := 2; n < 2+queueSize; n++ {
		w.ratios[buildPeer(n).User] = 2
		q.OnRequest(uint64(n), buildPeer(n), file, toTime(0))
	}

	if got := q.OnReask(buildPeer(1_000_000).IP, 4672, file, toTime(1)); got != (QueueFull{}) {
		t.Fatalf("reask from a stranger = %#v, want QueueFull", got)
	}
	if got := q.OnReask(buildPeer(2).IP, 4672, file, toTime(1)); got != (ReaskAck{1}) {
		t.Fatalf("reask from a waiter = %#v, want its rank", got)
	}

	matchActions(t, q.OnRequest(9000, buildPeer(1_000_001), file, toTime(1)))
	credited := buildPeer(1_000_002)
	w.ratios[credited.User] = 2
	if got := q.OnRequest(9001, credited, file, toTime(1)); len(got) != 1 {
		t.Fatalf("peer with average credit past the soft limit: %#v", got)
	}

	for n := 2_000_000; len(q.waiters) < hardQueueSize; n++ {
		w.ratios[buildPeer(n).User] = 10
		q.OnRequest(uint64(n), buildPeer(n), file, toTime(1))
	}
	best := buildPeer(3_000_000)
	w.ratios[best.User] = 10
	matchActions(t, q.OnRequest(9002, best, file, toTime(1)))
}

func TestBannedPeersLoseTheirPlace(t *testing.T) {
	w, q := buildWorld()
	startSlots(t, q)
	matchActions(t, q.OnRequest(3, buildPeer(3), file, toTime(10)), SendRank{3, 1})
	matchActions(t, q.OnRequest(4, buildPeer(4), file, toTime(20)), SendRank{4, 2})
	w.banned[buildPeer(3).User] = true
	w.banned[buildPeer(1).User] = true
	matchActions(t, q.OnTick(toTime(30)), Revoke{1, ReasonBanned}, Grant{4, file})
	if got := q.OnReask(buildPeer(3).IP, 4672, file, toTime(31)); got != nil {
		t.Fatalf("banned waiter still queued: %#v", got)
	}
}

func TestRemoveFile(t *testing.T) {
	_, q := buildWorld()
	startSlots(t, q)
	matchActions(t, q.OnRequest(2, buildPeer(2), other, toTime(2)), Grant{2, other})
	matchActions(t, q.OnRequest(3, buildPeer(3), other, toTime(10)), SendRank{3, 1})
	matchActions(t, q.RemoveFile(other), Revoke{2, ReasonFileRemoved})
	if got := q.OnReask(buildPeer(3).IP, 4672, other, toTime(11)); got != (FileNotFound{}) {
		t.Fatalf("reask for removed file = %#v", got)
	}
	matchActions(t, q.OnTick(toTime(12)))
}

// probeSlots queues many peers that each take at most peerRate, sends what
// the link allows every 100 ms for two minutes, and counts open slots.
func probeSlots(rate, linkRate, peerRate int64) int {
	_, q := buildWorld()
	q.SetRate(rate)
	open := map[uint64]bool{1: true}
	for n := 1; n <= 300; n++ {
		q.OnRequest(uint64(n), buildPeer(n), file, toTime(0))
	}
	for tick := range 1200 {
		now := toTime(float64(tick) / 10)
		if len(open) > 0 {
			each := min(linkRate/int64(len(open)), peerRate) / 10
			for conn := range open {
				q.OnSent(conn, each)
			}
		}
		for _, a := range q.OnTick(now) {
			switch a := a.(type) {
			case Grant:
				open[a.Conn] = true
			case Revoke:
				delete(open, a.Conn)
			}
		}
	}
	return len(open)
}

func TestSlotCountFollowsRate(t *testing.T) {
	const kb = 1024
	cases := []struct {
		name                     string
		rate, linkRate, peerRate int64
		min, max                 int
	}{
		{"3 KB/s limit keeps the minimum", 3 * kb, 3 * kb, 50 * kb, 2, 2},
		{"10 KB/s limit", 10 * kb, 10 * kb, 50 * kb, 4, 4},
		{"unlimited with an idle link", 0, 0, 0, 2, 2},
		{"100 KB/s limit", 100 * kb, 100 * kb, 50 * kb, 6, 10},
		{"unlimited grows with what peers take", 0, 4096 * kb, 10 * kb, 5, 10},
		{"unlimited fast link", 0, 100 * 1024 * kb, 50 * kb, 15, 25},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := probeSlots(c.rate, c.linkRate, c.peerRate)
			if got < c.min || got > c.max {
				t.Fatalf("slots = %d, want %d..%d", got, c.min, c.max)
			}
		})
	}
}

// movePeer is peer n's user hash at peer m's address.
func movePeer(n, m int) Peer {
	p := buildPeer(n)
	p.IP = buildPeer(m).IP
	return p
}

func TestSameUserFromTwoAddressesUnproven(t *testing.T) {
	_, q := buildWorld()
	startSlots(t, q)
	matchActions(t, q.OnRequest(3, buildPeer(3), file, toTime(2)), SendRank{3, 1})
	matchActions(t, q.OnRequest(4, buildPeer(4), file, toTime(3)), SendRank{4, 2})
	matchActions(t, q.OnRequest(5, movePeer(3, 9), file, toTime(4)))
	matchActions(t, q.OnRequest(4, buildPeer(4), file, toTime(5)), SendRank{4, 1})
	matchActions(t, q.OnRequest(5, movePeer(3, 9), file, toTime(6)), SendRank{5, 2})
}

func TestSameUserFromTwoAddressesIdentifiedWaiterStays(t *testing.T) {
	w, q := buildWorld()
	startSlots(t, q)
	w.identified[buildPeer(3).User] = buildPeer(3).IP
	matchActions(t, q.OnRequest(3, buildPeer(3), file, toTime(2)), SendRank{3, 1})
	matchActions(t, q.OnRequest(5, movePeer(3, 9), file, toTime(4)))
	matchActions(t, q.OnRequest(3, buildPeer(3), file, toTime(5)), SendRank{3, 1})
}

func TestSameUserFromTwoAddressesIdentifiedNewcomerReplaces(t *testing.T) {
	w, q := buildWorld()
	startSlots(t, q)
	matchActions(t, q.OnRequest(3, buildPeer(3), file, toTime(2)), SendRank{3, 1})
	matchActions(t, q.OnRequest(4, buildPeer(4), file, toTime(3)), SendRank{4, 2})
	w.identified[buildPeer(3).User] = buildPeer(9).IP
	matchActions(t, q.OnRequest(5, movePeer(3, 9), file, toTime(4)), SendRank{5, 2})
	matchActions(t, q.OnRequest(4, buildPeer(4), file, toTime(5)), SendRank{4, 1})
}

func TestImpostorNeverGetsSlot(t *testing.T) {
	w, q := buildWorld()
	startSlots(t, q)
	matchActions(t, q.OnRequest(3, buildPeer(3), file, toTime(2)), SendRank{3, 1})
	w.identified[buildPeer(3).User] = buildPeer(9).IP
	matchActions(t, q.OnRequest(4, buildPeer(4), file, toTime(100)), SendRank{4, 1})
	q.OnConnectionGone(1)
	matchActions(t, q.OnTick(toTime(101)), Grant{4, file})
}

func TestOldClientScoresHalf(t *testing.T) {
	_, q := buildWorld()
	startSlots(t, q)
	old := buildPeer(3)
	old.MuleVersion = 0x19
	emuleHash := buildPeer(4)
	emuleHash.User[5], emuleHash.User[14] = 14, 111
	modern := buildPeer(5)
	modern.MuleVersion = 0x99
	matchActions(t, q.OnRequest(3, old, file, toTime(2)), SendRank{3, 1})
	matchActions(t, q.OnRequest(4, emuleHash, file, toTime(2)), SendRank{4, 1})
	matchActions(t, q.OnRequest(5, modern, file, toTime(12)), SendRank{5, 3})
	matchActions(t, q.OnRequest(5, modern, file, toTime(30)), SendRank{5, 1})
}

func TestHasPeerWhileWaitingOrHoldingASlot(t *testing.T) {
	_, q := buildWorld()
	startSlots(t, q)
	q.OnRequest(3, buildPeer(3), file, toTime(2))
	for _, n := range []int{1, 3} {
		if p := buildPeer(n); !q.HasPeer(p.User, p.IP) {
			t.Errorf("HasPeer(peer %d) = false", n)
		}
	}
	q.OnConnectionGone(1)
	q.RemoveFile(file)
	for _, n := range []int{1, 3, 4} {
		if p := buildPeer(n); q.HasPeer(p.User, p.IP) {
			t.Errorf("HasPeer(peer %d) = true", n)
		}
	}
}
