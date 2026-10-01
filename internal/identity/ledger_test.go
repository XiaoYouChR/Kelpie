package identity

import (
	"math"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/wire"
)

var (
	alice    = wire.Hash{1}
	home     = netip.MustParseAddr("198.51.100.1")
	away     = netip.MustParseAddr("198.51.100.2")
	keyA     = []byte("key A")
	keyB     = []byte("key B")
	megabyte = int64(1048576)
	today    = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
)

func TestRatioFormula(t *testing.T) {
	cases := []struct {
		uploaded, downloaded uint64
		want                 float64
	}{
		{0, 0, 1},
		{0, 999999, 1},
		{0, 1000000, math.Sqrt(1000000.0/1048576 + 2)},
		{0, 100 * 1048576, 10},
		{100 * 1048576, 100 * 1048576, 2},
		{400 * 1048576, 100 * 1048576, 1},
		{2 * 1048576, 9 * 1048576, math.Sqrt(11)},
		{1, 1000 * 1048576, 10},
	}
	for _, c := range cases {
		ledger := BuildLedger([]Credit{{User: alice, Uploaded: c.uploaded, Downloaded: c.downloaded}}, today)
		if got := ledger.Ratio(alice, home); math.Abs(got-c.want) > 1e-9 {
			t.Errorf("up %d down %d: ratio %v, want %v", c.uploaded, c.downloaded, got, c.want)
		}
	}
}

func TestUnknownUserRatioIsOne(t *testing.T) {
	if got := BuildLedger(nil, today).Ratio(alice, home); got != 1 {
		t.Fatalf("ratio %v", got)
	}
}

func TestUserWithoutKeyIsCredited(t *testing.T) {
	ledger := BuildLedger(nil, today)
	ledger.OnTransferred(alice, home, 0, 10*megabyte)
	if got := ledger.Ratio(alice, away); got != math.Sqrt(12) {
		t.Fatalf("ratio %v", got)
	}
}

func TestOfferedKeyStopsCreditUntilIdentified(t *testing.T) {
	ledger := BuildLedger([]Credit{{User: alice, Downloaded: uint64(10 * megabyte)}}, today)
	ledger.OnKeyReceived(alice, keyA)
	if got := ledger.Ratio(alice, home); got != 1 {
		t.Fatalf("unidentified ratio %v", got)
	}
	ledger.OnTransferred(alice, home, 0, megabyte)

	ledger.OnIdentified(alice, home)
	want := []Credit{{User: alice, Uploaded: 1, Downloaded: 1, PublicKey: keyA, LastSeen: today}}
	if got := ledger.ToCredits(); !reflect.DeepEqual(got, want) {
		t.Fatalf("credits %+v, want %+v (unproven credits reset)", got, want)
	}

	ledger.OnTransferred(alice, home, megabyte, 20*megabyte)
	if got := ledger.Ratio(alice, home); got <= 1 {
		t.Fatalf("identified ratio %v", got)
	}
	if got := ledger.Ratio(alice, away); got != 1 {
		t.Fatalf("ratio from another address %v", got)
	}
	ledger.OnTransferred(alice, away, 0, 50*megabyte)
	if got := ledger.ToCredits()[0].Downloaded; got != uint64(20*megabyte)+1 {
		t.Fatalf("downloaded %d: transfer from another address was counted", got)
	}
}

func TestStoredKeyNeedsIdentificationAfterLoad(t *testing.T) {
	ledger := BuildLedger([]Credit{{User: alice, Downloaded: uint64(10 * megabyte), PublicKey: keyA}}, today)
	if got := ledger.Ratio(alice, home); got != 1 {
		t.Fatalf("ratio before identification %v", got)
	}
	ledger.OnIdentified(alice, home)
	if got := ledger.Ratio(alice, home); got != math.Sqrt(12) {
		t.Fatalf("ratio after identification %v", got)
	}
	if got := ledger.ToCredits()[0].Downloaded; got != uint64(10*megabyte) {
		t.Fatalf("stored credits reset on re-identification: %d", got)
	}
}

func TestStoredKeyIsNotReplaced(t *testing.T) {
	ledger := BuildLedger([]Credit{{User: alice, Downloaded: uint64(10 * megabyte), PublicKey: keyA}}, today)
	ledger.OnKeyReceived(alice, keyB)
	if got := ledger.PublicKeyByUser(alice); string(got) != string(keyA) {
		t.Fatalf("key to verify against = %q", got)
	}
	ledger.OnIdentityFailed(alice)
	ledger.OnTransferred(alice, home, 0, megabyte)
	if got := ledger.Ratio(alice, home); got != 1 {
		t.Fatalf("failed identity ratio %v", got)
	}
	if got := ledger.ToCredits()[0].Downloaded; got != uint64(10*megabyte) {
		t.Fatalf("failed identity was credited: %d", got)
	}
}

func TestFailureDoesNotRevokeIdentification(t *testing.T) {
	ledger := BuildLedger([]Credit{{User: alice, Downloaded: uint64(10 * megabyte), PublicKey: keyA}}, today)
	ledger.OnIdentified(alice, home)
	ledger.OnIdentityFailed(alice)
	if got := ledger.Ratio(alice, home); got == 1 {
		t.Fatal("impostor's failure revoked the identified user's credit")
	}
}

func TestPublicKeyByUser(t *testing.T) {
	ledger := BuildLedger(nil, today)
	if got := ledger.PublicKeyByUser(alice); got != nil {
		t.Fatalf("unknown user key %q", got)
	}
	ledger.OnKeyReceived(alice, keyA)
	if got := ledger.PublicKeyByUser(alice); string(got) != string(keyA) {
		t.Fatalf("offered key %q", got)
	}
}

func TestToCreditsSkipsEmptyAndSorts(t *testing.T) {
	bob := wire.Hash{0}
	ledger := BuildLedger(nil, today)
	ledger.Ratio(wire.Hash{9}, home)
	ledger.OnIdentityFailed(wire.Hash{8})
	ledger.OnHello(alice, today)
	ledger.OnHello(bob, today)
	ledger.OnTransferred(alice, home, 5, 0)
	ledger.OnTransferred(bob, home, 0, 7)
	want := []Credit{{User: bob, Downloaded: 7, LastSeen: today}, {User: alice, Uploaded: 5, LastSeen: today}}
	if got := ledger.ToCredits(); !reflect.DeepEqual(got, want) {
		t.Fatalf("credits %+v", got)
	}
	restored := BuildLedger(want, today).ToCredits()
	if !reflect.DeepEqual(restored, want) {
		t.Fatalf("round trip %+v", restored)
	}
}

func TestCreditsExpireAfter150Days(t *testing.T) {
	bob, carol := wire.Hash{2}, wire.Hash{3}
	ledger := BuildLedger([]Credit{
		{User: alice, Downloaded: 7, LastSeen: today.Add(-150 * 24 * time.Hour)},
		{User: bob, Downloaded: 7, LastSeen: today.Add(-151 * 24 * time.Hour)},
		{User: carol, Downloaded: 7},
	}, today)
	want := []Credit{
		{User: alice, Downloaded: 7, LastSeen: today.Add(-150 * 24 * time.Hour)},
		{User: carol, Downloaded: 7, LastSeen: today},
	}
	if got := ledger.ToCredits(); !reflect.DeepEqual(got, want) {
		t.Fatalf("credits %+v", got)
	}
}

func TestHelloRenewsLastSeen(t *testing.T) {
	ledger := BuildLedger([]Credit{{User: alice, Downloaded: 7, LastSeen: today.Add(-100 * 24 * time.Hour)}}, today)
	ledger.OnHello(alice, today)
	if got := ledger.ToCredits()[0].LastSeen; !got.Equal(today) {
		t.Fatalf("last seen %v", got)
	}
	later := today.Add(100 * 24 * time.Hour)
	if got := BuildLedger(ledger.ToCredits(), later).ToCredits(); len(got) != 1 {
		t.Fatalf("renewed credit expired: %+v", got)
	}
}

func TestTrustByUser(t *testing.T) {
	ledger := BuildLedger([]Credit{{User: alice, PublicKey: keyA}}, today)
	if got := ledger.TrustByUser(alice, home); got != TrustUnproven {
		t.Fatalf("before identification %v", got)
	}
	ledger.OnIdentified(alice, home)
	if got := ledger.TrustByUser(alice, home); got != TrustIdentified {
		t.Fatalf("identified address %v", got)
	}
	if got := ledger.TrustByUser(alice, away); got != TrustImpostor {
		t.Fatalf("other address %v", got)
	}
	if got := ledger.TrustByUser(wire.Hash{9}, home); got != TrustUnproven {
		t.Fatalf("unknown user %v", got)
	}
}

func TestIdleUsersAreRemoved(t *testing.T) {
	ledger := BuildLedger(nil, today)
	for i := range 1000 {
		user := wire.Hash{byte(i), byte(i >> 8), 5}
		ledger.OnHello(user, today)
		ledger.OnKeyReceived(user, keyA)
		ledger.OnIdentified(user, home)
	}
	ledger.OnHello(alice, today)
	ledger.OnTransferred(alice, home, 5, 0)
	if got := ledger.ToCredits(); len(got) != 1 || got[0].User != alice {
		t.Fatalf("saved %d users, want only the one with traffic", len(got))
	}
	ledger.RemoveIdle(today.Add(idleTime - time.Second))
	if len(ledger.accounts) != 1001 {
		t.Fatalf("%d users before idleTime, want 1001", len(ledger.accounts))
	}
	ledger.RemoveIdle(today.Add(idleTime))
	if len(ledger.accounts) != 1 || ledger.accounts[alice] == nil {
		t.Fatalf("%d users after idleTime, want only the one with traffic", len(ledger.accounts))
	}
}
