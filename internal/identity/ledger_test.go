package identity

import (
	"math"
	"net/netip"
	"reflect"
	"testing"

	"github.com/XiaoYouChR/Kelpie/internal/wire"
)

var (
	alice    = wire.Hash{1}
	home     = netip.MustParseAddr("198.51.100.1")
	away     = netip.MustParseAddr("198.51.100.2")
	keyA     = []byte("key A")
	keyB     = []byte("key B")
	megabyte = int64(1048576)
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
		ledger := BuildLedger([]Credit{{User: alice, Uploaded: c.uploaded, Downloaded: c.downloaded}})
		if got := ledger.Ratio(alice, home); math.Abs(got-c.want) > 1e-9 {
			t.Errorf("up %d down %d: ratio %v, want %v", c.uploaded, c.downloaded, got, c.want)
		}
	}
}

func TestUnknownUserRatioIsOne(t *testing.T) {
	if got := BuildLedger(nil).Ratio(alice, home); got != 1 {
		t.Fatalf("ratio %v", got)
	}
}

func TestUserWithoutKeyIsCredited(t *testing.T) {
	ledger := BuildLedger(nil)
	ledger.OnTransferred(alice, home, 0, 10*megabyte)
	if got := ledger.Ratio(alice, away); got != math.Sqrt(12) {
		t.Fatalf("ratio %v", got)
	}
}

func TestOfferedKeyStopsCreditUntilIdentified(t *testing.T) {
	ledger := BuildLedger([]Credit{{User: alice, Downloaded: uint64(10 * megabyte)}})
	ledger.OnKeyReceived(alice, keyA)
	if got := ledger.Ratio(alice, home); got != 1 {
		t.Fatalf("unidentified ratio %v", got)
	}
	ledger.OnTransferred(alice, home, 0, megabyte)

	ledger.OnIdentified(alice, home)
	want := []Credit{{User: alice, Uploaded: 1, Downloaded: 1, PublicKey: keyA}}
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
	ledger := BuildLedger([]Credit{{User: alice, Downloaded: uint64(10 * megabyte), PublicKey: keyA}})
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
	ledger := BuildLedger([]Credit{{User: alice, Downloaded: uint64(10 * megabyte), PublicKey: keyA}})
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
	ledger := BuildLedger([]Credit{{User: alice, Downloaded: uint64(10 * megabyte), PublicKey: keyA}})
	ledger.OnIdentified(alice, home)
	ledger.OnIdentityFailed(alice)
	if got := ledger.Ratio(alice, home); got == 1 {
		t.Fatal("impostor's failure revoked the identified user's credit")
	}
}

func TestPublicKeyByUser(t *testing.T) {
	ledger := BuildLedger(nil)
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
	ledger := BuildLedger(nil)
	ledger.Ratio(wire.Hash{9}, home)
	ledger.OnIdentityFailed(wire.Hash{8})
	ledger.OnTransferred(alice, home, 5, 0)
	ledger.OnTransferred(bob, home, 0, 7)
	want := []Credit{{User: bob, Downloaded: 7}, {User: alice, Uploaded: 5}}
	if got := ledger.ToCredits(); !reflect.DeepEqual(got, want) {
		t.Fatalf("credits %+v", got)
	}
	restored := BuildLedger(want).ToCredits()
	if !reflect.DeepEqual(restored, want) {
		t.Fatalf("round trip %+v", restored)
	}
}
