package transfer_test

import (
	"testing"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/piece"
	"github.com/XiaoYouChR/Kelpie/internal/transfer"
)

// A ban for corrupt data lasts CLIENTBANTIME, not the whole run.
func TestBanExpires(t *testing.T) {
	data := buildData(2*piece.PartSize + 5000)
	h := buildHarness(t, data, transfer.Options{File: buildFile(data)})
	h.connect(1, 1, piece.Set{true, false, false})
	for h.deliver(1, 10, true) > 0 {
	}
	isBanned := func(peer uint64) bool {
		actions := h.transfer.OnPeerConnected(peer, transfer.Source{Endpoint: endpoint(1), UserHash: userHash(1)}, h.now)
		return len(actions) == 1 && actions[0] == (transfer.Close{Peer: peer, Reason: "banned"})
	}
	if !isBanned(2) {
		t.Fatal("corrupt sender not banned")
	}
	h.now = h.now.Add(2*time.Hour - time.Second)
	h.tick(transfer.Tick{})
	if !isBanned(3) {
		t.Fatal("ban lifted early")
	}
	h.now = h.now.Add(time.Second)
	h.tick(transfer.Tick{})
	if isBanned(4) {
		t.Fatal("ban still holds after CLIENTBANTIME")
	}
}
