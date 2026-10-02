package transfer_test

import (
	"testing"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/piece"
	"github.com/XiaoYouChR/Kelpie/internal/transfer"
)

// A ban for corrupt data lasts CLIENTBANTIME, not the whole run.
func TestBanExpires(t *testing.T) {
	data := buildData(piece.PartSize + 5000)
	tree := buildTree(data)
	file := buildFile(data)
	file.AICHHash = tree.Root()
	h := buildHarness(t, data, transfer.Options{File: file})
	h.connect(1, 1, nil)
	h.connect(2, 2, nil)
	h.connect(3, 3, nil)
	h.transfer.OnRoot(3, tree.Root())
	h.fillPart(1, 2, 4)
	h.run(h.transfer.OnRecovery(3, 0, tree.Root(), tree.BuildRecovery(0)))
	isBanned := func(peer uint64) bool {
		actions := h.transfer.OnPeerConnected(peer, transfer.Source{Endpoint: endpoint(2), UserHash: userHash(2)}, h.now)
		return len(actions) == 1 && actions[0] == (transfer.Close{Peer: peer, Reason: "banned"})
	}
	if !isBanned(4) {
		t.Fatal("corrupt sender not banned")
	}
	h.now = h.now.Add(2*time.Hour - time.Second)
	h.tick(transfer.Tick{})
	if !isBanned(5) {
		t.Fatal("ban lifted early")
	}
	h.now = h.now.Add(time.Second)
	h.tick(transfer.Tick{})
	if isBanned(6) {
		t.Fatal("ban still holds after CLIENTBANTIME")
	}
}
