package transfer

import (
	"math/rand/v2"
	"net/netip"
	"testing"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/link"
	"github.com/XiaoYouChR/Kelpie/internal/piece"
	"github.com/XiaoYouChR/Kelpie/internal/wire"
)

// Connections that come and go are not remembered as senders, except one
// whose block waits for its part's hash and may still prove corrupt.
func TestSendersAreForgotten(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	size := 2 * piece.PartSize
	file := link.File{Name: "f.bin", Size: size, Hash: wire.Hash{1}, PartHashes: []wire.Hash{{2}, {3}}}
	tr := Build(Options{File: file, Path: "/f.bin", Mode: ModeDownload, Random: rand.New(rand.NewPCG(1, 1))}, now)
	for peer := range uint64(1000) {
		addr := netip.AddrFrom4([4]byte{198, 51, byte(peer >> 8), byte(peer)})
		tr.OnPeerConnected(peer, Hello{Endpoint: netip.AddrPortFrom(addr, 4662), UserHash: wire.Hash{byte(peer), byte(peer >> 8), 7}}, now)
		if peer == 0 {
			tr.OnPeerParts(peer, piece.BuildFullSet(2))
			tr.OnSlotGranted(peer, now)
			block := tr.Request(peer, 1)[0]
			tr.OnBlockReceived(peer, block, make([]byte, block.End-block.Begin), now)
		}
		tr.OnPeerGone(peer, "closed", now)
	}
	tr.OnTick(Tick{Now: now})
	if len(tr.senders) != 1 || tr.senders[0] == nil {
		t.Fatalf("%d senders remembered, want only the one with an unverified block", len(tr.senders))
	}
}
