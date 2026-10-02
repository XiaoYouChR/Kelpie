package transfer_test

import (
	"slices"
	"testing"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/piece"
	"github.com/XiaoYouChR/Kelpie/internal/transfer"
)

// buildEndgame resumes a file of five parts, the last one ten blocks long,
// with the parts before first verified.
func buildEndgame(t *testing.T, first int) *harness {
	data := make([]byte, 4*piece.PartSize+10*piece.BlockSize)
	file := buildFile(data)
	verified := make(piece.Set, piece.PartCount(file.Size))
	for i := range first {
		verified[i] = true
	}
	state := transfer.State{Size: file.Size, File: path, VerifiedParts: verified, Created: start}
	return buildHarness(t, data, transfer.Options{File: file, State: &state})
}

// fast is asked for 3 blocks and delivers them, slow is asked for every
// other missing block, which startEndgame returns.
func (h *harness) startEndgame(fast, slow uint64) []piece.Block {
	full := piece.BuildFullSet(5)
	h.connect(fast, int(fast), full)
	h.connect(slow, int(slow), full)
	h.deliver(fast, 3, false)
	return h.request(slow, 1000)
}

func closes(actions []transfer.Action) []transfer.Close {
	var found []transfer.Close
	for _, action := range actions {
		if c, ok := action.(transfer.Close); ok {
			found = append(found, c)
		}
	}
	return found
}

func TestEndgameTakesOverASlowSourceBlocks(t *testing.T) {
	h := buildEndgame(t, 3)
	h.startEndgame(1, 2)

	blocks, actions := h.transfer.Request(1, 5, h.now)
	if want := []transfer.Close{{Peer: 2, Reason: "slower source"}}; !slices.Equal(closes(actions), want) {
		t.Fatalf("actions %+v, want %+v", actions, want)
	}
	if len(blocks) != 5 {
		t.Fatalf("fast source got %v, want 5 of the slow source's blocks", blocks)
	}
	h.run(h.transfer.OnPeerGone(2, "slower source", h.now))
	h.connect(3, 3, piece.BuildFullSet(5))
	for _, b := range h.request(3, 1000) {
		if slices.Contains(blocks, b) {
			t.Fatalf("block %v asked of the fast source is handed out again", b)
		}
	}
}

func TestEndgameWaitsForTheLastFourParts(t *testing.T) {
	h := buildEndgame(t, 0)
	h.startEndgame(1, 2)

	if blocks, actions := h.transfer.Request(1, 5, h.now); len(blocks) != 0 || len(actions) != 0 {
		t.Fatalf("fast source got %v and %+v five parts from the end", blocks, actions)
	}
}

func TestEndgameKeepsASourceNotTwiceAsSlow(t *testing.T) {
	h := buildEndgame(t, 3)
	slow := h.startEndgame(1, 2)
	h.now = h.now.Add(time.Second)
	for _, b := range slow[:2] {
		h.run(h.transfer.OnBlockReceived(2, b, make([]byte, piece.BlockSize), h.now))
	}

	if blocks, actions := h.transfer.Request(1, 5, h.now); len(blocks) != 0 || len(actions) != 0 {
		t.Fatalf("fast source got %v and %+v from a source half as fast", blocks, actions)
	}
}

// A slot with nothing left to ask for near completion leaves its source
// queued at the usual reask interval; elsewhere, or when the source has
// nothing we need, it counts as having no needed parts.
func TestEndgameRequeuesASourceWithPartsWeNeed(t *testing.T) {
	h := buildEndgame(t, 3)
	h.startEndgame(1, 2)
	h.connect(3, 3, piece.Set{true, true, false, false, false})
	if !h.transfer.OnNoNeededParts(3) {
		t.Fatal("source with only verified parts kept as useful")
	}
	if h.transfer.OnNoNeededParts(1) {
		t.Fatal("source with parts we need marked as having none near completion")
	}

	far := buildEndgame(t, 0)
	far.startEndgame(1, 2)
	if !far.transfer.OnNoNeededParts(1) {
		t.Fatal("source whose slot gave nothing kept as useful five parts from the end")
	}
}
