package transfer_test

import (
	"slices"
	"testing"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/aich"
	"github.com/XiaoYouChR/Kelpie/internal/piece"
	"github.com/XiaoYouChR/Kelpie/internal/transfer"
	"github.com/XiaoYouChR/Kelpie/internal/wire"
)

func buildTree(data []byte) *aich.Tree {
	var hasher aich.Hasher
	hasher.Write(data)
	return aich.BuildTree(int64(len(data)), hasher.Leaves())
}

// fillPart writes part 0: peer bad sends the block at badBlock corrupted,
// peer good every other block.
func (h *harness) fillPart(good, bad uint64, badBlock int) {
	for index := range piece.BlockCount(int64(len(h.data)), 0) {
		peer, isCorrupt := good, false
		if index == badBlock {
			peer, isCorrupt = bad, true
		}
		h.transfer.OnPeerParts(peer, piece.Set{true, false})
		h.deliver(peer, 1, isCorrupt)
		h.transfer.OnPeerParts(peer, piece.Set{false, false})
	}
}

func lastRecovery(t *testing.T, actions []transfer.Action) transfer.RequestRecovery {
	t.Helper()
	for i := len(actions) - 1; i >= 0; i-- {
		if r, ok := actions[i].(transfer.RequestRecovery); ok {
			return r
		}
	}
	t.Fatal("no recovery requested")
	return transfer.RequestRecovery{}
}

func closedPeers(actions []transfer.Action) []uint64 {
	var peers []uint64
	for _, action := range actions {
		if c, ok := action.(transfer.Close); ok {
			peers = append(peers, c.Peer)
		}
	}
	return peers
}

func TestRepairRedownloadsOnlyTheBadBlock(t *testing.T) {
	data := buildData(piece.PartSize + 5000)
	tree := buildTree(data)
	file := buildFile(data)
	file.AICHHash = tree.Root()
	h := buildHarness(t, data, transfer.Options{File: file})
	h.connect(1, 1, nil)
	h.connect(2, 2, nil)
	h.connect(3, 3, nil)
	h.transfer.OnRoot(3, tree.Root())

	before := len(h.actions)
	h.fillPart(1, 2, 4)
	request := lastRecovery(t, h.actions[before:])
	if request != (transfer.RequestRecovery{Peer: 3, Part: 0, Root: tree.Root()}) {
		t.Fatalf("request = %+v", request)
	}
	if closed := closedPeers(h.actions[before:]); len(closed) > 0 {
		t.Fatalf("closed %v before the repair", closed)
	}

	before = len(h.actions)
	h.run(h.transfer.OnRecovery(3, 0, tree.Root(), tree.BuildRecovery(0), h.now))
	if closed := closedPeers(h.actions[before:]); !slices.Equal(closed, []uint64{2}) {
		t.Fatalf("closed %v, want only the sender of the bad block", closed)
	}
	h.transfer.OnPeerParts(1, piece.Set{true, false})
	bad := piece.Block{Begin: 4 * piece.BlockSize, End: 5 * piece.BlockSize}
	if got := h.request(1, 10); !slices.Equal(got, []piece.Block{bad}) {
		t.Fatalf("asked again for %v, want only %v", got, bad)
	}
	h.run(h.transfer.OnBlockReceived(1, bad, data[bad.Begin:bad.End], h.now))
	if !h.transfer.ToState().VerifiedParts[0] {
		t.Fatal("repaired part not verified")
	}
}

// A sender of a bad block that sent enough good data stays: aMule bans only
// above 32% corrupt (CorruptionBlackBox.cpp:39).
func TestRepairKeepsASenderMostlyGood(t *testing.T) {
	data := buildData(2*piece.PartSize + 5000)
	tree := buildTree(data)
	file := buildFile(data)
	file.AICHHash = tree.Root()
	h := buildHarness(t, data, transfer.Options{File: file})
	h.connect(1, 1, nil)
	h.connect(2, 2, nil)
	h.connect(3, 3, nil)
	h.transfer.OnRoot(3, tree.Root())
	h.transfer.OnPeerParts(2, piece.Set{false, true, false})
	for h.deliver(2, 10, false) > 0 {
	}
	if !h.transfer.ToState().VerifiedParts[1] {
		t.Fatal("part 1 not verified")
	}

	h.fillPart(1, 2, 4)
	before := len(h.actions)
	h.run(h.transfer.OnRecovery(3, 0, tree.Root(), tree.BuildRecovery(0), h.now))
	if closed := closedPeers(h.actions[before:]); len(closed) != 0 {
		t.Fatalf("closed %v, but the bad block is under 32%% of what 2 sent", closed)
	}
}

// The short last block of a part counts whole when it is bad, as aMule
// counts corrupt data as at least EMBLOCKSIZE
// (CorruptionBlackBox.cpp:166-169): two good blocks and a bad short one
// are 33% corrupt and banned, where its 143,360 actual bytes would be 28%.
func TestRepairCountsAShortBadBlockWhole(t *testing.T) {
	data := buildData(piece.PartSize + 5000)
	tree := buildTree(data)
	file := buildFile(data)
	file.AICHHash = tree.Root()
	h := buildHarness(t, data, transfer.Options{File: file})
	h.connect(1, 1, nil)
	h.connect(2, 2, nil)
	h.connect(3, 3, nil)
	h.transfer.OnRoot(3, tree.Root())
	last := piece.BlockCount(file.Size, 0) - 1
	for index := range last + 1 {
		peer := uint64(1)
		if index < 2 || index == last {
			peer = 2
		}
		h.transfer.OnPeerParts(peer, piece.Set{true, false})
		h.deliver(peer, 1, index == last)
		h.transfer.OnPeerParts(peer, piece.Set{false, false})
	}

	before := len(h.actions)
	h.run(h.transfer.OnRecovery(3, 0, tree.Root(), tree.BuildRecovery(0), h.now))
	if closed := closedPeers(h.actions[before:]); !slices.Equal(closed, []uint64{2}) {
		t.Fatalf("closed %v, want the sender of the short bad block", closed)
	}
}

func TestRepairAsksAnotherSourceThenGivesUp(t *testing.T) {
	data := buildData(piece.PartSize + 5000)
	tree := buildTree(data)
	file := buildFile(data)
	file.AICHHash = tree.Root()
	h := buildHarness(t, data, transfer.Options{File: file})
	for peer := range uint64(4) {
		h.connect(peer+1, int(peer+1), nil)
	}
	h.transfer.OnRoot(3, tree.Root())
	h.transfer.OnRoot(4, tree.Root())
	h.transfer.OnRoot(2, wire.AICHHash{9})

	before := len(h.actions)
	h.fillPart(1, 2, 0)
	first := lastRecovery(t, h.actions[before:]).Peer

	before = len(h.actions)
	h.run(h.transfer.OnRecoveryFailed(first, h.now))
	second := lastRecovery(t, h.actions[before:]).Peer
	if second == first || second != 3 && second != 4 {
		t.Fatalf("asked %d after %d failed", second, first)
	}

	before = len(h.actions)
	h.run(h.transfer.OnPeerGone(second, "closed", h.now))
	if closed := closedPeers(h.actions[before:]); len(closed) != 0 {
		t.Fatalf("closed %v once no source can repair, want nobody banned", closed)
	}
	h.transfer.OnPeerParts(1, piece.Set{true, false})
	if got := h.request(1, 100); len(got) != piece.BlockCount(file.Size, 0) {
		t.Fatalf("asked again for %d blocks, want the whole part", len(got))
	}
}

func TestRecoveryFromAnotherRootIsRefused(t *testing.T) {
	data := buildData(piece.PartSize + 5000)
	tree := buildTree(data)
	file := buildFile(data)
	file.AICHHash = tree.Root()
	h := buildHarness(t, data, transfer.Options{File: file})
	h.connect(1, 1, nil)
	h.connect(2, 2, nil)
	h.connect(3, 3, nil)
	h.transfer.OnRoot(3, tree.Root())
	h.fillPart(1, 2, 0)

	wrong := append([]byte(nil), data...)
	wrong[0] ^= 1
	before := len(h.actions)
	h.run(h.transfer.OnRecovery(3, 0, tree.Root(), buildTree(wrong).BuildRecovery(0), h.now))
	if countActions[transfer.HashBlocks](h.actions[before:]) != 0 || len(closedPeers(h.actions[before:])) != 0 {
		t.Fatalf("recovery data of other content: %+v", h.actions[before:])
	}
}

// A root no part agrees with stops repairs: the part goes whole.
func TestRepairThatFindsNoBadBlockDropsTheRoot(t *testing.T) {
	data := buildData(piece.PartSize + 5000)
	file := buildFile(data)
	wrong := append([]byte(nil), data...)
	wrong[0] ^= 0xFF
	tree := buildTree(wrong)
	file.AICHHash = tree.Root()
	h := buildHarness(t, data, transfer.Options{File: file})
	h.connect(1, 1, nil)
	h.connect(2, 2, nil)
	h.connect(3, 3, nil)
	h.transfer.OnRoot(3, tree.Root())
	h.fillPart(1, 2, 0)

	before := len(h.actions)
	h.run(h.transfer.OnRecovery(3, 0, tree.Root(), tree.BuildRecovery(0), h.now))
	if closed := closedPeers(h.actions[before:]); len(closed) != 0 {
		t.Fatalf("closed %v, want nobody banned by a wrong root", closed)
	}
	h.connect(4, 4, nil)
	h.transfer.OnRoot(4, tree.Root())
	before = len(h.actions)
	h.fillPart(4, 4, 0)
	if countActions[transfer.RequestRecovery](h.actions[before:]) != 0 {
		t.Fatal("asked for recovery with a root that proved wrong")
	}
}

// Without a root in the link one is trusted once ten /20 prefixes sent it
// and they are at least 92% of all voters.
func TestRootIsTrustedByVotes(t *testing.T) {
	data := buildData(piece.PartSize + 5000)
	tree := buildTree(data)
	h := buildHarness(t, data, transfer.Options{File: buildFile(data)})
	h.connect(1, 1, nil)
	h.connect(2, 2, nil)
	vote := func(peer uint64, prefix int, root wire.AICHHash) {
		h.connect(peer, prefix<<12|int(peer), nil)
		h.transfer.OnRoot(peer, root)
	}
	for i := range 9 {
		vote(uint64(10+i), i+1, tree.Root())
	}
	vote(30, 1, tree.Root())
	before := len(h.actions)
	h.fillPart(1, 2, 0)
	if countActions[transfer.RequestRecovery](h.actions[before:]) != 0 {
		t.Fatal("trusted a root from nine prefixes")
	}

	h = buildHarness(t, data, transfer.Options{File: buildFile(data)})
	h.connect(1, 1, nil)
	h.connect(2, 2, nil)
	for i := range 10 {
		vote(uint64(10+i), i+1, tree.Root())
	}
	vote(30, 11, wire.AICHHash{9})
	before = len(h.actions)
	h.fillPart(1, 2, 0)
	if countActions[transfer.RequestRecovery](h.actions[before:]) != 0 {
		t.Fatal("trusted a root with 10 of 11 prefixes, below 92%")
	}

	h = buildHarness(t, data, transfer.Options{File: buildFile(data)})
	h.connect(1, 1, nil)
	h.connect(2, 2, nil)
	for i := range 10 {
		vote(uint64(10+i), i+1, tree.Root())
	}
	before = len(h.actions)
	h.fillPart(1, 2, 0)
	if countActions[transfer.RequestRecovery](h.actions[before:]) != 1 {
		t.Fatal("did not trust a root from ten prefixes")
	}
}

// One bad part after another asks a source for recovery data at most once
// per MIN_REQUESTTIME: aMule 3.1.0 counts a sooner OP_AICHREQUEST as
// aggressive and bans at the fourth.
func TestRecoveryAsksASourceOncePerMinRequestTime(t *testing.T) {
	const minRequestTime = 590 * time.Second
	for _, wait := range []time.Duration{minRequestTime - time.Second, minRequestTime} {
		data := buildData(2*piece.PartSize + 5000)
		tree := buildTree(data)
		file := buildFile(data)
		file.AICHHash = tree.Root()
		h := buildHarness(t, data, transfer.Options{File: file})
		for peer := range uint64(4) {
			h.connect(peer+1, int(peer+1), nil)
		}
		h.transfer.OnRoot(3, tree.Root())
		h.fillPart(1, 2, 4)
		if got := lastRecovery(t, h.actions).Peer; got != 3 {
			t.Fatalf("asked %d", got)
		}
		h.run(h.transfer.OnRecovery(3, 0, tree.Root(), tree.BuildRecovery(0), h.now))

		h.now = h.now.Add(wait)
		before := len(h.actions)
		for index := range piece.BlockCount(int64(len(data)), 1) {
			h.transfer.OnPeerParts(4, piece.Set{false, true, false})
			h.deliver(4, 1, index == 0)
		}
		isAsked := countActions[transfer.RequestRecovery](h.actions[before:]) == 1
		if isAsked != (wait >= minRequestTime) {
			t.Fatalf("after %v asked again: %v", wait, isAsked)
		}
	}
}
