package transfer

import (
	"math/rand/v2"
	"slices"
	"testing"

	"github.com/XiaoYouChR/Kelpie/internal/piece"
)

const (
	peerA uint64 = iota + 1
	peerB
	peerC
)

func buildEmptyPicker(t *testing.T, size int64, seed uint64) *picker {
	t.Helper()
	return buildResumedPicker(t, size, nil, nil, seed)
}

func buildResumedPicker(t *testing.T, size int64, verified piece.Set, written []piece.Block, seed uint64) *picker {
	t.Helper()
	picker, err := buildPicker(size, verified, written, rand.New(rand.NewPCG(seed, 0)))
	if err != nil {
		t.Fatal(err)
	}
	return picker
}

func partsOf(blocks []piece.Block) []int {
	var parts []int
	for _, b := range blocks {
		parts = append(parts, b.Part())
	}
	return parts
}

func TestRequestPrefersRarestPart(t *testing.T) {
	picker := buildEmptyPicker(t, 3*piece.PartSize, 1)
	picker.onPeerParts(peerA, piece.Set{true, true, true})
	picker.onPeerParts(peerB, piece.Set{false, true, true})
	picker.onPeerParts(peerC, piece.Set{false, false, true})

	if got := partsOf(picker.request(peerA, 1)); !slices.Equal(got, []int{0}) {
		t.Fatalf("a got parts %v, want the rarest part 0", got)
	}
	if got := partsOf(picker.request(peerB, 1)); !slices.Equal(got, []int{1}) {
		t.Fatalf("b got parts %v, want its rarest part 1", got)
	}
}

func TestRequestKeepsAPeerOnItsPart(t *testing.T) {
	picker := buildEmptyPicker(t, 2*piece.PartSize, 1)
	picker.onPeerParts(peerA, piece.Set{true, true})
	picker.onPeerParts(peerB, piece.Set{true, true})
	first := picker.request(peerA, 1)[0]

	got := picker.request(peerA, 1)
	if want := (piece.Block{Begin: first.End, End: first.End + piece.BlockSize}); !slices.Equal(got, []piece.Block{want}) {
		t.Fatalf("a got %v, want the next block of its part, %v", got, want)
	}
}

func TestRequestSpreadsPeersOverPartsNobodyDownloads(t *testing.T) {
	picker := buildEmptyPicker(t, 2*piece.PartSize, 1)
	picker.onPeerParts(peerA, piece.Set{true, true})
	picker.onPeerParts(peerB, piece.Set{true, true})
	fromA := picker.request(peerA, 1)

	if got := partsOf(picker.request(peerB, 1)); slices.Equal(got, partsOf(fromA)) {
		t.Fatalf("b got part %v, which a downloads, while the other part has no peer", got)
	}
}

// A very rare part goes first even when another part is half received
// (aMule ranks it 0..xxxx, PartFile.cpp:2269-2275).
func TestRequestPrefersVeryRarePartToStartedOne(t *testing.T) {
	head := piece.Block{Begin: piece.PartSize, End: piece.PartSize + piece.BlockSize}
	picker := buildResumedPicker(t, 2*piece.PartSize, nil, []piece.Block{head}, 1)
	picker.onPeerParts(peerA, piece.Set{true, true})
	picker.onPeerParts(peerB, piece.Set{false, true})
	picker.onPeerParts(peerC, piece.Set{false, true})

	if got := partsOf(picker.request(peerA, 1)); !slices.Equal(got, []int{0}) {
		t.Fatalf("a got parts %v, want the very rare part 0", got)
	}
}

// Peers join a very rare part another peer downloads rather than start a
// common one: very rare parts are ranked alike whether requested or not.
func TestRequestJoinsVeryRarePartInProgress(t *testing.T) {
	picker := buildEmptyPicker(t, 2*piece.PartSize, 1)
	picker.onPeerParts(peerA, piece.Set{true, true})
	picker.onPeerParts(peerB, piece.Set{true, true})
	for peer := range uint64(18) {
		picker.onPeerParts(100+peer, piece.Set{false, true})
	}
	if got := partsOf(picker.request(peerB, 1)); !slices.Equal(got, []int{0}) {
		t.Fatalf("b got parts %v, want the very rare part 0", got)
	}
	if got := partsOf(picker.request(peerA, 1)); !slices.Equal(got, []int{0}) {
		t.Fatalf("a got parts %v, want the very rare part 0 b downloads", got)
	}
}

func TestRequestBreaksTiesWithInjectedRandom(t *testing.T) {
	firstParts := map[int]bool{}
	for seed := range uint64(20) {
		picks := make([][]piece.Block, 2)
		for i := range picks {
			picker := buildEmptyPicker(t, 4*piece.PartSize, seed)
			picker.onPeerParts(peerA, piece.BuildFullSet(4))
			picks[i] = picker.request(peerA, 1)
		}
		if !slices.Equal(picks[0], picks[1]) {
			t.Fatalf("seed %d picked %v and %v", seed, picks[0], picks[1])
		}
		firstParts[picks[0][0].Part()] = true
	}
	if len(firstParts) < 2 {
		t.Fatalf("20 seeds always picked part %v first", firstParts)
	}
}

func TestRequestNeverHandsOutARequestedBlock(t *testing.T) {
	size := piece.PartSize
	picker := buildEmptyPicker(t, size, 1)
	for _, peer := range []uint64{peerA, peerB, peerC} {
		picker.onPeerParts(peer, piece.Set{true})
	}
	fromA := picker.request(peerA, 50)
	fromB := picker.request(peerB, 10)

	if len(fromB) != 3 {
		t.Fatalf("b got %d blocks, want the 3 a was not asked for", len(fromB))
	}
	for _, b := range fromB {
		if slices.Contains(fromA, b) {
			t.Fatalf("b got %v, already asked of a", b)
		}
	}
	if got := picker.request(peerC, 100); len(got) != 0 {
		t.Fatalf("c got %v, but every block is asked of a or b", got)
	}
}

// A block handed over from a cancelled peer may still arrive from it; only
// the first delivery is written.
func TestReceivedBlockIsWrittenOnce(t *testing.T) {
	picker := buildEmptyPicker(t, piece.PartSize, 1)
	picker.onPeerParts(peerA, piece.Set{true})
	picker.onPeerParts(peerB, piece.Set{true})
	picker.request(peerA, 53)
	picker.cancel(peerA)
	b := picker.request(peerB, 1)[0]

	if written, ok := picker.onBlockReceived(peerB, b); !ok || written != b {
		t.Fatal("first delivery should be written")
	}
	if _, ok := picker.onBlockReceived(peerA, b); ok {
		t.Fatal("second delivery should be dropped")
	}
	if got := picker.request(peerB, 1); slices.Contains(got, b) {
		t.Fatal("received block was requested again")
	}
}

func TestGonePeerReleasesItsBlocks(t *testing.T) {
	picker := buildEmptyPicker(t, piece.PartSize, 1)
	picker.onPeerParts(peerA, piece.Set{true})
	picker.onPeerParts(peerB, piece.Set{true})
	fromA := picker.request(peerA, 53)
	received := fromA[0]
	picker.onBlockReceived(peerA, received)

	picker.onPeerGone(peerA)

	fromB := picker.request(peerB, 100)
	if len(fromB) != 52 || slices.Contains(fromB, received) {
		t.Fatalf("b got %d blocks (received one included: %v), want the 52 a left undelivered",
			len(fromB), slices.Contains(fromB, received))
	}
}

func TestOnPeerPartsReplacesAvailability(t *testing.T) {
	picker := buildEmptyPicker(t, 2*piece.PartSize, 1)
	picker.onPeerParts(peerA, piece.Set{true, true})
	picker.onPeerParts(peerB, piece.Set{true, false})
	picker.onPeerParts(peerB, piece.Set{false, true})
	picker.onPeerParts(peerC, piece.Set{true, true})

	if got := partsOf(picker.request(peerC, 1)); !slices.Equal(got, []int{0}) {
		t.Fatalf("c got parts %v, want part 0, now held by fewer peers", got)
	}
	picker.onPeerParts(peerC, piece.Set{false, false})
	if got := picker.request(peerC, 1); len(got) != 0 {
		t.Fatalf("c got %v after reporting no parts", got)
	}
}

func TestFailedPartStartsOver(t *testing.T) {
	size := 2*piece.BlockSize + 10
	picker := buildEmptyPicker(t, size, 1)
	picker.onPeerParts(peerA, piece.Set{true})
	picker.onPeerParts(peerB, piece.Set{true})
	fromA := picker.request(peerA, 2)
	fromB := picker.request(peerB, 1)
	if fromB[0] != (piece.Block{Begin: 2 * piece.BlockSize, End: size}) {
		t.Fatalf("last block = %v, want it to end at the file size", fromB[0])
	}

	deliveries := map[piece.Block]uint64{fromA[0]: peerA, fromA[1]: peerA, fromB[0]: peerB}
	var isPartWritten bool
	for _, b := range append(fromA, fromB...) {
		picker.onBlockReceived(deliveries[b], b)
		isPartWritten = picker.onBlockWritten(b)
	}
	if !isPartWritten {
		t.Fatal("writing the last block should report the part written")
	}
	if got := picker.writtenSize(); got != size {
		t.Fatalf("WrittenSize = %d, want %d", got, size)
	}

	senders := picker.senders()
	slices.Sort(senders)
	if !slices.Equal(senders, []uint64{peerA, peerB}) {
		t.Fatalf("senders = %v, want [a b]", senders)
	}
	picker.onPartFailed(0)
	if got := picker.writtenSize(); got != 0 {
		t.Fatalf("WrittenSize after failure = %d, want 0", got)
	}
	if got := picker.request(peerA, 10); len(got) != 3 {
		t.Fatalf("a got %d blocks after the reset, want 3", len(got))
	}

	picker.onPartVerified(0)
	if !picker.verifiedParts().IsFull() || picker.writtenSize() != size {
		t.Fatalf("IsComplete = %v, WrittenSize = %d after verification", picker.verifiedParts().IsFull(), picker.writtenSize())
	}
	if got := picker.request(peerB, 10); len(got) != 0 {
		t.Fatalf("b got %v from a complete file", got)
	}
}

func TestEmptyFileIsComplete(t *testing.T) {
	if !buildEmptyPicker(t, 0, 1).verifiedParts().IsFull() {
		t.Fatal("an empty file has nothing to download")
	}
}

func TestResumeDataRestoresProgress(t *testing.T) {
	size := 2*piece.PartSize + 5
	picker := buildEmptyPicker(t, size, 1)
	picker.onPeerParts(peerA, piece.BuildFullSet(3))
	for _, b := range picker.request(peerA, 200) {
		picker.onBlockReceived(peerA, b)
		if b.Part() == 1 || b.Begin == 0 {
			picker.onBlockWritten(b)
		}
	}
	picker.onPartVerified(2)

	verified, written := picker.verifiedParts(), picker.writtenBlocks()
	restored := buildResumedPicker(t, size, verified, written, 2)
	if !slices.Equal(restored.verifiedParts(), verified) || !slices.Equal(restored.writtenBlocks(), written) {
		t.Fatalf("restored %v %v, want %v %v", restored.verifiedParts(), restored.writtenBlocks(), verified, written)
	}
	if got, want := restored.writtenSize(), piece.PartSize+piece.BlockSize+5; got != want {
		t.Fatalf("restored WrittenSize = %d, want %d", got, want)
	}
	if got := restored.writtenParts(); !slices.Equal(got, []int{1}) {
		t.Fatalf("WrittenParts = %v, want [1] to be hashed after restart", got)
	}
	if !slices.Equal(restored.verifiedParts(), piece.Set{false, false, true}) {
		t.Fatalf("VerifiedParts = %v", restored.verifiedParts())
	}

	restored.onPeerParts(peerA, piece.BuildFullSet(3))
	got := restored.request(peerA, 200)
	if len(got) != 52 || slices.Contains(partsOf(got), 1) || slices.Contains(got, piece.BlockOf(size, 0, 0)) {
		t.Fatalf("restored picker requested %d blocks %v, want the 52 unwritten blocks of part 0", len(got), partsOf(got))
	}
}

func TestResumeDataOutsideFileIsRejected(t *testing.T) {
	random := rand.New(rand.NewPCG(1, 0))
	invalid := []struct {
		verified piece.Set
		written  []piece.Block
	}{
		{verified: piece.Set{false, true}},
		{written: []piece.Block{{Begin: 10, End: 20}}},
		{written: []piece.Block{{Begin: 0, End: 0}}},
		{written: []piece.Block{{Begin: 0, End: piece.BlockSize + 1}}},
		{written: []piece.Block{{Begin: piece.PartSize, End: piece.PartSize + piece.BlockSize}}},
	}
	for _, resume := range invalid {
		if _, err := buildPicker(piece.BlockSize*2, resume.verified, resume.written, random); err == nil {
			t.Errorf("buildPicker accepted %v", resume)
		}
	}
}

// A slot that ends inside a block leaves its received bytes; only the missing
// tail is asked for again, from the same peer or another one.
func TestPartlyReceivedBlockKeepsItsBytes(t *testing.T) {
	picker := buildEmptyPicker(t, piece.BlockSize, 1)
	picker.onPeerParts(peerA, piece.Set{true})
	picker.onPeerParts(peerB, piece.Set{true})
	block := picker.request(peerA, 1)[0]

	head := piece.Block{Begin: block.Begin, End: block.Begin + 1000}
	if written, ok := picker.onBlockReceived(peerA, head); !ok || written != head {
		t.Fatalf("partial delivery: written %v %v, want %v", written, ok, head)
	}
	picker.cancel(peerA)
	tail := piece.Block{Begin: head.End, End: block.End}
	if got := picker.request(peerB, 1); !slices.Equal(got, []piece.Block{tail}) {
		t.Fatalf("after a's slot ended b got %v, want only the missing tail %v", got, tail)
	}

	if picker.onBlockWritten(head) {
		t.Fatal("part reported written with only its head on disk")
	}
	if got := picker.writtenSize(); got != 1000 {
		t.Fatalf("written size = %d, want the 1000 bytes of the head", got)
	}
	if got := picker.writtenBlocks(); !slices.Equal(got, []piece.Block{head}) {
		t.Fatalf("resume data = %v, want the written head %v", got, head)
	}

	late := piece.Block{Begin: block.Begin, End: block.Begin + 5000}
	if written, ok := picker.onBlockReceived(peerA, late); !ok || written != (piece.Block{Begin: head.End, End: late.End}) {
		t.Fatalf("overlapping late delivery: written %v %v, want only its new bytes", written, ok)
	}
	rest := piece.Block{Begin: late.End, End: block.End}
	if written, ok := picker.onBlockReceived(peerB, tail); !ok || written != rest {
		t.Fatalf("tail delivery: written %v %v, want %v", written, ok, rest)
	}
	picker.onBlockWritten(piece.Block{Begin: head.End, End: late.End})
	if !picker.onBlockWritten(rest) {
		t.Fatal("part not reported written once every byte is on disk")
	}
	if senders := picker.senders(); !slices.Equal(senders, []uint64{peerA, peerB}) {
		t.Fatalf("senders of the part = %v, want both peers", senders)
	}
}

func TestBlockFailedIsRequestedAlone(t *testing.T) {
	size := 3 * piece.BlockSize
	picker := buildEmptyPicker(t, size, 1)
	picker.onPeerParts(peerA, piece.BuildFullSet(1))
	picker.onPeerParts(peerB, piece.BuildFullSet(1))
	blocks := picker.request(peerA, 2)
	blocks = append(blocks, picker.request(peerB, 1)...)
	for i, b := range blocks {
		picker.onBlockReceived([]uint64{peerA, peerA, peerB}[i], b)
		picker.onBlockWritten(b)
	}

	if senders := picker.onBlockFailed(blocks[2]); !slices.Equal(senders, []uint64{peerB}) {
		t.Fatalf("senders = %v, want [b]", senders)
	}
	if got := picker.writtenSize(); got != 2*piece.BlockSize {
		t.Fatalf("WrittenSize = %d, want two blocks", got)
	}
	if got := picker.request(peerA, 3); !slices.Equal(got, blocks[2:]) {
		t.Fatalf("requested %v after the failure, want only %v", got, blocks[2:])
	}
}

// A block cut off when a slot ended keeps its written head across a
// restart, and only its tail is asked for again.
func TestResumeDataKeepsWrittenHeadOfBlock(t *testing.T) {
	size := 3 * piece.BlockSize
	picker := buildEmptyPicker(t, size, 1)
	picker.onPeerParts(peerA, piece.Set{true})
	blocks := picker.request(peerA, 3)
	head := piece.Block{Begin: blocks[0].Begin, End: blocks[0].Begin + 1000}
	fresh, _ := picker.onBlockReceived(peerA, head)
	picker.onBlockWritten(fresh)
	pending := piece.Block{Begin: blocks[1].Begin, End: blocks[1].Begin + 500}
	picker.onBlockReceived(peerA, pending)

	written := picker.writtenBlocks()
	if !slices.Equal(written, []piece.Block{head}) {
		t.Fatalf("WrittenBlocks = %v, want only the written head %v", written, head)
	}
	restored := buildResumedPicker(t, size, nil, written, 2)
	if got := restored.writtenSize(); got != 1000 {
		t.Fatalf("restored WrittenSize = %d, want 1000", got)
	}
	restored.onPeerParts(peerB, piece.Set{true})
	got := restored.request(peerB, 3)
	if !slices.Contains(got, piece.Block{Begin: head.End, End: blocks[0].End}) || !slices.Contains(got, blocks[1]) {
		t.Fatalf("restored picker requested %v, want the tail of the first block and the whole second", got)
	}
	if again := restored.writtenBlocks(); !slices.Equal(again, written) {
		t.Fatalf("WrittenBlocks after restart = %v, want %v", again, written)
	}
}
