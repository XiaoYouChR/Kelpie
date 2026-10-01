package piece_test

import (
	"math/rand/v2"
	"slices"
	"testing"

	"github.com/XiaoYouChR/Kelpie/internal/piece"
)

func buildPicker(t *testing.T, size int64, resume piece.ResumeData, seed uint64) *piece.Picker[string] {
	t.Helper()
	picker, err := piece.BuildPicker[string](size, resume, rand.New(rand.NewPCG(seed, 0)))
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
	picker := buildPicker(t, 3*piece.PartSize, piece.ResumeData{}, 1)
	picker.OnPeerParts("a", piece.Set{true, true, true})
	picker.OnPeerParts("b", piece.Set{false, true, true})
	picker.OnPeerParts("c", piece.Set{false, false, true})

	if got := partsOf(picker.Request("a", 1)); !slices.Equal(got, []int{0}) {
		t.Fatalf("a got parts %v, want the rarest part 0", got)
	}
	if got := partsOf(picker.Request("b", 1)); !slices.Equal(got, []int{1}) {
		t.Fatalf("b got parts %v, want its rarest part 1", got)
	}
}

func TestRequestPrefersPartInProgress(t *testing.T) {
	picker := buildPicker(t, 2*piece.PartSize, piece.ResumeData{}, 1)
	picker.OnPeerParts("a", piece.Set{true, true})
	picker.OnPeerParts("b", piece.Set{true, false})
	picker.Request("b", 1)

	got := picker.Request("a", 1)
	if want := (piece.Block{Begin: piece.BlockSize, End: 2 * piece.BlockSize}); !slices.Equal(got, []piece.Block{want}) {
		t.Fatalf("a got %v, want the next block of part 0 in progress, %v", got, want)
	}
}

func TestRequestBreaksTiesWithInjectedRandom(t *testing.T) {
	firstParts := map[int]bool{}
	for seed := range uint64(20) {
		picks := make([][]piece.Block, 2)
		for i := range picks {
			picker := buildPicker(t, 4*piece.PartSize, piece.ResumeData{}, seed)
			picker.OnPeerParts("a", piece.BuildFullSet(4))
			picks[i] = picker.Request("a", 1)
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

func TestRequestDuplicatesOnlyInEndgame(t *testing.T) {
	picker := buildPicker(t, 2*piece.PartSize, piece.ResumeData{}, 1)
	picker.OnPeerParts("a", piece.Set{true, false})
	picker.OnPeerParts("b", piece.Set{false, true})

	if got := picker.Request("a", 100); len(got) != 53 {
		t.Fatalf("a got %d blocks, want all 53 of part 0", len(got))
	}
	if got := picker.Request("a", 10); len(got) != 0 {
		t.Fatalf("a got %v while part 1 is still unrequested", got)
	}
}

func TestEndgameAllowsTwoRequestersPerBlock(t *testing.T) {
	size := piece.PartSize
	picker := buildPicker(t, size, piece.ResumeData{}, 1)
	for _, peer := range []string{"a", "b", "c"} {
		picker.OnPeerParts(peer, piece.Set{true})
	}
	fromA := picker.Request("a", 50)
	fromB := picker.Request("b", 10)

	for _, b := range fromB[:3] {
		if slices.Contains(fromA, b) {
			t.Fatalf("b got %v already requested from a while unrequested blocks remained", b)
		}
	}
	for _, b := range fromB[3:] {
		if !slices.Contains(fromA, b) {
			t.Fatalf("b got endgame block %v that a was not asked for", b)
		}
	}
	if got := picker.Request("c", 100); len(got) != 53-7 {
		t.Fatalf("c got %d endgame blocks, want %d (blocks with fewer than two requesters)", len(got), 53-7)
	}
	if got := picker.Request("a", 100); len(got) != 0 {
		t.Fatalf("a got %v, but every block already has two requesters or is a's", got)
	}
}

func TestReceivedBlockIsWrittenOnce(t *testing.T) {
	picker := buildPicker(t, piece.PartSize, piece.ResumeData{}, 1)
	picker.OnPeerParts("a", piece.Set{true})
	picker.OnPeerParts("b", piece.Set{true})
	picker.Request("a", 53)
	b := picker.Request("b", 1)[0]

	if written, ok := picker.OnBlockReceived("b", b); !ok || written != b {
		t.Fatal("first delivery should be written")
	}
	if _, ok := picker.OnBlockReceived("a", b); ok {
		t.Fatal("second delivery should be dropped")
	}
	if got := picker.Request("b", 1); slices.Contains(got, b) {
		t.Fatal("received block was requested again")
	}
}

func TestGonePeerReleasesItsBlocks(t *testing.T) {
	picker := buildPicker(t, piece.PartSize, piece.ResumeData{}, 1)
	picker.OnPeerParts("a", piece.Set{true})
	picker.OnPeerParts("b", piece.Set{true})
	fromA := picker.Request("a", 53)
	received := fromA[0]
	picker.OnBlockReceived("a", received)

	picker.OnPeerGone("a")

	fromB := picker.Request("b", 100)
	if len(fromB) != 52 || slices.Contains(fromB, received) {
		t.Fatalf("b got %d blocks (received one included: %v), want the 52 a left undelivered",
			len(fromB), slices.Contains(fromB, received))
	}
}

func TestOnPeerPartsReplacesAvailability(t *testing.T) {
	picker := buildPicker(t, 2*piece.PartSize, piece.ResumeData{}, 1)
	picker.OnPeerParts("a", piece.Set{true, true})
	picker.OnPeerParts("b", piece.Set{true, false})
	picker.OnPeerParts("b", piece.Set{false, true})
	picker.OnPeerParts("c", piece.Set{true, true})

	if got := partsOf(picker.Request("c", 1)); !slices.Equal(got, []int{0}) {
		t.Fatalf("c got parts %v, want part 0, now held by fewer peers", got)
	}
	picker.OnPeerParts("c", piece.Set{false, false})
	if got := picker.Request("c", 1); len(got) != 0 {
		t.Fatalf("c got %v after reporting no parts", got)
	}
}

func TestFailedPartReportsSendersAndStartsOver(t *testing.T) {
	size := 2*piece.BlockSize + 10
	picker := buildPicker(t, size, piece.ResumeData{}, 1)
	picker.OnPeerParts("a", piece.Set{true})
	picker.OnPeerParts("b", piece.Set{true})
	fromA := picker.Request("a", 2)
	fromB := picker.Request("b", 1)
	if fromB[0] != (piece.Block{Begin: 2 * piece.BlockSize, End: size}) {
		t.Fatalf("last block = %v, want it to end at the file size", fromB[0])
	}

	deliveries := map[piece.Block]string{fromA[0]: "a", fromA[1]: "a", fromB[0]: "b"}
	var isPartWritten bool
	for _, b := range append(fromA, fromB...) {
		picker.OnBlockReceived(deliveries[b], b)
		isPartWritten = picker.OnBlockWritten(b)
	}
	if !isPartWritten {
		t.Fatal("writing the last block should report the part written")
	}
	if got := picker.WrittenSize(); got != size {
		t.Fatalf("WrittenSize = %d, want %d", got, size)
	}

	senders := picker.OnPartFailed(0)
	slices.Sort(senders)
	if !slices.Equal(senders, []string{"a", "b"}) {
		t.Fatalf("senders = %v, want [a b]", senders)
	}
	if got := picker.WrittenSize(); got != 0 {
		t.Fatalf("WrittenSize after failure = %d, want 0", got)
	}
	if got := picker.Request("a", 10); len(got) != 3 {
		t.Fatalf("a got %d blocks after the reset, want 3", len(got))
	}

	picker.OnPartVerified(0)
	if !picker.IsComplete() || picker.WrittenSize() != size {
		t.Fatalf("IsComplete = %v, WrittenSize = %d after verification", picker.IsComplete(), picker.WrittenSize())
	}
	if got := picker.Request("b", 10); len(got) != 0 {
		t.Fatalf("b got %v from a complete file", got)
	}
}

func TestEmptyFileIsComplete(t *testing.T) {
	if !buildPicker(t, 0, piece.ResumeData{}, 1).IsComplete() {
		t.Fatal("an empty file has nothing to download")
	}
}

func TestResumeDataRestoresProgress(t *testing.T) {
	size := 2*piece.PartSize + 5
	picker := buildPicker(t, size, piece.ResumeData{}, 1)
	picker.OnPeerParts("a", piece.BuildFullSet(3))
	for _, b := range picker.Request("a", 200) {
		picker.OnBlockReceived("a", b)
		if b.Part() == 1 || b.Begin == 0 {
			picker.OnBlockWritten(b)
		}
	}
	picker.OnPartVerified(2)

	resume := picker.ToResumeData()
	restored := buildPicker(t, size, resume, 2)
	if got := restored.ToResumeData(); !slices.Equal(got.VerifiedParts, resume.VerifiedParts) || !slices.Equal(got.WrittenBlocks, resume.WrittenBlocks) {
		t.Fatalf("restored resume data %v, want %v", got, resume)
	}
	if got, want := restored.WrittenSize(), piece.PartSize+piece.BlockSize+5; got != want {
		t.Fatalf("restored WrittenSize = %d, want %d", got, want)
	}
	if got := restored.WrittenParts(); !slices.Equal(got, []int{1}) {
		t.Fatalf("WrittenParts = %v, want [1] to be hashed after restart", got)
	}
	if !slices.Equal(restored.VerifiedParts(), piece.Set{false, false, true}) {
		t.Fatalf("VerifiedParts = %v", restored.VerifiedParts())
	}

	restored.OnPeerParts("a", piece.BuildFullSet(3))
	got := restored.Request("a", 200)
	if len(got) != 52 || slices.Contains(partsOf(got), 1) || slices.Contains(got, picker.BlockAt(0)) {
		t.Fatalf("restored picker requested %d blocks %v, want the 52 unwritten blocks of part 0", len(got), partsOf(got))
	}
}

func TestResumeDataOutsideFileIsRejected(t *testing.T) {
	random := rand.New(rand.NewPCG(1, 0))
	invalid := []piece.ResumeData{
		{VerifiedParts: []int{1}},
		{WrittenBlocks: []piece.Block{{Begin: 10, End: 20}}},
		{WrittenBlocks: []piece.Block{{Begin: 0, End: 0}}},
		{WrittenBlocks: []piece.Block{{Begin: 0, End: piece.BlockSize + 1}}},
		{WrittenBlocks: []piece.Block{{Begin: piece.PartSize, End: piece.PartSize + piece.BlockSize}}},
	}
	for _, resume := range invalid {
		if _, err := piece.BuildPicker[string](piece.BlockSize*2, resume, random); err == nil {
			t.Errorf("BuildPicker accepted %v", resume)
		}
	}
}

// A slot that ends inside a block leaves its received bytes; only the missing
// tail is asked for again, from the same peer or another one.
func TestPartlyReceivedBlockKeepsItsBytes(t *testing.T) {
	picker := buildPicker(t, piece.BlockSize, piece.ResumeData{}, 1)
	picker.OnPeerParts("a", piece.Set{true})
	picker.OnPeerParts("b", piece.Set{true})
	block := picker.Request("a", 1)[0]

	head := piece.Block{Begin: block.Begin, End: block.Begin + 1000}
	if written, ok := picker.OnBlockReceived("a", head); !ok || written != head {
		t.Fatalf("partial delivery: written %v %v, want %v", written, ok, head)
	}
	picker.Cancel("a")
	tail := piece.Block{Begin: head.End, End: block.End}
	if got := picker.Request("b", 1); !slices.Equal(got, []piece.Block{tail}) {
		t.Fatalf("after a's slot ended b got %v, want only the missing tail %v", got, tail)
	}

	if picker.OnBlockWritten(head) {
		t.Fatal("part reported written with only its head on disk")
	}
	if got := picker.WrittenSize(); got != 1000 {
		t.Fatalf("written size = %d, want the 1000 bytes of the head", got)
	}
	if got := picker.ToResumeData().WrittenBlocks; !slices.Equal(got, []piece.Block{head}) {
		t.Fatalf("resume data = %v, want the written head %v", got, head)
	}

	late := piece.Block{Begin: block.Begin, End: block.Begin + 5000}
	if written, ok := picker.OnBlockReceived("a", late); !ok || written != (piece.Block{Begin: head.End, End: late.End}) {
		t.Fatalf("overlapping late delivery: written %v %v, want only its new bytes", written, ok)
	}
	rest := piece.Block{Begin: late.End, End: block.End}
	if written, ok := picker.OnBlockReceived("b", tail); !ok || written != rest {
		t.Fatalf("tail delivery: written %v %v, want %v", written, ok, rest)
	}
	picker.OnBlockWritten(piece.Block{Begin: head.End, End: late.End})
	if !picker.OnBlockWritten(rest) {
		t.Fatal("part not reported written once every byte is on disk")
	}
	if senders := picker.OnPartFailed(0); !slices.Equal(senders, []string{"a", "b"}) {
		t.Fatalf("senders of a failed part = %v, want both peers", senders)
	}
}

// A block cut off when a slot ended keeps its written head across a
// restart, and only its tail is asked for again.
func TestResumeDataKeepsWrittenHeadOfBlock(t *testing.T) {
	size := 3 * piece.BlockSize
	picker := buildPicker(t, size, piece.ResumeData{}, 1)
	picker.OnPeerParts("a", piece.Set{true})
	blocks := picker.Request("a", 3)
	head := piece.Block{Begin: blocks[0].Begin, End: blocks[0].Begin + 1000}
	fresh, _ := picker.OnBlockReceived("a", head)
	picker.OnBlockWritten(fresh)
	pending := piece.Block{Begin: blocks[1].Begin, End: blocks[1].Begin + 500}
	picker.OnBlockReceived("a", pending)

	resume := picker.ToResumeData()
	if !slices.Equal(resume.WrittenBlocks, []piece.Block{head}) {
		t.Fatalf("WrittenBlocks = %v, want only the written head %v", resume.WrittenBlocks, head)
	}
	restored := buildPicker(t, size, resume, 2)
	if got := restored.WrittenSize(); got != 1000 {
		t.Fatalf("restored WrittenSize = %d, want 1000", got)
	}
	restored.OnPeerParts("b", piece.Set{true})
	got := restored.Request("b", 3)
	if !slices.Contains(got, piece.Block{Begin: head.End, End: blocks[0].End}) || !slices.Contains(got, blocks[1]) {
		t.Fatalf("restored picker requested %v, want the tail of the first block and the whole second", got)
	}
	if again := restored.ToResumeData(); !slices.Equal(again.WrittenBlocks, resume.WrittenBlocks) {
		t.Fatalf("resume data after restart = %v, want %v", again.WrittenBlocks, resume.WrittenBlocks)
	}
}
