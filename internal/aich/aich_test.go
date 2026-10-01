package aich

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/XiaoYouChR/Kelpie/internal/piece"
	"github.com/XiaoYouChR/Kelpie/internal/wire"
	"github.com/XiaoYouChR/Kelpie/internal/wire/client"
)

// vectors.json comes from testdata/vectors.py, which follows aMule's
// recursion with Python's hashlib and shares no code with this package.
type vectors struct {
	Roots []struct {
		Size int64
		Root string
	}
	Recovery struct {
		Size    int64
		Part    int
		Entries []struct {
			Ident uint32
			Hash  string
		}
	}
}

func loadVectors(t *testing.T) vectors {
	t.Helper()
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func buildData(size int64) []byte {
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i % 251)
	}
	return data
}

// buildTree hashes data in uneven writes, so block borders fall inside them.
func buildTree(data []byte) *Tree {
	var h Hasher
	for rest := data; len(rest) > 0; {
		n := min(len(rest), 100_003)
		h.Write(rest[:n])
		rest = rest[n:]
	}
	return BuildTree(int64(len(data)), h.Leaves())
}

func TestRootMatchesVectors(t *testing.T) {
	for _, v := range loadVectors(t).Roots {
		if got := buildTree(buildData(v.Size)).Root().String(); got != v.Root {
			t.Errorf("size %d: root %s, want %s", v.Size, got, v.Root)
		}
	}
}

func TestRecoveryMatchesVectors(t *testing.T) {
	v := loadVectors(t).Recovery
	var want []client.AICHEntry
	for _, e := range v.Entries {
		var hash wire.AICHHash
		hex.Decode(hash[:], []byte(e.Hash))
		want = append(want, client.AICHEntry{Ident: e.Ident, Hash: hash})
	}
	got := buildTree(buildData(v.Size)).BuildRecovery(v.Part)
	if len(got) != len(want) {
		t.Fatalf("%d entries, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("entry %d: %x/%s, want %x/%s", i, got[i].Ident, got[i].Hash, want[i].Ident, want[i].Hash)
		}
	}
}

func TestMatchRecoveryReturnsPartBlocks(t *testing.T) {
	size := 3*piece.PartSize + 500_000
	data := buildData(size)
	tree := buildTree(data)
	for part := range piece.PartCount(size) {
		got, ok := MatchRecovery(tree.Root(), size, part, tree.BuildRecovery(part))
		if !ok {
			t.Fatalf("part %d: recovery rejected", part)
		}
		begin := int64(part) * piece.PartSize
		var h Hasher
		h.Write(data[begin:min(begin+piece.PartSize, size)])
		want := h.Leaves()
		if len(got) != piece.BlockCount(size, part) || len(got) != len(want) {
			t.Fatalf("part %d: %d blocks, want %d", part, len(got), len(want))
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("part %d block %d differs", part, i)
			}
		}
	}
}

func TestMatchRecoveryRejectsTampering(t *testing.T) {
	size := 3*piece.PartSize + 500_000
	tree := buildTree(buildData(size))
	entries := tree.BuildRecovery(1)
	tamper := func(change func([]client.AICHEntry) []client.AICHEntry) []client.AICHEntry {
		return change(append([]client.AICHEntry(nil), entries...))
	}
	cases := map[string][]client.AICHEntry{
		"block hash":    tamper(func(e []client.AICHEntry) []client.AICHEntry { e[10].Hash[0] ^= 1; return e }),
		"sibling hash":  tamper(func(e []client.AICHEntry) []client.AICHEntry { e[0].Hash[0] ^= 1; return e }),
		"missing block": tamper(func(e []client.AICHEntry) []client.AICHEntry { return e[:len(e)-1] }),
		"duplicate":     tamper(func(e []client.AICHEntry) []client.AICHEntry { e[len(e)-1] = e[len(e)-2]; return e }),
		"other part":    tree.BuildRecovery(2),
	}
	for name, e := range cases {
		if _, ok := MatchRecovery(tree.Root(), size, 1, e); ok {
			t.Errorf("%s: accepted", name)
		}
	}
	other := tree.Root()
	other[0] ^= 1
	if _, ok := MatchRecovery(other, size, 1, entries); ok {
		t.Error("another root: accepted")
	}
}
