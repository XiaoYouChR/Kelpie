package transfer_test

import (
	"math/rand/v2"
	"os"
	"path/filepath"
	"testing"

	"github.com/XiaoYouChR/Kelpie/internal/link"
	"github.com/XiaoYouChR/Kelpie/internal/piece"
	"github.com/XiaoYouChR/Kelpie/internal/store"
	"github.com/XiaoYouChR/Kelpie/internal/transfer"
	"github.com/XiaoYouChR/Kelpie/internal/wire"
)

// FuzzResume resumes Transfers from a corrupt state.json. The file comes
// from a link, so its size is one link.Parse accepts.
func FuzzResume(f *testing.F) {
	file := buildFile(buildData(2*piece.PartSize + 5000))
	state := store.State{Transfers: map[wire.Hash]store.Transfer{}}
	state.Transfers[file.Hash] = store.Transfer{
		Size:          file.Size,
		File:          path,
		PartHashes:    file.PartHashes,
		VerifiedParts: []bool{true, false, false},
		WrittenBlocks: []piece.Block{
			piece.BlockOf(file.Size, 1, 7),
			piece.BlockOf(file.Size, 2, 0),
			{Begin: piece.BlockOf(file.Size, 1, 8).Begin, End: piece.BlockOf(file.Size, 1, 8).Begin + 1000},
		},
		Uploaded: 5,
		Created:  start,
	}
	seed := transfer.State(state.Transfers[file.Hash])
	resumed := transfer.Build(transfer.Options{File: file, Path: path, State: &seed, Random: rand.New(rand.NewPCG(1, 2))}, start)
	if got, want := resumed.Progress(start).Received, piece.PartSize+piece.BlockSize+1000+5000; got != want {
		f.Fatalf("seed resumes %d bytes, want %d", got, want)
	}
	folder := f.TempDir()
	if err := store.Save(folder, state); err != nil {
		f.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(folder, "state.json"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Fuzz(func(t *testing.T, raw []byte) {
		folder := t.TempDir()
		if err := os.WriteFile(filepath.Join(folder, "state.json"), raw, 0o644); err != nil {
			t.Fatal(err)
		}
		state, err := store.Load(folder)
		if err != nil {
			return
		}
		for hash, saved := range state.Transfers {
			linked := link.File{Name: "file.bin", Size: file.Size, Hash: hash}
			if saved.Size > 0 && saved.Size <= 256<<30 {
				linked.Size = saved.Size
			}
			resume := transfer.State(saved)
			tr := transfer.Build(transfer.Options{File: linked, Path: saved.File, State: &resume, Random: rand.New(rand.NewPCG(1, 2))}, start)
			tr.Progress(start)
			tr.ToState()
		}
	})
}
