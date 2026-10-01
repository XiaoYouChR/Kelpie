package store

import (
	"os"
	"path/filepath"
	"testing"
)

func FuzzLoad(f *testing.F) {
	goed2k, err := os.ReadFile("testdata/goed2k-v3.json")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(goed2k)
	folder := f.TempDir()
	if err := Save(folder, buildSampleState(f)); err != nil {
		f.Fatal(err)
	}
	saved, err := os.ReadFile(filepath.Join(folder, fileName))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(saved)
	f.Fuzz(func(t *testing.T, raw []byte) {
		folder := t.TempDir()
		if err := os.WriteFile(filepath.Join(folder, fileName), raw, 0o644); err != nil {
			t.Fatal(err)
		}
		state, err := Load(folder)
		if err != nil {
			return
		}
		if err := Save(folder, state); err != nil {
			t.Fatalf("save what was loaded: %v", err)
		}
		if _, err := Load(folder); err != nil {
			t.Fatalf("load what was saved: %v", err)
		}
	})
}
