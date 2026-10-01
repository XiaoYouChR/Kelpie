package store

import (
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/wire"
)

func mustHash(t *testing.T, text string) wire.Hash {
	t.Helper()
	hash, err := wire.ParseHash(text)
	if err != nil {
		t.Fatal(err)
	}
	return hash
}

func copyFixture(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	folder := t.TempDir()
	if err := os.WriteFile(filepath.Join(folder, fileName), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return folder
}

func TestLoadMissingIsEmpty(t *testing.T) {
	state, err := Load(filepath.Join(t.TempDir(), "absent"))
	if err != nil {
		t.Fatal(err)
	}
	if state.Credits == nil || state.Transfers == nil || len(state.Transfers) != 0 {
		t.Fatalf("want empty state with maps, got %+v", state)
	}
}

func TestLoadCorruptFails(t *testing.T) {
	for _, content := range []string{`{"version": 4, "transfers": [`, `{"version": 99}`, `{"version": 4, "userHash": "XYZ"}`} {
		folder := t.TempDir()
		os.WriteFile(filepath.Join(folder, fileName), []byte(content), 0o644)
		if _, err := Load(folder); err == nil {
			t.Errorf("%s: loaded", content)
		}
	}
}

func TestLoadGoed2k(t *testing.T) {
	state, err := Load(copyFixture(t, "goed2k-v3.json"))
	if err != nil {
		t.Fatal(err)
	}
	want := State{
		Identity: Identity{UserHash: mustHash(t, "FD3887E9230E53F744E5CA8FAF1A6F31")},
		Kad: Kad{
			ID:           mustHash(t, "1E5ABC409D3E49D315D76222566E99E4"),
			IsFirewalled: true,
			Nodes: []KadNode{
				{ID: mustHash(t, "54F4C64866EE9E505DB15D4B4785A0BA"), Addr: netip.MustParseAddrPort("195.32.118.142:4672"), Version: 8},
				{ID: mustHash(t, "00112233445566778899AABBCCDDEEFF"), Addr: netip.MustParseAddrPort("82.64.1.2:5672"), Version: 9},
			},
		},
		Credits: map[wire.Hash]Credit{
			mustHash(t, "1550D611EA0E55210F452221902F6F73"): {Downloaded: 1822908},
			mustHash(t, "8F6E0C2A1B3D4E5F60718293A4B5C6D7"): {Uploaded: 734003200, Downloaded: 12},
		},
		Transfers: map[wire.Hash]Transfer{
			mustHash(t, "2D2A61A79C0E0B4B4B7E6F7A4B9F1C55"): {
				Size: 25000000,
				File: "/Users/alice/Downloads/ubuntu 24.04 中文.iso",
				PartHashes: []wire.Hash{
					mustHash(t, "0A1B2C3D4E5F60718293A4B5C6D7E8F9"),
					mustHash(t, "1F2E3D4C5B6A79880716253443526170"),
					mustHash(t, "AABBCCDDEEFF00112233445566778899"),
				},
				VerifiedParts: []bool{true, false, false},
				WrittenBlocks: []Block{{Part: 1, Index: 0}, {Part: 1, Index: 3}, {Part: 2, Index: 52}},
				Created:       time.UnixMilli(1787328879185).UTC(),
			},
			mustHash(t, "31D6CFE0D16AE931B73C59D7E0C089C0"): {
				Size:    1048576,
				File:    "/Users/alice/Downloads/small.bin",
				Created: time.UnixMilli(1787400000000).UTC(),
			},
		},
	}
	if !reflect.DeepEqual(state, want) {
		t.Fatalf("got  %+v\nwant %+v", state, want)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	folder := filepath.Join(t.TempDir(), "kelpie")
	state := buildState()
	state.Identity = Identity{UserHash: mustHash(t, "FD3887E9230E53F744E5CA8FAF1A6F31"), PrivateKey: []byte{0x30, 0x82, 0x01}}
	state.Kad = Kad{
		ID:           mustHash(t, "1E5ABC409D3E49D315D76222566E99E4"),
		IsFirewalled: true,
		Nodes: []KadNode{
			{ID: mustHash(t, "54F4C64866EE9E505DB15D4B4785A0BA"), Addr: netip.MustParseAddrPort("195.32.118.142:4672"), Version: 8},
			{ID: mustHash(t, "00112233445566778899AABBCCDDEEFF"), Addr: netip.MustParseAddrPort("[2001:db8::1]:4672"), Version: 9},
		},
	}
	lastSeen := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	state.Credits[mustHash(t, "1550D611EA0E55210F452221902F6F73")] = Credit{Uploaded: 1, Downloaded: 2, PublicKey: []byte{4, 5}, LastSeen: lastSeen}
	state.Transfers[mustHash(t, "31D6CFE0D16AE931B73C59D7E0C089C0")] = Transfer{
		Size:          25000000,
		File:          "/tmp/a.iso",
		PartHashes:    []wire.Hash{mustHash(t, "0A1B2C3D4E5F60718293A4B5C6D7E8F9"), mustHash(t, "1F2E3D4C5B6A79880716253443526170"), mustHash(t, "AABBCCDDEEFF00112233445566778899")},
		VerifiedParts: []bool{true, false, true},
		WrittenBlocks: []Block{{Part: 1, Index: 7}},
		Uploaded:      123456,
		Created:       lastSeen,
	}

	if err := Save(folder, state); err != nil {
		t.Fatal(err)
	}
	got, err := Load(folder)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, state) {
		t.Fatalf("got  %+v\nwant %+v", got, state)
	}

	raw, _ := os.ReadFile(filepath.Join(folder, fileName))
	if !strings.Contains(string(raw), `"version": 4`) || !strings.Contains(string(raw), `"31D6CFE0D16AE931B73C59D7E0C089C0"`) {
		t.Fatalf("unexpected file:\n%s", raw)
	}
	entries, _ := os.ReadDir(folder)
	if len(entries) != 1 {
		t.Fatalf("temp file left behind: %v", entries)
	}
}

func TestSaveConvertsGoed2k(t *testing.T) {
	folder := copyFixture(t, "goed2k-v3.json")
	old, err := Load(folder)
	if err != nil {
		t.Fatal(err)
	}
	if err := Save(folder, old); err != nil {
		t.Fatal(err)
	}
	converted, err := Load(folder)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(converted, old) {
		t.Fatalf("got  %+v\nwant %+v", converted, old)
	}
}

func TestSaveEmptyState(t *testing.T) {
	folder := t.TempDir()
	if err := Save(folder, buildState()); err != nil {
		t.Fatal(err)
	}
	state, err := Load(folder)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(state, buildState()) {
		t.Fatalf("got %+v", state)
	}
}
