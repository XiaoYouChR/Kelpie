package server

import (
	"encoding/binary"
	"net/netip"
	"os"
	"testing"

	"github.com/XiaoYouChR/Kelpie/internal/wire"
)

func buildMet(entries ...[]byte) []byte {
	b := binary.LittleEndian.AppendUint32([]byte{0x0E}, uint32(len(entries)))
	for _, e := range entries {
		b = append(b, e...)
	}
	return b
}

func buildMetEntry(endpoint string, tags ...wire.Tag) []byte {
	return wire.BuildTags(wire.BuildAddrPort(nil, netip.MustParseAddrPort(endpoint)), tags)
}

func TestParseMetBundledList(t *testing.T) {
	data, err := os.ReadFile("testdata/server.met")
	if err != nil {
		t.Fatal(err)
	}
	entries, err := ParseMet(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 13 {
		t.Fatalf("got %d servers, want 13", len(entries))
	}
	first := entries[0]
	if first.Name != "ed2k-rust" || first.Description != "main server" || !first.Endpoint.IsValid() {
		t.Fatalf("first entry = %+v", first)
	}
	if first.Users == 0 || first.Files == 0 || first.UDPFlags == 0 || first.SoftFiles == 0 {
		t.Fatalf("first entry lost counts or flags: %+v", first)
	}
	for _, e := range entries {
		if e.Name == "" || e.Endpoint.Port() == 0 {
			t.Fatalf("incomplete entry %+v", e)
		}
	}
}

func TestParseMetReadsSelectionTags(t *testing.T) {
	data := buildMet(buildMetEntry("1.2.3.4:4661",
		wire.Tag{Type: wire.TagString, ID: 0x01, String: "one"},
		wire.Tag{Type: wire.TagUint32, ID: 0x0E, Uint: uint64(PreferenceHigh)},
		wire.Tag{Type: wire.TagUint32, ID: 0x0D, Uint: 3},
		wire.Tag{Type: wire.TagUint32, ID: 0x0C, Uint: 80},
		wire.Tag{Type: wire.TagUint32, ID: 0x92, Uint: 0x21},
		wire.Tag{Type: wire.TagUint16, ID: 0x97, Uint: 4665},
		wire.Tag{Type: wire.TagUint32, Name: "users", Uint: 5000},
		wire.Tag{Type: wire.TagUint32, Name: "files", Uint: 9000},
		wire.Tag{Type: wire.TagString, Name: "unknown", String: "x"},
	))
	entries, err := ParseMet(data)
	if err != nil {
		t.Fatal(err)
	}
	want := Entry{
		Endpoint: netip.MustParseAddrPort("1.2.3.4:4661"), Name: "one", Preference: PreferenceHigh,
		Failures: 3, Ping: 80, UDPFlags: 0x21, TCPObfuscationPort: 4665, Users: 5000, Files: 9000,
	}
	if len(entries) != 1 || entries[0] != want {
		t.Fatalf("got %+v, want %+v", entries, want)
	}
}

func TestParseMetAcceptsOldHeaderAndDropsUnusable(t *testing.T) {
	data := buildMet(
		buildMetEntry("0.0.0.0:4661", wire.Tag{Type: wire.TagString, ID: 0x85, String: "dyn.example"}),
		buildMetEntry("1.2.3.4:0"),
		buildMetEntry("224.0.0.1:4661"),
		buildMetEntry("5.6.7.8:4242"),
	)
	data[0] = 0xE0
	entries, err := ParseMet(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Endpoint != netip.MustParseAddrPort("5.6.7.8:4242") {
		t.Fatalf("got %+v", entries)
	}
}

func TestParseMetRejectsBrokenInput(t *testing.T) {
	good := buildMet(buildMetEntry("1.2.3.4:4661"))
	for name, data := range map[string][]byte{
		"empty":     nil,
		"version":   append([]byte{0x42}, good[1:]...),
		"count":     binary.LittleEndian.AppendUint32([]byte{0x0E}, 1000),
		"truncated": good[:len(good)-2],
	} {
		if _, err := ParseMet(data); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}
