package wire

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"net/netip"
	"reflect"
	"runtime"
	"testing"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestFrameGolden(t *testing.T) {
	got := BuildFrame(nil, ProtocolEDonkey, 0x5C, []byte{0x70, 0x11, 0x01, 0x00})
	want := unhex(t, "e305000000"+"5c"+"70110100")
	if !bytes.Equal(got, want) {
		t.Fatalf("frame = %x, want %x", got, want)
	}
	f, n, err := ParseFrame(append(got, 0xE3))
	if err != nil || n != len(want) {
		t.Fatalf("ParseFrame n=%d err=%v", n, err)
	}
	if f.Protocol != ProtocolEDonkey || f.Opcode != 0x5C || !bytes.Equal(f.Body, want[6:]) {
		t.Fatalf("frame = %+v", f)
	}
}

func TestParseFrameWaitsForWholeFrame(t *testing.T) {
	raw := BuildFrame(nil, ProtocolEMule, 0x60, make([]byte, 12))
	for cut := range len(raw) {
		if _, n, err := ParseFrame(raw[:cut]); n != 0 || err != nil {
			t.Fatalf("cut %d: n=%d err=%v", cut, n, err)
		}
	}
}

func TestParseFrameRejects(t *testing.T) {
	cases := map[string][]byte{
		"unknown protocol": {0x00, 1, 0, 0, 0, 1},
		"zero length":      {0xE3, 0, 0, 0, 0, 1},
		"too large":        {0xE3, 0xFF, 0xFF, 0xFF, 0x7F, 1},
	}
	for name, raw := range cases {
		if _, _, err := ParseFrame(raw); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

func TestPackedFrameInflatesToEMule(t *testing.T) {
	body := bytes.Repeat([]byte("kelpie"), 100)
	raw := BuildPackedFrame(nil, 0x84, body)
	if raw[0] != ProtocolPacked {
		t.Fatalf("protocol = %#x", raw[0])
	}
	f, err := ParseFrameFrom(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if f.Protocol != ProtocolEMule || f.Opcode != 0x84 || !bytes.Equal(f.Body, body) {
		t.Fatalf("frame = %x %x %d bytes", f.Protocol, f.Opcode, len(f.Body))
	}
}

func TestPackedKadDatagram(t *testing.T) {
	body := []byte{1, 2, 3, 4}
	raw := BuildPackedDatagram(nil, ProtocolKad, 0x3B, body)
	if raw[0] != ProtocolKadPacked {
		t.Fatalf("protocol = %#x", raw[0])
	}
	f, err := ParseDatagram(raw)
	if err != nil {
		t.Fatal(err)
	}
	if f.Protocol != ProtocolKad || f.Opcode != 0x3B || !bytes.Equal(f.Body, body) {
		t.Fatalf("frame = %+v", f)
	}
}

func TestPackedFrameRejectsGarbage(t *testing.T) {
	raw := BuildFrame(nil, ProtocolPacked, 0x84, []byte{1, 2, 3})
	if _, _, err := ParseFrame(raw); err == nil {
		t.Fatal("want inflate error")
	}
}

func TestReaderIsSticky(t *testing.T) {
	r := Reader{Rest: []byte{1, 2, 3}}
	if r.Uint32() != 0 || !errors.Is(r.Err(), ErrShort) {
		t.Fatalf("err = %v", r.Err())
	}
	if r.Uint8() != 0 {
		t.Fatal("read after failure returned data")
	}
}

func TestAddrGolden(t *testing.T) {
	ap := netip.MustParseAddrPort("1.2.3.4:4662")
	got := BuildAddrPort(nil, ap)
	if !bytes.Equal(got, unhex(t, "010203043612")) {
		t.Fatalf("addr = %x", got)
	}
	r := Reader{Rest: got}
	if r.AddrPort() != ap {
		t.Fatal("round trip")
	}
	if id := ToClientID(ap.Addr()); id != 0x04030201 || IsLowID(id) {
		t.Fatalf("id = %#x", id)
	}
	if ToAddr(0x04030201) != ap.Addr() {
		t.Fatal("ToAddr")
	}
	if !IsLowID(16777215) || IsLowID(16777216) {
		t.Fatal("LowID boundary")
	}
	zero := Reader{Rest: make([]byte, 6)}
	if zero.AddrPort().IsValid() {
		t.Fatal("zero address should decode as absent")
	}
}

func TestTagRoundTrip(t *testing.T) {
	tags := []Tag{
		{Type: TagHash, ID: 0xAE, Hash: Hash{0x2a, 0x01}},
		{Type: TagString, ID: 0x01, String: "Kelpie"},
		{Type: TagString, Name: "ip6", String: "20010db8000000000000000000000001"},
		{Type: TagUint32, ID: 0x11, Uint: 0x3C},
		{Type: TagFloat32, ID: 0x10, Float: 1.5},
		{Type: TagBool, ID: 0x12, Uint: 1},
		{Type: TagBoolArray, ID: 0x13, Uint: 9, Blob: []byte{0xFF, 0x01}},
		{Type: TagBlob, ID: 0x14, Blob: []byte{9, 8, 7}},
		{Type: TagUint16, ID: 0x15, Uint: 4662},
		{Type: TagUint8, ID: 0x16, Uint: 7},
		{Type: TagBsob, ID: 0x17, Blob: []byte{1}},
		{Type: TagUint64, ID: 0x02, Uint: 1 << 40},
	}
	raw := BuildTags(nil, tags)
	r := Reader{Rest: raw}
	got := r.Tags()
	if r.Err() != nil || r.Len() != 0 {
		t.Fatalf("err=%v rest=%d", r.Err(), r.Len())
	}
	if !reflect.DeepEqual(got, tags) {
		t.Fatalf("got  %+v\nwant %+v", got, tags)
	}
}

func TestCompactTagNarrows(t *testing.T) {
	cases := []struct {
		tag  Tag
		want string
	}{
		{Tag{Type: TagUint32, ID: 0xBB, Uint: 4661}, "88bb3512"},
		{Tag{Type: TagUint32, ID: 0xBA, Uint: 0x04030201}, "83ba01020304"},
		{Tag{Type: TagUint64, ID: 0x02, Uint: 4}, "890204"},
		{Tag{Type: TagString, ID: 0x01, String: "abc"}, "930161626" + "3"},
		{Tag{Type: TagUint8, Name: "ab", Uint: 1}, "0902006162" + "01"},
	}
	for _, c := range cases {
		got := BuildCompactTag(nil, c.tag)
		if hex.EncodeToString(got) != c.want {
			t.Errorf("%+v = %x, want %s", c.tag, got, c.want)
		}
		r := Reader{Rest: got}
		back := r.Tag()
		if r.Err() != nil || back.Uint != c.tag.Uint || back.String != c.tag.String || back.ID != c.tag.ID || back.Name != c.tag.Name {
			t.Errorf("%+v decoded as %+v (%v)", c.tag, back, r.Err())
		}
	}
}

func TestTagGolden(t *testing.T) {
	// emule-qt ipv6-spec §3.1: CT_MOD_MISCOPTIONS and CT_MOD_IP_V6 in hello.
	misc := BuildTag(nil, Tag{Type: TagUint32, ID: 0xAA, Uint: 5})
	if !bytes.Equal(misc, unhex(t, "030100aa05000000")) {
		t.Fatalf("misc = %x", misc)
	}
	addr := netip.MustParseAddr("2a01:4f8::1").As16()
	ip6 := BuildTag(nil, Tag{Type: TagHash, ID: 0xAE, Hash: Hash(addr)})
	if !bytes.Equal(ip6, unhex(t, "010100ae2a0104f8000000000000000000000001")) {
		t.Fatalf("ip6 = %x", ip6)
	}
}

func TestTagsRejectImpossibleCount(t *testing.T) {
	r := Reader{Rest: []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x03}}
	r.Tags()
	if r.Err() == nil {
		t.Fatal("want error")
	}
}

func TestTagRejectsUnknownType(t *testing.T) {
	r := Reader{Rest: []byte{0x8F, 0x01, 0x00}}
	r.Tag()
	if r.Err() == nil {
		t.Fatal("want error")
	}
}

func TestBitfieldGolden(t *testing.T) {
	f := ToBitfield([]bool{true, false, true, false, false, false, false, false, false, true})
	raw := BuildBitfield(nil, f)
	if !bytes.Equal(raw, unhex(t, "0a00"+"05"+"02")) {
		t.Fatalf("bitfield = %x", raw)
	}
	r := Reader{Rest: raw}
	back := r.Bitfield()
	if r.Err() != nil || !reflect.DeepEqual(back.Bools(), f.Bools()) || back.Count() != 3 {
		t.Fatalf("back = %v", back.Bools())
	}
}

func TestBitfieldDropsTrailingBits(t *testing.T) {
	r := Reader{Rest: []byte{0x03, 0x00, 0xFF}}
	f := r.Bitfield()
	if f.Len() != 3 || f.Count() != 3 || f.Has(3) {
		t.Fatalf("bitfield = %v", f.Bools())
	}
	if raw := BuildBitfield(nil, f); !bytes.Equal(raw, []byte{0x03, 0x00, 0x07}) {
		t.Fatalf("re-encoded = %x", raw)
	}
}

func TestBitfieldSetClear(t *testing.T) {
	f := ToBitfield(make([]bool, 12))
	f.Set(11)
	f.Set(0)
	f.Clear(0)
	if !f.Has(11) || f.Has(0) || f.Has(12) || f.Has(-1) || f.Count() != 1 {
		t.Fatalf("bitfield = %v", f.Bools())
	}
}

// A peer that announces a 16 MiB frame and sends nothing more must not cost
// 16 MiB per connection.
func TestParseFrameFromAllocatesWhatArrives(t *testing.T) {
	head := []byte{ProtocolEMule, 0, 0, 0, 1, 0x46}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := ParseFrameFrom(bytes.NewReader(append(head, make([]byte, 100)...)))
	runtime.ReadMemStats(&after)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("err = %v, want unexpected EOF", err)
	}
	if n := after.TotalAlloc - before.TotalAlloc; n > 1<<20 {
		t.Fatalf("allocated %d bytes for a 100-byte body", n)
	}
}
