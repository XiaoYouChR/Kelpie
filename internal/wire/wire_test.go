package wire

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net/netip"
	"reflect"
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
	if r.Err() != nil || !reflect.DeepEqual(back.bools(), f.bools()) || back.Count() != 3 {
		t.Fatalf("back = %v", back.bools())
	}
}

func TestBitfieldDropsTrailingBits(t *testing.T) {
	r := Reader{Rest: []byte{0x03, 0x00, 0xFF}}
	f := r.Bitfield()
	if f.Len() != 3 || f.Count() != 3 || f.Has(3) {
		t.Fatalf("bitfield = %v", f.bools())
	}
	if raw := BuildBitfield(nil, f); !bytes.Equal(raw, []byte{0x03, 0x00, 0x07}) {
		t.Fatalf("re-encoded = %x", raw)
	}
}

func TestBitfieldSet(t *testing.T) {
	f := ToBitfield(make([]bool, 12))
	f.Set(11)
	if !f.Has(11) || f.Has(0) || f.Has(12) || f.Has(-1) || f.Count() != 1 {
		t.Fatalf("bitfield = %v", f.bools())
	}
}

// failingReader fails the test if the frame body is read.
type failingReader struct {
	t    *testing.T
	head []byte
}

func (r *failingReader) Read(b []byte) (int, error) {
	if len(r.head) == 0 {
		r.t.Fatal("body read after an oversized header")
	}
	n := copy(b, r.head)
	r.head = r.head[n:]
	return n, nil
}

func TestOversizedFrameIsRejectedUnread(t *testing.T) {
	head := []byte{ProtocolEMule, 0, 0, 0, 0, 0x60}
	binary.LittleEndian.PutUint32(head[1:5], MaxFrameSize+1)
	if _, err := ParseFrameFrom(&failingReader{t: t, head: head}); !errors.Is(err, errTooLarge) {
		t.Fatalf("err = %v, want errTooLarge", err)
	}
	binary.LittleEndian.PutUint32(head[1:5], MaxFrameSize)
	raw := append(head, make([]byte, MaxFrameSize-1)...)
	if f, err := ParseFrameFrom(bytes.NewReader(raw)); err != nil || len(f.Body) != MaxFrameSize-1 {
		t.Fatalf("largest frame: %d bytes, err %v", len(f.Body), err)
	}
}

func TestTruncatedFrameFails(t *testing.T) {
	raw := BuildFrame(nil, ProtocolEMule, 0x60, make([]byte, 100))
	if _, err := ParseFrameFrom(bytes.NewReader(raw[:50])); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("err = %v, want ErrUnexpectedEOF", err)
	}
}

func TestInflationBomb(t *testing.T) {
	bomb := make([]byte, maxInflatedSize+1)
	if _, err := ParseFrameFrom(bytes.NewReader(BuildPackedFrame(nil, 0x60, bomb))); !errors.Is(err, errTooLarge) {
		t.Fatalf("frame err = %v, want errTooLarge", err)
	}
	if _, err := ParseDatagram(BuildPackedDatagram(nil, ProtocolKad, 0x3B, bomb)); !errors.Is(err, errTooLarge) {
		t.Fatalf("datagram err = %v, want errTooLarge", err)
	}
	if f, err := ParseDatagram(BuildPackedDatagram(nil, ProtocolKad, 0x3B, bomb[:maxInflatedSize])); err != nil || len(f.Body) != maxInflatedSize {
		t.Fatalf("largest datagram: %d bytes, err %v", len(f.Body), err)
	}
}

func TestTagListCap(t *testing.T) {
	build := func(count int) []byte {
		b := binary.LittleEndian.AppendUint32(nil, uint32(count))
		for range count {
			b = append(b, TagUint8|0x80, 0x01, 7)
		}
		return b
	}
	r := &Reader{Rest: build(maxTags)}
	if tags := r.Tags(); len(tags) != maxTags || r.Err() != nil {
		t.Fatalf("%d tags: got %d, err %v", maxTags, len(tags), r.Err())
	}
	r = &Reader{Rest: build(maxTags + 1)}
	if tags := r.Tags(); tags != nil || r.Err() == nil {
		t.Fatalf("%d tags: got %d, want an error", maxTags+1, len(tags))
	}
}

func TestToEmuleVersion(t *testing.T) {
	for version, want := range map[string]uint32{
		"v1.2.3":    0x4B<<24 | 1<<17 | 2<<10 | 3<<7,
		"1.2.3":     0x4B<<24 | 1<<17 | 2<<10 | 3<<7,
		"1.2.3-dev": 0x4B<<24 | 1<<17 | 2<<10 | 3<<7,
		"v0.10":     0x4B<<24 | 10<<10,
		"dev":       0x4B << 24,
		"1.2.9":     0x4B<<24 | 1<<17 | 2<<10 | 1<<7,
	} {
		if got := ToEmuleVersion(version); got != want {
			t.Errorf("ToEmuleVersion(%q) = %#x, want %#x", version, got, want)
		}
	}
}
