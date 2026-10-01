package wire

import (
	"bytes"
	"net/netip"
	"testing"
)

func FuzzParseFrame(f *testing.F) {
	f.Add(BuildFrame(nil, ProtocolEDonkey, 0x5C, []byte{0x70, 0x11, 0x01, 0x00}))
	f.Add(BuildPackedFrame(nil, 0x84, bytes.Repeat([]byte("kelpie"), 100)))
	f.Add(BuildFrame(nil, ProtocolEMule, 0x60, make([]byte, 12)))
	f.Add([]byte{0xE3, 0xFF, 0xFF, 0xFF, 0x7F, 1})
	f.Fuzz(func(t *testing.T, b []byte) {
		frame, n, err := ParseFrame(b)
		if n > len(b) || (err == nil && n > 0 && len(frame.Body) > max(MaxFrameSize, maxInflatedSize)) {
			t.Fatalf("n=%d body=%d", n, len(frame.Body))
		}
		ParseFrameFrom(bytes.NewReader(b))
	})
}

func FuzzParseDatagram(f *testing.F) {
	f.Add(BuildPackedDatagram(nil, ProtocolKad, 0x3B, []byte{1, 2, 3, 4}))
	f.Add(BuildPackedDatagram(nil, ProtocolEMule, 0x90, make([]byte, 16)))
	f.Add(buildDatagram(nil, ProtocolEDonkey, 0x96, []byte{1, 2, 3, 4}))
	f.Fuzz(func(t *testing.T, b []byte) {
		frame, err := ParseDatagram(b)
		if err == nil && len(frame.Body) > max(MaxFrameSize, maxInflatedSize) {
			t.Fatalf("body=%d", len(frame.Body))
		}
	})
}

func FuzzTags(f *testing.F) {
	addr := netip.MustParseAddr("2a01:4f8::1").As16()
	f.Add(BuildTags(nil, []Tag{
		{Type: TagHash, ID: 0xAE, Hash: Hash(addr)},
		{Type: TagString, Name: "custom", String: "x"},
		{Type: TagUint32, ID: 0xBB, Uint: 4661},
		{Type: TagFloat32, ID: 0x10, Float: 1.5},
		{Type: TagBool, ID: 0x11, Uint: 1},
		{Type: TagBoolArray, ID: 0x12, Uint: 9, Blob: []byte{0xFF, 0x01}},
		{Type: TagBlob, ID: 0x13, Blob: []byte{1, 2, 3}},
		{Type: TagUint16, ID: 0x14, Uint: 7},
		{Type: TagUint8, Name: "ab", Uint: 1},
		{Type: TagBsob, ID: 0x15, Blob: []byte{4}},
		{Type: TagUint64, ID: 0x02, Uint: 1 << 40},
	}))
	f.Add(append([]byte{2, 0, 0, 0}, BuildCompactTag(BuildCompactTag(nil, Tag{Type: TagString, ID: 0x01, String: "abc"}), Tag{Type: TagUint64, ID: 0x02, Uint: 4})...))
	f.Add(BuildBitfield(nil, ToBitfield([]bool{true, false, true, true, false, false, false, false, true})))
	f.Fuzz(func(t *testing.T, b []byte) {
		r := &Reader{Rest: b}
		if tags := r.Tags(); r.Err() == nil {
			BuildTags(nil, tags)
		}
		r = &Reader{Rest: b}
		field := r.Bitfield()
		field.Count()
		field.bools()
		BuildBitfield(nil, field)
	})
}
