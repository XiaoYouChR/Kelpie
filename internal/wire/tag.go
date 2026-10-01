// Derived from goed2k protocol/simple_tag.go.
package wire

import (
	"encoding/binary"
	"fmt"
	"math"
)

const (
	TagHash      byte = 0x01
	TagString    byte = 0x02
	TagUint32    byte = 0x03
	TagFloat32   byte = 0x04
	TagBool      byte = 0x05
	TagBoolArray byte = 0x06
	TagBlob      byte = 0x07
	TagUint16    byte = 0x08
	TagUint8     byte = 0x09
	TagBsob      byte = 0x0A
	TagUint64    byte = 0x0B
	TagStr1      byte = 0x11
	TagStr16     byte = 0x20
)

// Tag is one eD2k tag. A tag is named either by a one-byte ID (Name empty)
// or by a multi-byte Name. Which value field is meaningful depends on Type:
// Uint for the integer types and Bool (and the bit count of BoolArray),
// Float for Float32, String for String, Hash for Hash, Blob for Blob, Bsob
// and the bytes of BoolArray.
//
// Short string types (Str1..Str16) decode as String; integer types keep the
// width they arrived with.
type Tag struct {
	Type   byte
	ID     byte
	Name   string
	Uint   uint64
	Float  float32
	String string
	Hash   Hash
	Blob   []byte
}

// Tag reads a tag in either the classic form (uint16 name length) or the
// compact form (type|0x80 followed by a one-byte ID).
func (r *Reader) Tag() Tag {
	var t Tag
	head := r.Uint8()
	t.Type = head & 0x7F
	if head&0x80 != 0 {
		t.ID = r.Uint8()
	} else {
		name := r.Bytes(int(r.Uint16()))
		if len(name) == 1 {
			t.ID = name[0]
		} else {
			t.Name = string(name)
		}
	}
	switch {
	case t.Type == TagHash:
		t.Hash = r.Hash()
	case t.Type == TagString:
		t.String = r.String()
	case t.Type == TagUint32:
		t.Uint = uint64(r.Uint32())
	case t.Type == TagFloat32:
		t.Float = r.Float32()
	case t.Type == TagBool, t.Type == TagUint8:
		t.Uint = uint64(r.Uint8())
	case t.Type == TagBoolArray:
		t.Uint = uint64(r.Uint16())
		t.Blob = r.Bytes(int(t.Uint)/8 + 1)
	case t.Type == TagBlob:
		t.Blob = r.Bytes(int(r.Uint32()))
	case t.Type == TagUint16:
		t.Uint = uint64(r.Uint16())
	case t.Type == TagBsob:
		t.Blob = r.Bytes(int(r.Uint8()))
	case t.Type == TagUint64:
		t.Uint = r.Uint64()
	case t.Type >= TagStr1 && t.Type <= TagStr16:
		t.String = string(r.Bytes(int(t.Type-TagStr1) + 1))
		t.Type = TagString
	default:
		r.SetErr(fmt.Errorf("wire: unknown tag type %#x", t.Type))
	}
	return t
}

// Tags reads a uint32 count followed by that many tags.
func (r *Reader) Tags() []Tag {
	count := r.Uint32()
	if uint64(count) > uint64(r.Len()/2) {
		r.SetErr(fmt.Errorf("wire: %d tags cannot fit in %d bytes", count, r.Len()))
		return nil
	}
	if count == 0 {
		return nil
	}
	tags := make([]Tag, 0, count)
	for range count {
		tags = append(tags, r.Tag())
	}
	if r.Err() != nil {
		return nil
	}
	return tags
}

// BuildTag writes the classic form: a uint16-length name, strings as
// TagString, integers at their declared width. Hello, login, offer-files and
// Kad tags must use it; servers drop clients that send compact tags before
// the session has negotiated them.
func BuildTag(b []byte, t Tag) []byte {
	b = append(b, t.Type)
	if t.Name == "" {
		b = append(b, 1, 0, t.ID)
	} else {
		b = BuildString(b, t.Name)
	}
	return buildTagValue(b, t)
}

// BuildCompactTag writes the compact form eMule uses once both sides speak
// it: a one-byte ID name, Str1..Str16 for short strings, and the narrowest
// integer type that holds the value.
func BuildCompactTag(b []byte, t Tag) []byte {
	switch t.Type {
	case TagUint8, TagUint16, TagUint32, TagUint64:
		t.Type = toNarrowestUint(t.Uint)
	case TagString:
		if n := len(t.String); n >= 1 && n <= 16 {
			t.Type = TagStr1 + byte(n-1)
		}
	}
	if t.Name == "" {
		b = append(b, t.Type|0x80, t.ID)
	} else {
		b = append(b, t.Type)
		b = BuildString(b, t.Name)
	}
	return buildTagValue(b, t)
}

func BuildTags(b []byte, tags []Tag) []byte {
	b = binary.LittleEndian.AppendUint32(b, uint32(len(tags)))
	for _, t := range tags {
		b = BuildTag(b, t)
	}
	return b
}

func toNarrowestUint(v uint64) byte {
	switch {
	case v <= math.MaxUint8:
		return TagUint8
	case v <= math.MaxUint16:
		return TagUint16
	case v <= math.MaxUint32:
		return TagUint32
	}
	return TagUint64
}

func buildTagValue(b []byte, t Tag) []byte {
	switch {
	case t.Type == TagHash:
		return append(b, t.Hash[:]...)
	case t.Type == TagString:
		return BuildString(b, t.String)
	case t.Type == TagUint32:
		return binary.LittleEndian.AppendUint32(b, uint32(t.Uint))
	case t.Type == TagFloat32:
		return binary.LittleEndian.AppendUint32(b, math.Float32bits(t.Float))
	case t.Type == TagBool, t.Type == TagUint8:
		return append(b, byte(t.Uint))
	case t.Type == TagBoolArray:
		b = binary.LittleEndian.AppendUint16(b, uint16(t.Uint))
		return append(b, t.Blob...)
	case t.Type == TagBlob:
		b = binary.LittleEndian.AppendUint32(b, uint32(len(t.Blob)))
		return append(b, t.Blob...)
	case t.Type == TagUint16:
		return binary.LittleEndian.AppendUint16(b, uint16(t.Uint))
	case t.Type == TagBsob:
		b = append(b, byte(len(t.Blob)))
		return append(b, t.Blob...)
	case t.Type == TagUint64:
		return binary.LittleEndian.AppendUint64(b, t.Uint)
	case t.Type >= TagStr1 && t.Type <= TagStr16:
		return append(b, t.String...)
	}
	panic(fmt.Sprintf("wire: unknown tag type %#x", t.Type))
}
