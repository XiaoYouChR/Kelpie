// Derived from goed2k protocol/packet_header.go and protocol/packet_combiner.go.
package wire

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	ProtocolEDonkey   byte = 0xE3
	ProtocolEMule     byte = 0xC5
	ProtocolPacked    byte = 0xD4
	ProtocolKad       byte = 0xE4
	ProtocolKadPacked byte = 0xE5

	// HeaderSize is protocol byte, uint32 length, opcode.
	HeaderSize = 6

	// MaxFrameSize bounds a TCP frame's declared length, checked before
	// anything is allocated (aMule EMSocket.cpp:42 MAX_PACKET_SIZE).
	MaxFrameSize = 2_000_000
	// MaxInflatedSize bounds a packed body once inflated: eMule's limit for
	// servers and UDP (ServerSocket.cpp:742, ClientUDPSocket.cpp:118), the
	// largest it uses; its 50000 for clients is not worth a second limit.
	MaxInflatedSize = 250_000
)

var ErrTooLarge = errors.New("wire: frame too large")

// Frame is one decoded packet envelope. Packed frames are inflated on parse
// and reported under their plain protocol: 0xD4 becomes 0xC5, 0xE5 becomes
// 0xE4.
type Frame struct {
	Protocol byte
	Opcode   byte
	Body     []byte
}

// Packet is anything with a wire form: one struct per opcode.
type Packet interface {
	Protocol() byte
	Opcode() byte
	// Build appends the body, without the frame header, to b.
	Build(b []byte) []byte
}

// Unknown carries a packet whose opcode a family does not decode, so the
// caller sees it instead of losing it.
type Unknown struct {
	Proto byte
	Op    byte
	Body  []byte
}

func (u Unknown) Protocol() byte        { return u.Proto }
func (u Unknown) Opcode() byte          { return u.Op }
func (u Unknown) Build(b []byte) []byte { return append(b, u.Body...) }

// ParseFrame reads one TCP frame from the front of b and returns it with the
// number of bytes consumed. n == 0 with a nil error means b does not yet hold
// a whole frame. An unpacked Body aliases b.
func ParseFrame(b []byte) (f Frame, n int, err error) {
	if len(b) < HeaderSize {
		return Frame{}, 0, nil
	}
	size, err := parseHeader(b[:HeaderSize])
	if err != nil {
		return Frame{}, 0, err
	}
	n = HeaderSize + size
	if len(b) < n {
		return Frame{}, 0, nil
	}
	f, err = toFrame(b[0], b[5], b[HeaderSize:n])
	return f, n, err
}

// ParseFrameFrom reads exactly one TCP frame from r. The body grows as its
// bytes arrive, so a peer that declares a large frame and trickles it holds
// only what it sent.
func ParseFrameFrom(r io.Reader) (Frame, error) {
	var head [HeaderSize]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return Frame{}, err
	}
	size, err := parseHeader(head[:])
	if err != nil {
		return Frame{}, err
	}
	body, err := io.ReadAll(io.LimitReader(r, int64(size)))
	if err != nil {
		return Frame{}, err
	}
	if len(body) < size {
		return Frame{}, io.ErrUnexpectedEOF
	}
	return toFrame(head[0], head[5], body)
}

// ParseDatagram reads a UDP packet: protocol byte, opcode, body.
func ParseDatagram(b []byte) (Frame, error) {
	if len(b) < 2 {
		return Frame{}, ErrShort
	}
	if !isKnownProtocol(b[0]) {
		return Frame{}, fmt.Errorf("wire: unknown protocol %#x", b[0])
	}
	return toFrame(b[0], b[1], b[2:])
}

func BuildFrame(b []byte, protocol, opcode byte, body []byte) []byte {
	b = append(b, protocol)
	b = binary.LittleEndian.AppendUint32(b, uint32(len(body)+1))
	b = append(b, opcode)
	return append(b, body...)
}

// BuildPackedFrame zlib-compresses body under 0xD4. Whether packing pays off
// is the sender's call.
func BuildPackedFrame(b []byte, opcode byte, body []byte) []byte {
	return BuildFrame(b, ProtocolPacked, opcode, toDeflated(body))
}

func BuildDatagram(b []byte, protocol, opcode byte, body []byte) []byte {
	b = append(b, protocol, opcode)
	return append(b, body...)
}

// BuildPackedDatagram compresses body under the packed counterpart of
// protocol: 0xE5 for Kad, 0xD4 otherwise.
func BuildPackedDatagram(b []byte, protocol, opcode byte, body []byte) []byte {
	packed := ProtocolPacked
	if protocol == ProtocolKad {
		packed = ProtocolKadPacked
	}
	return BuildDatagram(b, packed, opcode, toDeflated(body))
}

func BuildPacket(b []byte, p Packet) []byte {
	return BuildFrame(b, p.Protocol(), p.Opcode(), p.Build(nil))
}

func BuildPacketDatagram(b []byte, p Packet) []byte {
	return BuildDatagram(b, p.Protocol(), p.Opcode(), p.Build(nil))
}

func parseHeader(head []byte) (int, error) {
	if !isKnownProtocol(head[0]) {
		return 0, fmt.Errorf("wire: unknown protocol %#x", head[0])
	}
	length := binary.LittleEndian.Uint32(head[1:5])
	if length == 0 {
		return 0, errors.New("wire: frame length 0 has no opcode")
	}
	if length > MaxFrameSize {
		return 0, ErrTooLarge
	}
	return int(length - 1), nil
}

func isKnownProtocol(p byte) bool {
	switch p {
	case ProtocolEDonkey, ProtocolEMule, ProtocolPacked, ProtocolKad, ProtocolKadPacked:
		return true
	}
	return false
}

func toFrame(protocol, opcode byte, body []byte) (Frame, error) {
	switch protocol {
	case ProtocolPacked:
		protocol = ProtocolEMule
	case ProtocolKadPacked:
		protocol = ProtocolKad
	default:
		return Frame{Protocol: protocol, Opcode: opcode, Body: body}, nil
	}
	plain, err := toInflated(body)
	if err != nil {
		return Frame{}, err
	}
	return Frame{Protocol: protocol, Opcode: opcode, Body: plain}, nil
}

func toInflated(body []byte) ([]byte, error) {
	zr, err := zlib.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("wire: inflate: %w", err)
	}
	defer zr.Close()
	plain, err := io.ReadAll(io.LimitReader(zr, MaxInflatedSize+1))
	if err != nil {
		return nil, fmt.Errorf("wire: inflate: %w", err)
	}
	if len(plain) > MaxInflatedSize {
		return nil, ErrTooLarge
	}
	return plain, nil
}

func toDeflated(body []byte) []byte {
	var out bytes.Buffer
	zw := zlib.NewWriter(&out)
	zw.Write(body)
	zw.Close()
	return out.Bytes()
}
