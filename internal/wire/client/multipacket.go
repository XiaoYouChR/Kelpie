package client

import (
	"encoding/binary"

	"github.com/XiaoYouChR/Kelpie/internal/wire"
)

// MultiPacket is OP_MULTIPACKET: several requests for one file in one frame.
// Requests holds FileRequest, SetRequestFileID, RequestSources,
// RequestSources2 and AICHFileHashRequest values, whose Hash is the MultiPacket's. Sub-requests are
// not length-prefixed, so an unknown one ends parsing and is kept, with
// everything after it, as a trailing wire.Unknown. A repeated opcode is read
// and dropped: eMule sends each once, and keeping every repeat would turn a
// frame of one-byte requests into millions of values.
type MultiPacket struct {
	Hash     wire.Hash
	Requests []wire.Packet
}

// MultiPacketExt is OP_MULTIPACKET_EXT, which adds the file size.
type MultiPacketExt struct {
	Hash     wire.Hash
	Size     uint64
	Requests []wire.Packet
}

// MultiPacketAnswer is OP_MULTIPACKETANSWER. Answers holds FileNameAnswer,
// FileStatus and AICHFileHashAnswer values, plus a trailing wire.Unknown as in MultiPacket.
type MultiPacketAnswer struct {
	Hash    wire.Hash
	Answers []wire.Packet
}

func (MultiPacket) Protocol() byte       { return wire.ProtocolEMule }
func (MultiPacket) Opcode() byte         { return opMultiPacket }
func (MultiPacketExt) Protocol() byte    { return wire.ProtocolEMule }
func (MultiPacketExt) Opcode() byte      { return opMultiPacketExt }
func (MultiPacketAnswer) Protocol() byte { return wire.ProtocolEMule }
func (MultiPacketAnswer) Opcode() byte   { return opMultiPacketAnswer }

func (m MultiPacket) Build(b []byte) []byte {
	return buildRequests(append(b, m.Hash[:]...), m.Requests)
}

func (m MultiPacketExt) Build(b []byte) []byte {
	b = binary.LittleEndian.AppendUint64(append(b, m.Hash[:]...), m.Size)
	return buildRequests(b, m.Requests)
}

func (m MultiPacketAnswer) Build(b []byte) []byte {
	b = append(b, m.Hash[:]...)
	for _, p := range m.Answers {
		b = append(b, p.Opcode())
		switch p := p.(type) {
		case FileNameAnswer:
			b = wire.BuildString(b, p.Name)
		case FileStatus:
			b = wire.BuildBitfield(b, p.Parts)
		case AICHFileHashAnswer:
			b = append(b, p.Root[:]...)
		case wire.Unknown:
			b = append(b, p.Body...)
		}
	}
	return b
}

func buildRequests(b []byte, requests []wire.Packet) []byte {
	for _, p := range requests {
		b = append(b, p.Opcode())
		switch p := p.(type) {
		case FileRequest:
			b = buildFileRequestExtension(b, p)
		case RequestSources2:
			b = binary.LittleEndian.AppendUint16(append(b, p.Version), p.Options)
		case wire.Unknown:
			b = append(b, p.Body...)
		}
	}
	return b
}

func parseMultiPacket(r *wire.Reader) MultiPacket {
	m := MultiPacket{Hash: r.Hash()}
	m.Requests = parseRequests(r, m.Hash)
	return m
}

func parseMultiPacketExt(r *wire.Reader) MultiPacketExt {
	m := MultiPacketExt{Hash: r.Hash(), Size: r.Uint64()}
	m.Requests = parseRequests(r, m.Hash)
	return m
}

func parseRequests(r *wire.Reader, hash wire.Hash) []wire.Packet {
	var out []wire.Packet
	var isSeen [256]bool
	for r.Len() > 0 && r.Err() == nil {
		op := r.Uint8()
		var p wire.Packet
		switch op {
		case opRequestFileName:
			f := FileRequest{Hash: hash}
			if ExtendedRequestsVersion >= 1 {
				f.HasParts, f.Parts = true, r.Bitfield()
			}
			if ExtendedRequestsVersion >= 2 {
				f.HasCompleteSources, f.CompleteSources = true, r.Uint16()
			}
			p = f
		case opSetRequestFileID:
			p = SetRequestFileID{Hash: hash}
		case opRequestSources:
			p = RequestSources{Hash: hash}
		case opRequestSources2:
			p = RequestSources2{Version: r.Uint8(), Options: r.Uint16(), Hash: hash}
		case opAICHFileHashRequest:
			p = AICHFileHashRequest{Hash: hash}
		default:
			return append(out, wire.Unknown{Proto: wire.ProtocolEMule, Op: op, Body: r.Bytes(r.Len())})
		}
		if !isSeen[op] {
			isSeen[op] = true
			out = append(out, p)
		}
	}
	return out
}

func parseMultiPacketAnswer(r *wire.Reader) MultiPacketAnswer {
	m := MultiPacketAnswer{Hash: r.Hash()}
	var isSeen [256]bool
	for r.Len() > 0 && r.Err() == nil {
		op := r.Uint8()
		var p wire.Packet
		switch op {
		case opFileNameAnswer:
			p = FileNameAnswer{Hash: m.Hash, Name: r.String()}
		case opFileStatus:
			p = FileStatus{Hash: m.Hash, Parts: r.Bitfield()}
		case opAICHFileHashAnswer:
			p = AICHFileHashAnswer{Hash: m.Hash, Root: r.AICHHash()}
		default:
			m.Answers = append(m.Answers, wire.Unknown{Proto: wire.ProtocolEMule, Op: op, Body: r.Bytes(r.Len())})
			return m
		}
		if !isSeen[op] {
			isSeen[op] = true
			m.Answers = append(m.Answers, p)
		}
	}
	return m
}
