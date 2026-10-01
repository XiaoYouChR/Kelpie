package client

import (
	"encoding/binary"
	"errors"

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

// MultiPacketExt2 is OP_MULTIPACKET_EXT2, which names the file by its
// FileIdentifier. eMule sends it to peers that set MiscOptions2
// HasFileIdentifiers (DownloadClient.cpp:316-400).
type MultiPacketExt2 struct {
	File     FileIdentifier
	Requests []wire.Packet
}

// MultiPacketAnswer is OP_MULTIPACKETANSWER. Answers holds FileNameAnswer,
// FileStatus and AICHFileHashAnswer values, plus a trailing wire.Unknown as in MultiPacket.
type MultiPacketAnswer struct {
	Hash    wire.Hash
	Answers []wire.Packet
}

// MultiPacketAnswerExt2 is OP_MULTIPACKETANSWER_EXT2, eMule's answer to a
// MultiPacketExt2; File is the sender's own identifier
// (ListenSocket.cpp:1168-1172, 1292).
type MultiPacketAnswerExt2 struct {
	File    FileIdentifier
	Answers []wire.Packet
}

// FileIdentifier is eMule's CFileIdentifier on the wire
// (FileIdentifier.cpp:94-118): a descriptor byte, then the hash, the size and
// the AICH root, each present when its descriptor bit is set. Size 0 means
// it was left out, as eMule reads it.
type FileIdentifier struct {
	Hash    wire.Hash
	Size    uint64
	HasRoot bool
	Root    wire.AICHHash
}

const (
	identifierHasHash byte = 1 << 0
	identifierHasSize byte = 1 << 1
	identifierHasRoot byte = 1 << 2
	// identifierMandatory are option bits a reader must understand.
	identifierMandatory byte = 0x03 << 3
)

var errFileIdentifier = errors.New("client: file identifier without hash or with unknown mandatory options")

func (MultiPacket) Protocol() byte           { return wire.ProtocolEMule }
func (MultiPacket) Opcode() byte             { return opMultiPacket }
func (MultiPacketExt) Protocol() byte        { return wire.ProtocolEMule }
func (MultiPacketExt) Opcode() byte          { return opMultiPacketExt }
func (MultiPacketAnswer) Protocol() byte     { return wire.ProtocolEMule }
func (MultiPacketAnswer) Opcode() byte       { return opMultiPacketAnswer }
func (MultiPacketExt2) Protocol() byte       { return wire.ProtocolEMule }
func (MultiPacketExt2) Opcode() byte         { return opMultiPacketExt2 }
func (MultiPacketAnswerExt2) Protocol() byte { return wire.ProtocolEMule }
func (MultiPacketAnswerExt2) Opcode() byte   { return opMultiPacketAnswerExt2 }

func (m MultiPacket) Build(b []byte) []byte {
	return buildRequests(append(b, m.Hash[:]...), m.Requests)
}

func (m MultiPacketExt) Build(b []byte) []byte {
	b = binary.LittleEndian.AppendUint64(append(b, m.Hash[:]...), m.Size)
	return buildRequests(b, m.Requests)
}

func (m MultiPacketExt2) Build(b []byte) []byte {
	return buildRequests(buildFileIdentifier(b, m.File), m.Requests)
}

func (m MultiPacketAnswer) Build(b []byte) []byte {
	return buildAnswers(append(b, m.Hash[:]...), m.Answers)
}

func (m MultiPacketAnswerExt2) Build(b []byte) []byte {
	return buildAnswers(buildFileIdentifier(b, m.File), m.Answers)
}

func buildFileIdentifier(b []byte, f FileIdentifier) []byte {
	desc := identifierHasHash
	if f.Size != 0 {
		desc |= identifierHasSize
	}
	if f.HasRoot {
		desc |= identifierHasRoot
	}
	b = append(append(b, desc), f.Hash[:]...)
	if f.Size != 0 {
		b = binary.LittleEndian.AppendUint64(b, f.Size)
	}
	if f.HasRoot {
		b = append(b, f.Root[:]...)
	}
	return b
}

// parseFileIdentifier rejects what eMule rejects: no hash, or a mandatory
// option it does not know; other option bits are ignored
// (FileIdentifier.cpp:498-532).
func parseFileIdentifier(r *wire.Reader) FileIdentifier {
	desc := r.Uint8()
	if desc&identifierHasHash == 0 || desc&identifierMandatory != 0 {
		r.SetErr(errFileIdentifier)
		return FileIdentifier{}
	}
	f := FileIdentifier{Hash: r.Hash()}
	if desc&identifierHasSize != 0 {
		f.Size = r.Uint64()
	}
	if desc&identifierHasRoot != 0 {
		f.HasRoot, f.Root = true, r.AICHHash()
	}
	return f
}

func buildAnswers(b []byte, answers []wire.Packet) []byte {
	for _, p := range answers {
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

func parseMultiPacketExt2(r *wire.Reader) MultiPacketExt2 {
	m := MultiPacketExt2{File: parseFileIdentifier(r)}
	m.Requests = parseRequests(r, m.File.Hash)
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
	m.Answers = parseAnswers(r, m.Hash)
	return m
}

func parseMultiPacketAnswerExt2(r *wire.Reader) MultiPacketAnswerExt2 {
	m := MultiPacketAnswerExt2{File: parseFileIdentifier(r)}
	m.Answers = parseAnswers(r, m.File.Hash)
	return m
}

func parseAnswers(r *wire.Reader, hash wire.Hash) []wire.Packet {
	var out []wire.Packet
	var isSeen [256]bool
	for r.Len() > 0 && r.Err() == nil {
		op := r.Uint8()
		var p wire.Packet
		switch op {
		case opFileNameAnswer:
			p = FileNameAnswer{Hash: hash, Name: r.String()}
		case opFileStatus:
			p = FileStatus{Hash: hash, Parts: r.Bitfield()}
		case opAICHFileHashAnswer:
			p = AICHFileHashAnswer{Hash: hash, Root: r.AICHHash()}
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
