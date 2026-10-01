// Derived from goed2k protocol/client (file_request.go, file_answer.go,
// file_status_*.go, hash_set_*.go, queue_rank*.go, request_parts.go,
// sending_part.go, compressed_part.go).
package client

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/XiaoYouChR/Kelpie/internal/wire"
)

// ExtendedRequestsVersion is the extended-requests version Kelpie must
// advertise in MiscOptions1. A peer appends file-request extensions sized by
// the version *we* advertise, and inside a MultiPacket nothing delimits them,
// so the parser can only follow this value.
const ExtendedRequestsVersion = 2

// FileRequest is OP_REQUESTFILENAME. With extended requests v1 the sender
// appends its own part status; v2 also appends its complete-source count.
type FileRequest struct {
	Hash               wire.Hash
	HasParts           bool
	Parts              wire.Bitfield
	HasCompleteSources bool
	CompleteSources    uint16
}

func (FileRequest) Protocol() byte { return wire.ProtocolEDonkey }
func (FileRequest) Opcode() byte   { return opRequestFileName }

func (f FileRequest) Build(b []byte) []byte {
	return buildFileRequestExtension(append(b, f.Hash[:]...), f)
}

func buildFileRequestExtension(b []byte, f FileRequest) []byte {
	if f.HasParts {
		b = wire.BuildBitfield(b, f.Parts)
	}
	if f.HasCompleteSources {
		b = binary.LittleEndian.AppendUint16(b, f.CompleteSources)
	}
	return b
}

func parseFileRequest(r *wire.Reader) FileRequest {
	f := FileRequest{Hash: r.Hash()}
	if r.Len() > 0 {
		f.HasParts, f.Parts = true, r.Bitfield()
	}
	if r.Len() > 0 {
		f.HasCompleteSources, f.CompleteSources = true, r.Uint16()
	}
	return f
}

// FileNameAnswer is OP_REQFILENAMEANSWER.
type FileNameAnswer struct {
	Hash wire.Hash
	Name string
}

func (FileNameAnswer) Protocol() byte { return wire.ProtocolEDonkey }
func (FileNameAnswer) Opcode() byte   { return opFileNameAnswer }

func (f FileNameAnswer) Build(b []byte) []byte {
	return wire.BuildString(append(b, f.Hash[:]...), f.Name)
}

// SetRequestFileID is OP_SETREQFILEID: "tell me your part status".
type SetRequestFileID struct{ Hash wire.Hash }

func (SetRequestFileID) Protocol() byte          { return wire.ProtocolEDonkey }
func (SetRequestFileID) Opcode() byte            { return opSetRequestFileID }
func (s SetRequestFileID) Build(b []byte) []byte { return append(b, s.Hash[:]...) }

// FileStatus is OP_FILESTATUS. Zero parts means the sender has the whole
// file.
type FileStatus struct {
	Hash  wire.Hash
	Parts wire.Bitfield
}

func (FileStatus) Protocol() byte { return wire.ProtocolEDonkey }
func (FileStatus) Opcode() byte   { return opFileStatus }

func (f FileStatus) Build(b []byte) []byte {
	return wire.BuildBitfield(append(b, f.Hash[:]...), f.Parts)
}

// NoFile is OP_FILEREQANSNOFIL: the peer does not share the file.
type NoFile struct{ Hash wire.Hash }

func (NoFile) Protocol() byte          { return wire.ProtocolEDonkey }
func (NoFile) Opcode() byte            { return opNoFile }
func (n NoFile) Build(b []byte) []byte { return append(b, n.Hash[:]...) }

// HashSetRequest is OP_HASHSETREQUEST.
type HashSetRequest struct{ Hash wire.Hash }

func (HashSetRequest) Protocol() byte          { return wire.ProtocolEDonkey }
func (HashSetRequest) Opcode() byte            { return opHashSetRequest }
func (h HashSetRequest) Build(b []byte) []byte { return append(b, h.Hash[:]...) }

// HashSetAnswer is OP_HASHSETANSWER: the MD4 of every part.
type HashSetAnswer struct {
	Hash  wire.Hash
	Parts []wire.Hash
}

func (HashSetAnswer) Protocol() byte { return wire.ProtocolEDonkey }
func (HashSetAnswer) Opcode() byte   { return opHashSetAnswer }

func (h HashSetAnswer) Build(b []byte) []byte {
	b = append(b, h.Hash[:]...)
	b = binary.LittleEndian.AppendUint16(b, uint16(len(h.Parts)))
	for _, p := range h.Parts {
		b = append(b, p[:]...)
	}
	return b
}

func parseHashSetAnswer(r *wire.Reader) HashSetAnswer {
	h := HashSetAnswer{Hash: r.Hash()}
	count := int(r.Uint16())
	if count*16 > r.Len() {
		r.SetErr(wire.ErrShort)
		return h
	}
	h.Parts = make([]wire.Hash, count)
	for i := range h.Parts {
		h.Parts[i] = r.Hash()
	}
	return h
}

// HashSetRequest2 is OP_HASHSETREQUEST2, which eMule sends instead of
// HashSetRequest to peers with HasFileIdentifiers
// (DownloadClient.cpp:2485-2515).
type HashSetRequest2 struct {
	File         FileIdentifier
	IsMD4Wanted  bool
	IsAICHWanted bool
}

// HashSetAnswer2 is OP_HASHSETANSWER2 carrying the MD4 part hashes, or
// nothing when Parts is empty. Kelpie never sends the AICH part hashes; eMule
// then asks another peer (DownloadClient.cpp:836-840).
type HashSetAnswer2 struct {
	File  FileIdentifier
	Parts []wire.Hash
}

const (
	hashSetMD4  byte = 0x01
	hashSetAICH byte = 0x02
)

func (HashSetRequest2) Protocol() byte { return wire.ProtocolEMule }
func (HashSetRequest2) Opcode() byte   { return opHashSetRequest2 }
func (HashSetAnswer2) Protocol() byte  { return wire.ProtocolEMule }
func (HashSetAnswer2) Opcode() byte    { return opHashSetAnswer2 }

func (h HashSetRequest2) Build(b []byte) []byte {
	var options byte
	if h.IsMD4Wanted {
		options |= hashSetMD4
	}
	if h.IsAICHWanted {
		options |= hashSetAICH
	}
	return append(buildFileIdentifier(b, h.File), options)
}

func parseHashSetRequest2(r *wire.Reader) HashSetRequest2 {
	h := HashSetRequest2{File: parseFileIdentifier(r)}
	options := r.Uint8()
	h.IsMD4Wanted, h.IsAICHWanted = options&hashSetMD4 != 0, options&hashSetAICH != 0
	return h
}

// Build lays out eMule's WriteHashSetsToPacket (FileIdentifier.cpp:267-308):
// the options byte says which sets follow.
func (h HashSetAnswer2) Build(b []byte) []byte {
	b = buildFileIdentifier(b, h.File)
	if len(h.Parts) == 0 {
		return append(b, 0)
	}
	return HashSetAnswer{Hash: h.File.Hash, Parts: h.Parts}.Build(append(b, hashSetMD4))
}

// StartUploadRequest is OP_STARTUPLOADREQ. Old clients send it without a
// hash, which decodes as the zero hash.
type StartUploadRequest struct{ Hash wire.Hash }

func (StartUploadRequest) Protocol() byte          { return wire.ProtocolEDonkey }
func (StartUploadRequest) Opcode() byte            { return opStartUploadRequest }
func (s StartUploadRequest) Build(b []byte) []byte { return append(b, s.Hash[:]...) }

// AcceptUploadRequest is OP_ACCEPTUPLOADREQ: we got an upload slot.
type AcceptUploadRequest struct{}

func (AcceptUploadRequest) Protocol() byte        { return wire.ProtocolEDonkey }
func (AcceptUploadRequest) Opcode() byte          { return opAcceptUploadRequest }
func (AcceptUploadRequest) Build(b []byte) []byte { return b }

// CancelTransfer is OP_CANCELTRANSFER.
type CancelTransfer struct{}

func (CancelTransfer) Protocol() byte        { return wire.ProtocolEDonkey }
func (CancelTransfer) Opcode() byte          { return opCancelTransfer }
func (CancelTransfer) Build(b []byte) []byte { return b }

// OutOfParts is OP_OUTOFPARTREQS: the uploader ends our slot.
type OutOfParts struct{}

func (OutOfParts) Protocol() byte        { return wire.ProtocolEDonkey }
func (OutOfParts) Opcode() byte          { return opOutOfParts }
func (OutOfParts) Build(b []byte) []byte { return b }

// QueueRank is the eDonkey OP_QUEUERANK.
type QueueRank struct{ Rank uint32 }

func (QueueRank) Protocol() byte { return wire.ProtocolEDonkey }
func (QueueRank) Opcode() byte   { return opQueueRank }
func (q QueueRank) Build(b []byte) []byte {
	return binary.LittleEndian.AppendUint32(b, q.Rank)
}

// QueueRanking is the eMule OP_QUEUERANKING: a uint16 rank padded with ten
// zero bytes.
type QueueRanking struct{ Rank uint16 }

func (QueueRanking) Protocol() byte { return wire.ProtocolEMule }
func (QueueRanking) Opcode() byte   { return opQueueRanking }
func (q QueueRanking) Build(b []byte) []byte {
	b = binary.LittleEndian.AppendUint16(b, q.Rank)
	return append(b, make([]byte, 10)...)
}

// RequestParts is OP_REQUESTPARTS: up to three [Start, End) ranges; unused
// slots are zero.
type RequestParts struct {
	Hash   wire.Hash
	Starts [3]uint32
	Ends   [3]uint32
}

func (RequestParts) Protocol() byte { return wire.ProtocolEDonkey }
func (RequestParts) Opcode() byte   { return opRequestParts }

func (p RequestParts) Build(b []byte) []byte {
	b = append(b, p.Hash[:]...)
	for _, v := range p.Starts {
		b = binary.LittleEndian.AppendUint32(b, v)
	}
	for _, v := range p.Ends {
		b = binary.LittleEndian.AppendUint32(b, v)
	}
	return b
}

func parseRequestParts(r *wire.Reader) RequestParts {
	p := RequestParts{Hash: r.Hash()}
	for i := range p.Starts {
		p.Starts[i] = r.Uint32()
	}
	for i := range p.Ends {
		p.Ends[i] = r.Uint32()
	}
	return p
}

// RequestParts64 is OP_REQUESTPARTS_I64, for files over 4 GiB.
type RequestParts64 struct {
	Hash   wire.Hash
	Starts [3]uint64
	Ends   [3]uint64
}

func (RequestParts64) Protocol() byte { return wire.ProtocolEMule }
func (RequestParts64) Opcode() byte   { return opRequestParts64 }

func (p RequestParts64) Build(b []byte) []byte {
	b = append(b, p.Hash[:]...)
	for _, v := range p.Starts {
		b = binary.LittleEndian.AppendUint64(b, v)
	}
	for _, v := range p.Ends {
		b = binary.LittleEndian.AppendUint64(b, v)
	}
	return b
}

func parseRequestParts64(r *wire.Reader) RequestParts64 {
	p := RequestParts64{Hash: r.Hash()}
	for i := range p.Starts {
		p.Starts[i] = r.Uint64()
	}
	for i := range p.Ends {
		p.Ends[i] = r.Uint64()
	}
	return p
}

// SendingPart is OP_SENDINGPART: Data is the file bytes [Start, End).
type SendingPart struct {
	Hash  wire.Hash
	Start uint32
	End   uint32
	Data  []byte
}

func (SendingPart) Protocol() byte { return wire.ProtocolEDonkey }
func (SendingPart) Opcode() byte   { return opSendingPart }

func (s SendingPart) Build(b []byte) []byte {
	b = append(b, s.Hash[:]...)
	b = binary.LittleEndian.AppendUint32(b, s.Start)
	b = binary.LittleEndian.AppendUint32(b, s.End)
	return append(b, s.Data...)
}

func parseSendingPart(r *wire.Reader) SendingPart {
	s := SendingPart{Hash: r.Hash(), Start: r.Uint32(), End: r.Uint32()}
	s.Data = r.Bytes(r.Len())
	if r.Err() == nil && (s.End < s.Start || s.End-s.Start != uint32(len(s.Data))) {
		r.SetErr(fmt.Errorf("client: part [%d, %d) carries %d bytes", s.Start, s.End, len(s.Data)))
	}
	return s
}

// SendingPart64 is OP_SENDINGPART_I64.
type SendingPart64 struct {
	Hash  wire.Hash
	Start uint64
	End   uint64
	Data  []byte
}

func (SendingPart64) Protocol() byte { return wire.ProtocolEMule }
func (SendingPart64) Opcode() byte   { return opSendingPart64 }

func (s SendingPart64) Build(b []byte) []byte {
	b = append(b, s.Hash[:]...)
	b = binary.LittleEndian.AppendUint64(b, s.Start)
	b = binary.LittleEndian.AppendUint64(b, s.End)
	return append(b, s.Data...)
}

func parseSendingPart64(r *wire.Reader) SendingPart64 {
	s := SendingPart64{Hash: r.Hash(), Start: r.Uint64(), End: r.Uint64()}
	s.Data = r.Bytes(r.Len())
	if r.Err() == nil && (s.End < s.Start || s.End-s.Start != uint64(len(s.Data))) {
		r.SetErr(fmt.Errorf("client: part [%d, %d) carries %d bytes", s.Start, s.End, len(s.Data)))
	}
	return s
}

// CompressedPart is OP_COMPRESSEDPART: one zlib chunk of a block that starts
// at Start. PackedSize is the compressed size of the whole block, which
// arrives across several of these.
type CompressedPart struct {
	Hash       wire.Hash
	Start      uint32
	PackedSize uint32
	Data       []byte
}

func (CompressedPart) Protocol() byte { return wire.ProtocolEMule }
func (CompressedPart) Opcode() byte   { return opCompressedPart }

func (c CompressedPart) Build(b []byte) []byte {
	b = append(b, c.Hash[:]...)
	b = binary.LittleEndian.AppendUint32(b, c.Start)
	b = binary.LittleEndian.AppendUint32(b, c.PackedSize)
	return append(b, c.Data...)
}

// CompressedPart64 is OP_COMPRESSEDPART_I64.
type CompressedPart64 struct {
	Hash       wire.Hash
	Start      uint64
	PackedSize uint32
	Data       []byte
}

func (CompressedPart64) Protocol() byte { return wire.ProtocolEMule }
func (CompressedPart64) Opcode() byte   { return opCompressedPart64 }

func (c CompressedPart64) Build(b []byte) []byte {
	b = append(b, c.Hash[:]...)
	b = binary.LittleEndian.AppendUint64(b, c.Start)
	b = binary.LittleEndian.AppendUint32(b, c.PackedSize)
	return append(b, c.Data...)
}

// SecureIdentState is OP_SECIDENTSTATE: which Secure User Identification
// pieces the sender still needs, and the challenge to sign.
type SecureIdentState struct {
	State     byte
	Challenge uint32
}

// SecureIdentNeedsKeyAndSignature is the only state Kelpie sends; a
// State of 1 asks for the signature alone.
const SecureIdentNeedsKeyAndSignature byte = 2

func (SecureIdentState) Protocol() byte { return wire.ProtocolEMule }
func (SecureIdentState) Opcode() byte   { return opSecureIdentState }
func (s SecureIdentState) Build(b []byte) []byte {
	return binary.LittleEndian.AppendUint32(append(b, s.State), s.Challenge)
}

// PublicKey is OP_PUBLICKEY.
type PublicKey struct{ Key []byte }

func (PublicKey) Protocol() byte { return wire.ProtocolEMule }
func (PublicKey) Opcode() byte   { return opPublicKey }
func (p PublicKey) Build(b []byte) []byte {
	return append(append(b, byte(len(p.Key))), p.Key...)
}

// Signature is OP_SIGNATURE. IPKind is present from Secure Ident v2 on and
// names which address the signature binds (identity.IPKind); 0 means
// absent.
type Signature struct {
	Signature []byte
	IPKind    byte
}

func (Signature) Protocol() byte { return wire.ProtocolEMule }
func (Signature) Opcode() byte   { return opSignature }
func (s Signature) Build(b []byte) []byte {
	b = append(append(b, byte(len(s.Signature))), s.Signature...)
	if s.IPKind != 0 {
		b = append(b, s.IPKind)
	}
	return b
}

func parseSignature(r *wire.Reader) Signature {
	s := Signature{Signature: r.Bytes(int(r.Uint8()))}
	if r.Len() > 0 {
		s.IPKind = r.Uint8()
	}
	return s
}

// IPv6Changed is OP_CHANGE_CLIENT_IP (ipv6-spec §3.2): the sender's public
// IPv6 changed. It travels under 0xE3, not 0xC5.
type IPv6Changed struct{ Addr netip.Addr }

func (IPv6Changed) Protocol() byte          { return wire.ProtocolEDonkey }
func (IPv6Changed) Opcode() byte            { return opIPv6Changed }
func (c IPv6Changed) Build(b []byte) []byte { return wire.BuildIPv6(b, c.Addr) }
