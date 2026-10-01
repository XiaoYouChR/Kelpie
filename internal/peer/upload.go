package peer

import (
	"bytes"
	"compress/zlib"
	"slices"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/aich"
	"github.com/XiaoYouChR/Kelpie/internal/piece"
	"github.com/XiaoYouChR/Kelpie/internal/wire"
	"github.com/XiaoYouChR/Kelpie/internal/wire/client"
)

const (
	// eMule splits each block it uploads into packets of this size.
	partPacketSize = 10240
	// eMule's AddReqBlock refuses a requested range longer than three
	// EMBLOCKSIZE blocks.
	maxRequestSize = 3 * piece.BlockSize
	// maxUploadBlocks bounds the blocks a peer may have requested and not
	// yet received, and the sent blocks remembered: aMule keeps at most 32
	// requests open to one uploader (DownloadClient.cpp:603).
	maxUploadBlocks = 32
)

// Share is one of our files as offered to peers. Parts is what we can
// upload; PartHashes is empty for files below one part. Tree is the AICH
// tree of a complete file, nil until built.
type Share struct {
	Name       string
	Size       int64
	Parts      piece.Set
	PartHashes []wire.Hash
	Tree       *aich.Tree
}

// shareByHash looks up a file we offer.
type shareByHash func(file wire.Hash) (Share, bool)

type uploadBlock struct {
	file  wire.Hash
	block piece.Block
}

// uploadState is the upload role. Like eMule we hold one slot per client;
// while it is open the peer may request blocks of any file we share.
type uploadState struct {
	// file is what the peer last asked about, for an OP_STARTUPLOADREQ that
	// carries no hash.
	file wire.Hash
	// parts holds, per file, what the peer's file request said it has.
	parts       map[wire.Hash]piece.Set
	isUploading bool
	sizes       map[wire.Hash]int64
	// blocks holds the blocks requested and not yet sent (false) and the
	// last ones sent (true, oldest first in sent), so a peer re-listing
	// blocks still in flight gets each only once.
	blocks map[uploadBlock]bool
	sent   []uploadBlock
}

// StartUpload gives the peer an upload slot.
func (s *Session) StartUpload() Output {
	var out Output
	s.up.isUploading = true
	clear(s.up.blocks)
	s.up.sent = nil
	out.send(client.AcceptUploadRequest{})
	return out
}

// StopUpload ends the peer's upload slot.
func (s *Session) StopUpload() Output {
	var out Output
	if s.up.isUploading {
		s.up.isUploading = false
		clear(s.up.blocks)
		s.up.sent = nil
		out.send(client.OutOfParts{})
	}
	return out
}

// SendQueueRank tells a waiting peer its place in our upload queue.
func (s *Session) SendQueueRank(rank uint32) Output {
	var out Output
	if s.caps.IsEmule {
		out.send(client.QueueRanking{Rank: uint16(min(rank, 0xFFFF))})
	} else {
		out.send(client.QueueRank{Rank: rank})
	}
	return out
}

// SendBlock uploads one block the peer requested, compressed when the peer
// supports it and compression makes it smaller.
func (s *Session) SendBlock(file wire.Hash, block piece.Block, data []byte) Output {
	var out Output
	key := uploadBlock{file, block}
	if isSent, ok := s.up.blocks[key]; !s.up.isUploading || !ok || isSent {
		return out
	}
	s.up.blocks[key] = true
	if s.up.sent = append(s.up.sent, key); len(s.up.sent) > maxUploadBlocks {
		delete(s.up.blocks, s.up.sent[0])
		s.up.sent = s.up.sent[1:]
	}
	isLarge := s.up.sizes[file] > largeFileSize
	if s.caps.CanCompress {
		if packed := toDeflated(data); len(packed) < len(data) {
			for chunk := range slices.Chunk(packed, partPacketSize) {
				if isLarge {
					out.send(client.CompressedPart64{Hash: file, Start: uint64(block.Begin), PackedSize: uint32(len(packed)), Data: chunk})
				} else {
					out.send(client.CompressedPart{Hash: file, Start: uint32(block.Begin), PackedSize: uint32(len(packed)), Data: chunk})
				}
			}
			return out
		}
	}
	start := block.Begin
	for chunk := range slices.Chunk(data, partPacketSize) {
		end := start + int64(len(chunk))
		if isLarge {
			out.send(client.SendingPart64{Hash: file, Start: uint64(start), End: uint64(end), Data: chunk})
		} else {
			out.send(client.SendingPart{Hash: file, Start: uint32(start), End: uint32(end), Data: chunk})
		}
		start = end
	}
	return out
}

func toDeflated(data []byte) []byte {
	var packed bytes.Buffer
	w := zlib.NewWriter(&packed)
	w.Write(data)
	w.Close()
	return packed.Bytes()
}

func (s *Session) onFileRequest(p client.FileRequest, shares shareByHash, out *Output) {
	share, ok := shares(p.Hash)
	if !ok {
		out.send(client.NoFile{Hash: p.Hash})
		return
	}
	s.up.file = p.Hash
	s.setRequestedParts(p, share)
	out.send(client.FileNameAnswer{Hash: p.Hash, Name: share.Name})
}

func (s *Session) setRequestedParts(p client.FileRequest, share Share) {
	if !p.HasParts {
		return
	}
	if parts, ok := toPartSet(p.Parts, share.Size); ok {
		s.up.parts[p.Hash] = parts
	}
}

func (s *Session) onStatusRequest(file wire.Hash, shares shareByHash, out *Output) {
	share, ok := shares(file)
	if !ok {
		out.send(client.NoFile{Hash: file})
		return
	}
	s.up.file = file
	out.send(client.FileStatus{Hash: file, Parts: ToStatus(share)})
}

// ToStatus is our part status of share for OP_FILESTATUS and the UDP reask:
// no parts for a complete file, as eMule sends.
func ToStatus(share Share) wire.Bitfield {
	if share.Parts.IsFull() {
		return wire.Bitfield{}
	}
	return toBitfield(share.Parts, share.Size)
}

// onMultiPacket answers the bundled requests in one OP_MULTIPACKETANSWER,
// or OP_MULTIPACKETANSWER_EXT2 led by our identifier when isExt2
// (ListenSocket.cpp:1072-1297). OP_MULTIPACKET carries no size.
func (s *Session) onMultiPacket(id client.FileIdentifier, requests []wire.Packet, isExt2 bool, shares shareByHash, now time.Time, out *Output) {
	file := id.Hash
	share, ok := shares(file)
	if !ok || !matchFile(id, share) {
		out.send(client.NoFile{Hash: file})
		return
	}
	s.up.file = file
	var answers []wire.Packet
	var sourcesRequest *client.RequestSources2
	for _, request := range requests {
		switch r := request.(type) {
		case client.FileRequest:
			s.setRequestedParts(r, share)
			answers = append(answers, client.FileNameAnswer{Hash: file, Name: share.Name})
		case client.SetRequestFileID:
			answers = append(answers, client.FileStatus{Hash: file, Parts: ToStatus(share)})
		case client.RequestSources2:
			sourcesRequest = &r
		case client.AICHFileHashRequest:
			// eMule ignores it once the root travels in the identifier
			// (ListenSocket.cpp:1206).
			if isExt2 || s.caps.HasFileIdentifiers {
				continue
			}
			if root, ok := s.onRootRequest(file, share, out); ok {
				answers = append(answers, root)
			}
		}
	}
	switch {
	case isExt2:
		if share.Tree == nil {
			s.requestTree(file, share, out)
		}
		if len(answers) > 0 {
			out.send(client.MultiPacketAnswerExt2{File: toIdentifier(file, share), Answers: answers})
		}
	case len(answers) > 0:
		out.send(client.MultiPacketAnswer{Hash: file, Answers: answers})
	}
	if sourcesRequest != nil {
		s.onSourcesRequest(*sourcesRequest, shares, now, out)
	}
}

func (s *Session) onHashSetRequest(file wire.Hash, shares shareByHash, out *Output) {
	if share, ok := shares(file); ok && len(share.PartHashes) > 0 {
		out.send(client.HashSetAnswer{Hash: file, Parts: share.PartHashes})
	}
}

// onHashSetRequest2 answers with the MD4 part hashes only; eMule closes on
// a file it does not share (UploadClient.cpp:572-605).
func (s *Session) onHashSetRequest2(p client.HashSetRequest2, shares shareByHash, out *Output) {
	share, ok := shares(p.File.Hash)
	if !ok || !matchFile(p.File, share) {
		out.Close = closeProtocol
		return
	}
	if !p.IsMD4Wanted && !p.IsAICHWanted {
		return
	}
	answer := client.HashSetAnswer2{File: toIdentifier(p.File.Hash, share)}
	if p.IsMD4Wanted {
		answer.Parts = share.PartHashes
	}
	out.send(answer)
}

// matchFile is eMule's CompareRelaxed (FileIdentifier.cpp:75-82): size and
// root count only when both sides know them.
func matchFile(id client.FileIdentifier, share Share) bool {
	if id.Size != 0 && id.Size != uint64(share.Size) {
		return false
	}
	return !id.HasRoot || share.Tree == nil || share.Tree.Root() == id.Root
}

func toIdentifier(file wire.Hash, share Share) client.FileIdentifier {
	id := client.FileIdentifier{Hash: file, Size: uint64(share.Size)}
	if share.Tree != nil {
		id.HasRoot, id.Root = true, share.Tree.Root()
	}
	return id
}

func (s *Session) onUploadRequest(file wire.Hash, shares shareByHash, out *Output) {
	if file == (wire.Hash{}) {
		file = s.up.file
	}
	if _, ok := shares(file); !ok {
		return
	}
	s.up.file = file
	out.add(UploadRequested{File: file, Parts: s.up.parts[file]})
}

func (s *Session) onPartsRequest(file wire.Hash, blocks []piece.Block, shares shareByHash, out *Output) {
	share, ok := shares(file)
	if !s.up.isUploading || !ok {
		return
	}
	s.up.sizes[file] = share.Size
	var fresh []piece.Block
	for _, b := range blocks {
		key := uploadBlock{file, b}
		isFull := len(s.up.blocks)-len(s.up.sent) >= maxUploadBlocks
		if _, seen := s.up.blocks[key]; seen || isFull || b.End > share.Size || b.End-b.Begin > maxRequestSize {
			continue
		}
		s.up.blocks[key] = false
		fresh = append(fresh, b)
	}
	if len(fresh) > 0 {
		out.add(BlocksRequested{File: file, Blocks: fresh})
	}
}

func (s *Session) onUploadCancelled(out *Output) {
	s.up.isUploading = false
	clear(s.up.blocks)
	s.up.sent = nil
	out.add(UploadCancelled{})
}

func toBlocks32(p client.RequestParts) []piece.Block {
	var blocks []piece.Block
	for i := range p.Starts {
		if p.Ends[i] > p.Starts[i] {
			blocks = append(blocks, piece.Block{Begin: int64(p.Starts[i]), End: int64(p.Ends[i])})
		}
	}
	return blocks
}

func toBlocks64(p client.RequestParts64) []piece.Block {
	var blocks []piece.Block
	for i := range p.Starts {
		if p.Ends[i] > p.Starts[i] {
			blocks = append(blocks, piece.Block{Begin: int64(p.Starts[i]), End: int64(p.Ends[i])})
		}
	}
	return blocks
}
