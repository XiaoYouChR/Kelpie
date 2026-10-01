package peer

import (
	"bytes"
	"compress/zlib"
	"io"
	"slices"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/piece"
	"github.com/XiaoYouChR/Kelpie/internal/wire"
	"github.com/XiaoYouChR/Kelpie/internal/wire/client"
)

// OLD_MAX_EMULE_FILE_SIZE: larger files need the 64-bit part packets.
const largeFileSize = 4_290_048_000

// downloadState is the download role. Every added file is probed for the
// peer's parts, but the upload slot, which eD2k grants per client and not per
// file, is asked for one started file at a time.
type downloadState struct {
	files         map[wire.Hash]*download
	started       wire.Hash
	isStarted     bool
	isStartSent   bool
	isSlotGranted bool
	lastData      time.Time
}

type download struct {
	size               int64
	parts              piece.Set
	isRequested        bool
	isHashSetWanted    bool
	isHashSetRequested bool
	peerParts          piece.Set
	inFlight           []*inFlight
}

type inFlight struct {
	block piece.Block
	data  []byte
	// prefix counts the bytes received from the block's start without a gap;
	// ranges holds what arrived beyond a gap.
	prefix int64
	ranges []piece.Block
	packed []byte
}

// Add asks the peer about file, of which we have parts. Before the
// handshake completes the request waits for it.
func (s *Session) Add(file wire.Hash, size int64, parts piece.Set) Output {
	var out Output
	if s.down.files[file] != nil {
		return out
	}
	d := &download{size: size, parts: parts}
	s.down.files[file] = d
	if s.isHandshaken {
		s.sendFileRequest(file, d, &out)
	}
	return out
}

// Remove forgets file, cancelling its slot if it holds one. The engine
// releases the blocks it had requested.
func (s *Session) Remove(file wire.Hash) Output {
	var out Output
	if s.down.isStarted && s.down.started == file && s.down.isSlotGranted {
		out.send(client.CancelTransfer{})
	}
	s.removeFile(file, &out)
	return out
}

// Start asks the peer for an upload slot for file once its parts are known. Starting another file gives up the slot of
// the previous one.
func (s *Session) Start(file wire.Hash) Output {
	var out Output
	if s.down.files[file] == nil || s.down.isStarted && s.down.started == file {
		return out
	}
	if s.down.isStarted {
		if s.down.isSlotGranted {
			out.send(client.CancelTransfer{})
			s.down.isSlotGranted = false
		}
		s.cancelInFlight(s.down.started, &out)
		s.down.isStartSent = false
	}
	s.down.started, s.down.isStarted = file, true
	s.runStarted(&out)
	return out
}

// RequestHashSet asks the peer for file's part hashes once it has told its
// part status. aMule asks one source per file, right after its OP_FILESTATUS,
// and asks every other source for a slot meanwhile (DownloadClient.cpp:467-482);
// the transfer picks that source.
func (s *Session) RequestHashSet(file wire.Hash) Output {
	var out Output
	if d := s.down.files[file]; d != nil {
		d.isHashSetWanted = true
		s.sendHashSetRequest(file, d, &out)
	}
	return out
}

func (s *Session) sendHashSetRequest(file wire.Hash, d *download, out *Output) {
	if d.isHashSetWanted && !d.isHashSetRequested && d.peerParts != nil {
		d.isHashSetRequested = true
		out.send(client.HashSetRequest{Hash: file})
	}
}

// Request sends block requests for file, three ranges per packet as the
// protocol allows. The engine passes at most the Count of the last
// BlocksWanted.
func (s *Session) Request(file wire.Hash, blocks []piece.Block) Output {
	var out Output
	d := s.down.files[file]
	if d == nil || !s.down.isSlotGranted || s.down.started != file {
		return out
	}
	// aMule gives back a slot that yields nothing to request
	// (DownloadClient.cpp:646-689).
	if len(blocks) == 0 && len(d.inFlight) == 0 {
		out.send(client.CancelTransfer{})
		s.stopSlot(&out)
		return out
	}
	for _, b := range blocks {
		d.inFlight = append(d.inFlight, &inFlight{block: b})
	}
	for group := range slices.Chunk(blocks, 3) {
		if d.size > largeFileSize {
			p := client.RequestParts64{Hash: file}
			for i, b := range group {
				p.Starts[i], p.Ends[i] = uint64(b.Begin), uint64(b.End)
			}
			out.send(p)
			continue
		}
		p := client.RequestParts{Hash: file}
		for i, b := range group {
			p.Starts[i], p.Ends[i] = uint32(b.Begin), uint32(b.End)
		}
		out.send(p)
	}
	return out
}

// Stop gives up every block in flight on a closing connection.
func (s *Session) Stop() Output {
	var out Output
	if s.down.isStarted {
		s.cancelInFlight(s.down.started, &out)
	}
	return out
}

func (s *Session) removeFile(file wire.Hash, out *Output) {
	s.cancelInFlight(file, out)
	delete(s.down.files, file)
	delete(s.sx.asked, file)
	if s.down.isStarted && s.down.started == file {
		s.down = downloadState{files: s.down.files}
	}
}

func (s *Session) sendFileRequests(out *Output) {
	files := make([]wire.Hash, 0, len(s.down.files))
	for file := range s.down.files {
		files = append(files, file)
	}
	slices.SortFunc(files, func(a, b wire.Hash) int { return bytes.Compare(a[:], b[:]) })
	for _, file := range files {
		s.sendFileRequest(file, s.down.files[file], out)
	}
}

func (s *Session) sendFileRequest(file wire.Hash, d *download, out *Output) {
	if d.size > largeFileSize && !s.caps.HasLargeFiles {
		s.removeFile(file, out)
		out.add(FileRejected{File: file})
		return
	}
	d.isRequested = true
	request := client.FileRequest{Hash: file}
	// eMule reads these extensions by the version the sender advertised,
	// which for us is client.ExtendedRequestsVersion.
	if s.caps.ExtendedRequests > 0 {
		request.HasParts, request.Parts = true, toBitfield(d.parts, d.size)
		request.HasCompleteSources = true
	}
	requests := []wire.Packet{request}
	// A single-part file needs no status: the peer that names it has it all.
	if piece.PartCount(d.size) > 1 {
		requests = append(requests, client.SetRequestFileID{Hash: file})
	}
	switch {
	case s.caps.HasExtMultiPacket:
		out.send(client.MultiPacketExt{Hash: file, Size: uint64(d.size), Requests: requests})
	case s.caps.HasMultiPacket:
		out.send(client.MultiPacket{Hash: file, Requests: requests})
	default:
		out.send(requests...)
	}
}

func (s *Session) onMultiPacketAnswer(p client.MultiPacketAnswer, out *Output) {
	for _, answer := range p.Answers {
		switch a := answer.(type) {
		case client.FileNameAnswer:
			s.onFileName(a.Hash, out)
		case client.FileStatus:
			s.onFileStatus(a, out)
		}
	}
}

func (s *Session) onFileName(file wire.Hash, out *Output) {
	d := s.down.files[file]
	if d == nil || d.peerParts != nil || piece.PartCount(d.size) > 1 {
		return
	}
	s.setPeerParts(file, d, piece.BuildFullSet(1), out)
}

func (s *Session) onFileStatus(p client.FileStatus, out *Output) {
	d := s.down.files[p.Hash]
	if d == nil {
		return
	}
	parts, ok := toPartSet(p.Parts, d.size)
	if !ok {
		out.Close = CloseProtocol
		return
	}
	s.setPeerParts(p.Hash, d, parts, out)
}

func (s *Session) setPeerParts(file wire.Hash, d *download, parts piece.Set, out *Output) {
	d.peerParts = parts
	out.add(StatusReceived{File: file, Parts: parts})
	s.sendHashSetRequest(file, d, out)
	s.runStarted(out)
}

func (s *Session) onHashSet(p client.HashSetAnswer, out *Output) {
	d := s.down.files[p.Hash]
	if d == nil || !d.isHashSetRequested || !d.isHashSetWanted {
		return
	}
	d.isHashSetWanted = false
	// aMule drops a client that sends a wrong hash set (DownloadClient.cpp:584-585).
	if len(p.Parts) != piece.HashCount(d.size) || piece.BuildFileHash(p.Parts) != p.Hash {
		out.Close = CloseProtocol
		return
	}
	out.add(HashSetReceived{File: p.Hash, Hashes: p.Parts})
}

func (s *Session) onNoFile(file wire.Hash, out *Output) {
	if s.down.files[file] == nil {
		return
	}
	s.removeFile(file, out)
	out.add(FileRejected{File: file})
}

// runStarted moves the started file on as far as what we know allows: ask for
// a slot, or once granted, ask the engine for blocks. A peer with no part we
// still need is not asked for a slot (aMule DS_NONEEDEDPARTS,
// DownloadClient.cpp:459-466); the transfer keeps it as a queued source.
func (s *Session) runStarted(out *Output) {
	if !s.down.isStarted {
		return
	}
	d := s.down.files[s.down.started]
	if d.peerParts == nil {
		return
	}
	switch {
	case s.down.isSlotGranted:
		s.requestBlocks(d, out)
	case !s.down.isStartSent && hasNeededPart(d):
		s.down.isStartSent = true
		out.send(client.StartUploadRequest{Hash: s.down.started})
	}
}

func hasNeededPart(d *download) bool {
	for i, has := range d.peerParts {
		if has && (i >= len(d.parts) || !d.parts[i]) {
			return true
		}
	}
	return false
}

func (s *Session) requestBlocks(d *download, out *Output) {
	if room := s.cfg.Pipeline - len(d.inFlight); room > 0 {
		out.add(BlocksWanted{File: s.down.started, Count: room})
	}
}

func (s *Session) onQueueRank(rank uint32, out *Output) {
	s.stopSlot(out)
	if s.down.isStarted {
		out.add(Queued{File: s.down.started, Rank: rank})
	}
}

func (s *Session) onSlotGranted(now time.Time, out *Output) {
	if s.down.isSlotGranted {
		return
	}
	s.down.isSlotGranted = true
	s.down.lastData = now
	var file wire.Hash
	if s.down.isStarted {
		file = s.down.started
	}
	out.add(SlotGranted{File: file})
	s.runStarted(out)
}

func (s *Session) stopSlot(out *Output) {
	if !s.down.isSlotGranted {
		return
	}
	s.down.isSlotGranted = false
	s.down.isStartSent = false
	var file wire.Hash
	if s.down.isStarted {
		file = s.down.started
		s.cancelInFlight(file, out)
	}
	out.add(SlotRevoked{File: file})
}

func (s *Session) hasBlocksInFlight() bool {
	return s.down.isStarted && len(s.down.files[s.down.started].inFlight) > 0
}

func (s *Session) onPart(file wire.Hash, start int64, data []byte, now time.Time, out *Output) {
	d := s.down.files[file]
	if d == nil {
		return
	}
	end := start + int64(len(data))
	i := slices.IndexFunc(d.inFlight, func(f *inFlight) bool { return f.block.Begin <= start && end <= f.block.End })
	if i < 0 {
		return
	}
	s.down.lastData = now
	f := d.inFlight[i]
	if f.data == nil {
		f.data = make([]byte, f.block.End-f.block.Begin)
	}
	copy(f.data[start-f.block.Begin:], data)
	f.ranges = append(f.ranges, piece.Block{Begin: start, End: end})
	f.updatePrefix()
	if f.prefix == int64(len(f.data)) {
		s.onBlockFilled(file, d, i, out)
	}
}

func (f *inFlight) updatePrefix() {
	for isGrown := true; isGrown; {
		isGrown = false
		end := f.block.Begin + f.prefix
		for _, r := range f.ranges {
			if r.Begin <= end && end < r.End {
				end, isGrown = r.End, true
			}
		}
		f.prefix = end - f.block.Begin
	}
	f.ranges = slices.DeleteFunc(f.ranges, func(r piece.Block) bool { return r.End <= f.block.Begin+f.prefix })
}

// cancelInFlight gives up file's block requests and hands over what arrived
// of each block from its start: aMule writes every packet as it comes and
// later asks only for the gaps (DownloadClient.cpp:835-848), and inflates a
// compressed block as its packets arrive.
func (s *Session) cancelInFlight(file wire.Hash, out *Output) {
	d := s.down.files[file]
	if d == nil {
		return
	}
	for _, f := range d.inFlight {
		if data := toReceived(f); len(data) > 0 {
			out.add(BlockReceived{File: file, Block: piece.Block{Begin: f.block.Begin, End: f.block.Begin + int64(len(data))}, Data: data})
		}
	}
	d.inFlight = nil
}

// toReceived is the block's data received without a gap from its start; for
// a compressed block, what its zlib stream so far inflates to.
func toReceived(f *inFlight) []byte {
	if f.packed == nil {
		return f.data[:f.prefix]
	}
	size := f.block.End - f.block.Begin
	plain, _ := toInflated(f.packed, size)
	return plain[:min(int64(len(plain)), size)]
}

// onCompressedPart collects one block's zlib stream, which the uploader
// splits across packets that all carry the block's start and packed size.
func (s *Session) onCompressedPart(file wire.Hash, start int64, packedSize uint32, data []byte, now time.Time, out *Output) {
	d := s.down.files[file]
	if d == nil {
		return
	}
	i := slices.IndexFunc(d.inFlight, func(f *inFlight) bool { return f.block.Begin == start })
	if i < 0 {
		return
	}
	s.down.lastData = now
	f := d.inFlight[i]
	f.packed = append(f.packed, data...)
	if len(f.packed) < int(packedSize) {
		return
	}
	size := f.block.End - f.block.Begin
	plain, err := toInflated(f.packed, size)
	if err != nil || int64(len(plain)) != size {
		out.Close = CloseProtocol
		return
	}
	f.data = plain
	s.onBlockFilled(file, d, i, out)
}

func (s *Session) onBlockFilled(file wire.Hash, d *download, i int, out *Output) {
	f := d.inFlight[i]
	d.inFlight = slices.Delete(d.inFlight, i, i+1)
	out.add(BlockReceived{File: file, Block: f.block, Data: f.data})
	if s.down.isSlotGranted && s.down.started == file {
		s.requestBlocks(d, out)
	}
}

func toInflated(packed []byte, size int64) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(packed))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(io.LimitReader(r, size+1))
}

// toPartSet reads OP_FILESTATUS, whose count is eMule's ED2K part count,
// size/PARTSIZE+1, one more than PartCount for a file of whole parts. Zero
// parts means the peer has the complete file.
func toPartSet(f wire.Bitfield, size int64) (piece.Set, bool) {
	count := piece.PartCount(size)
	if f.Len() == 0 {
		return piece.BuildFullSet(count), true
	}
	if f.Len() != int(size/piece.PartSize)+1 {
		return nil, false
	}
	parts := make(piece.Set, count)
	for i := range parts {
		parts[i] = f.Has(i)
	}
	return parts, true
}

func toBitfield(parts piece.Set, size int64) wire.Bitfield {
	have := make([]bool, size/piece.PartSize+1)
	copy(have, parts)
	return wire.ToBitfield(have)
}
