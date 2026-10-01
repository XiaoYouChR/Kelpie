// Package transfer is the state machine of one eD2k file: its sources, its
// piece picker, verification, progress and Durable State. It performs no I/O;
// every reaction returns the actions the engine must perform.
package transfer

import (
	"math/rand/v2"
	"net/netip"
	"slices"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/link"
	"github.com/XiaoYouChR/Kelpie/internal/piece"
	"github.com/XiaoYouChR/Kelpie/internal/store"
	"github.com/XiaoYouChR/Kelpie/internal/wire"
)

type Mode int

const (
	ModeDownload Mode = iota
	ModeSeed
)

type Status int

const (
	StatusRunning Status = iota
	StatusComplete
	StatusFailed
)

type Code string

const (
	CodeDiskFull  Code = "DISK_FULL"
	CodeFileError Code = "FILE_ERROR"
)

// Outcome is the Transfer's state as its Run sees it. Code and Message are
// set only for StatusFailed.
type Outcome struct {
	Status  Status
	Code    Code
	Message string
}

type Progress struct {
	Size         int64
	Received     int64
	DownloadRate int64
	UploadRate   int64
	Uploaded     int64
	Peers        int
	ActivePeers  int
}

type Options struct {
	File link.File
	// Path is the file the Transfer writes; State is dropped when it belongs
	// to another path.
	Path   string
	State  *store.Transfer
	Mode   Mode
	Random *rand.Rand
}

// kadRepublishTime is eMule's KADEMLIAREPUBLISHTIMES (5 hours).
const kadRepublishTime = 5 * time.Hour

type Transfer struct {
	file       link.File
	path       string
	mode       Mode
	created    time.Time
	partHashes []wire.Hash
	picker     *piece.Picker[uint64]
	outcome    Outcome
	uploaded   int64
	download   meter
	upload     meter

	// pending holds actions produced outside a reaction, handed out by the
	// next OnTick.
	pending []Action
	// unhashedParts are written parts waiting for the hash set.
	unhashedParts     []int
	hashSetPeer       uint64
	isHashSetAsked    bool
	hashSetAskedPeers map[uint64]bool

	lastPublish time.Time

	sources         []*source
	peers           map[uint64]*source
	senders         map[uint64]*source
	bannedHashes    map[wire.Hash]bool
	bannedEndpoints map[netip.AddrPort]bool

	// tick is the engine's state as of the last OnTick.
	tick Tick

	lastServerAsk   time.Time
	lastServer      netip.AddrPort
	lastGlobalAsk   time.Time
	nextKadAsk      time.Time
	kadSearches     int
	lastExchangeAsk time.Time
	lastPurge       time.Time
}

// Build creates the Transfer for options.File. Persisted state that does not
// fit the file is dropped and the download starts over; a seed whose state is
// not complete fails at once with FILE_ERROR.
func Build(options Options, now time.Time) *Transfer {
	t := &Transfer{
		file:              options.File,
		path:              options.Path,
		mode:              options.Mode,
		created:           now,
		partHashes:        options.File.PartHashes,
		hashSetAskedPeers: map[uint64]bool{},
		peers:             map[uint64]*source{},
		senders:           map[uint64]*source{},
		bannedHashes:      map[wire.Hash]bool{},
		bannedEndpoints:   map[netip.AddrPort]bool{},
	}
	if state := options.State; state != nil && state.File == options.Path && state.Size == options.File.Size {
		picker, err := piece.BuildPicker[uint64](state.Size, toResumeData(state), options.Random)
		if err == nil {
			t.picker = picker
			t.created = state.Created
			t.uploaded = int64(state.Uploaded)
			if len(t.partHashes) == 0 && t.matchHashSet(state.PartHashes) {
				t.partHashes = state.PartHashes
			}
		}
	}
	if t.picker == nil {
		t.picker, _ = piece.BuildPicker[uint64](options.File.Size, piece.ResumeData{}, options.Random)
	}

	switch {
	case t.picker.IsComplete():
		t.outcome = Outcome{Status: StatusComplete}
		if t.mode == ModeSeed {
			t.outcome = Outcome{Status: StatusRunning}
		}
	case t.mode == ModeSeed:
		t.outcome = Outcome{Status: StatusFailed, Code: CodeFileError, Message: "the file is not complete"}
	default:
		for _, part := range t.picker.WrittenParts() {
			t.pending = append(t.pending, t.requestPartHash(part)...)
		}
		for _, source := range options.File.Sources {
			t.pending = append(t.pending, t.addSource(Source{Endpoint: source}, ChannelLink, now)...)
		}
	}
	return t
}

func toResumeData(state *store.Transfer) piece.ResumeData {
	resume := piece.ResumeData{}
	for part, isVerified := range state.VerifiedParts {
		if isVerified {
			resume.VerifiedParts = append(resume.VerifiedParts, part)
		}
	}
	for _, block := range state.WrittenBlocks {
		partBegin := int64(block.Part) * piece.PartSize
		begin := partBegin + int64(block.Index)*piece.BlockSize
		end := min(begin+piece.BlockSize, partBegin+piece.PartSize, state.Size)
		resume.WrittenBlocks = append(resume.WrittenBlocks, piece.Block{Begin: begin, End: end})
	}
	for _, block := range state.PartialBlocks {
		begin := int64(block.Part)*piece.PartSize + int64(block.Index)*piece.BlockSize
		resume.WrittenBlocks = append(resume.WrittenBlocks, piece.Block{Begin: begin, End: begin + block.Size})
	}
	return resume
}

func (t *Transfer) matchHashSet(hashes []wire.Hash) bool {
	return len(hashes) > 0 && len(hashes) == piece.HashCount(t.file.Size) && piece.BuildFileHash(hashes) == t.file.Hash
}

func (t *Transfer) isRunning() bool {
	return t.outcome.Status == StatusRunning
}

func (t *Transfer) isDownloading() bool {
	return t.isRunning() && t.mode == ModeDownload
}

func (t *Transfer) Outcome() Outcome {
	return t.outcome
}

// ToState exports the Durable State for internal/store.
func (t *Transfer) ToState() store.Transfer {
	resume := t.picker.ToResumeData()
	state := store.Transfer{
		Size:          t.file.Size,
		File:          t.path,
		PartHashes:    t.partHashes,
		VerifiedParts: t.picker.VerifiedParts(),
		WrittenBlocks: []store.Block{},
		PartialBlocks: []store.PartialBlock{},
		Uploaded:      uint64(t.uploaded),
		Created:       t.created,
	}
	for _, block := range resume.WrittenBlocks {
		part, index := block.Part(), int(block.Begin%piece.PartSize/piece.BlockSize)
		if block == t.picker.BlockAt(block.Begin) {
			state.WrittenBlocks = append(state.WrittenBlocks, store.Block{Part: part, Index: index})
		} else {
			state.PartialBlocks = append(state.PartialBlocks, store.PartialBlock{Part: part, Index: index, Size: block.End - block.Begin})
		}
	}
	return state
}

func (t *Transfer) Progress(now time.Time) Progress {
	progress := Progress{
		Size:         t.file.Size,
		Received:     t.picker.WrittenSize(),
		DownloadRate: t.download.rate(now),
		UploadRate:   t.upload.rate(now),
		Uploaded:     t.uploaded,
	}
	for _, s := range t.sources {
		if s.state != stateFailed {
			progress.Peers++
		}
		if s.state == stateDownloading {
			progress.ActivePeers++
		}
	}
	return progress
}

func (t *Transfer) OnUploaded(bytes int64, now time.Time) {
	t.uploaded += bytes
	t.upload.add(now, bytes)
}

// Request picks up to n more blocks to ask a downloading peer for, keeping its
// request pipeline full.
func (t *Transfer) Request(peer uint64, n int) []piece.Block {
	s := t.peers[peer]
	if !t.isDownloading() || s == nil || s.state != stateDownloading {
		return nil
	}
	return t.picker.Request(peer, n)
}

func (t *Transfer) OnPeerParts(peer uint64, parts piece.Set) {
	s := t.peers[peer]
	if t.isDownloading() && s != nil {
		s.hasAnswered = true
		s.isNoNeeded = false
		t.picker.OnPeerParts(peer, parts)
	}
}

// OnBlockReceived takes the data of a requested block, or of the part of it
// that arrived before the peer's slot ended; the rest is asked for later.
func (t *Transfer) OnBlockReceived(peer uint64, block piece.Block, data []byte, now time.Time) []Action {
	s := t.peers[peer]
	if !t.isDownloading() || s == nil {
		return nil
	}
	t.download.add(now, int64(len(data)))
	s.receivedBytes += int64(len(data))
	fresh, ok := t.picker.OnBlockReceived(peer, block)
	if !ok {
		return nil
	}
	return []Action{Write{Block: fresh, Data: data[fresh.Begin-block.Begin:]}}
}

func (t *Transfer) OnBlockWritten(block piece.Block) []Action {
	if !t.isDownloading() || !t.picker.OnBlockWritten(block) {
		return nil
	}
	return t.requestPartHash(block.Part())
}

// OnDiskFailed ends the Transfer after a write or a read for hashing failed.
// The engine classifies the error, keeping this package free of disk.
func (t *Transfer) OnDiskFailed(isDiskFull bool, message string) {
	if !t.isRunning() {
		return
	}
	code := CodeFileError
	if isDiskFull {
		code = CodeDiskFull
	}
	t.outcome = Outcome{Status: StatusFailed, Code: code, Message: message}
}

func (t *Transfer) requestPartHash(part int) []Action {
	if _, ok := t.expectedHash(part); !ok {
		t.unhashedParts = append(t.unhashedParts, part)
		return nil
	}
	begin := int64(part) * piece.PartSize
	return []Action{HashPart{Part: part, Begin: begin, End: min(begin+piece.PartSize, t.file.Size)}}
}

// expectedHash follows piece.HashCount: a file below PartSize is checked
// against its file hash.
func (t *Transfer) expectedHash(part int) (wire.Hash, bool) {
	if t.file.Size < piece.PartSize {
		return t.file.Hash, true
	}
	if len(t.partHashes) == 0 {
		return wire.Hash{}, false
	}
	return t.partHashes[part], true
}

// OnPartHashed verifies a part. A mismatch discards the part and bans every
// peer that sent a block of it.
func (t *Transfer) OnPartHashed(part int, hash wire.Hash, now time.Time) []Action {
	if !t.isDownloading() {
		return nil
	}
	if expected, _ := t.expectedHash(part); hash == expected {
		t.picker.OnPartVerified(part)
		if t.picker.IsComplete() {
			t.outcome = Outcome{Status: StatusComplete}
		}
		return nil
	}
	var actions []Action
	for _, peer := range t.picker.OnPartFailed(part) {
		actions = append(actions, t.removeCorrupt(peer, now)...)
	}
	return actions
}

// OnHashSet accepts the part hashes a peer sent if they add up to the file
// hash, and starts hashing the parts that waited for them.
func (t *Transfer) OnHashSet(peer uint64, hashes []wire.Hash) []Action {
	if peer == t.hashSetPeer {
		t.isHashSetAsked = false
	}
	if !t.isDownloading() || len(t.partHashes) > 0 || !t.matchHashSet(hashes) {
		return nil
	}
	t.partHashes = slices.Clone(hashes)
	var actions []Action
	parts := t.unhashedParts
	t.unhashedParts = nil
	for _, part := range parts {
		actions = append(actions, t.requestPartHash(part)...)
	}
	return actions
}

func (t *Transfer) needsHashSet() bool {
	return t.file.Size >= piece.PartSize && len(t.partHashes) == 0
}

func (t *Transfer) requestHashSet() []Action {
	if !t.needsHashSet() || t.isHashSetAsked {
		return nil
	}
	for _, s := range t.sources {
		if s.isConnected && !t.hashSetAskedPeers[s.peer] {
			t.hashSetPeer = s.peer
			t.isHashSetAsked = true
			t.hashSetAskedPeers[s.peer] = true
			return []Action{RequestHashSet{Peer: s.peer}}
		}
	}
	return nil
}

func (t *Transfer) runPublish(now time.Time) []Action {
	parts := t.picker.VerifiedParts()
	if parts.Count() == 0 || !t.lastPublish.IsZero() && now.Sub(t.lastPublish) < kadRepublishTime {
		return nil
	}
	t.lastPublish = now
	return []Action{Publish{Parts: parts}}
}
