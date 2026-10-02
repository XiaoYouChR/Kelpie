// Package transfer is the state machine of one eD2k file: its sources, its
// piece picker, verification, progress and Durable State. It performs no I/O;
// every reaction returns the actions the engine must perform.
//
// A method that needs the time takes it as now, OnTick as Tick.Now; none
// reads the time of the last Tick, which is up to a tick old.
package transfer

import (
	"math/rand/v2"
	"net/netip"
	"slices"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/link"
	"github.com/XiaoYouChR/Kelpie/internal/piece"
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
	// StatusFailed is a file error.
	StatusFailed
	StatusDiskFull
)

// Outcome is the Transfer's state as its Run sees it. Message says why it
// failed.
type Outcome struct {
	Status  Status
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

// State is the Transfer's Durable State, field for field store.Transfer
// (which describes them), so the engine converts one to the other.
type State struct {
	Size          int64
	File          string
	PartHashes    []wire.Hash
	VerifiedParts piece.Set
	WrittenBlocks []piece.Block
	Uploaded      uint64
	Created       time.Time
}

type Options struct {
	File link.File
	// Path is the file the Transfer writes. The engine passes only State
	// saved for this path.
	Path   string
	State  *State
	Mode   Mode
	Random *rand.Rand
}

type Transfer struct {
	file       link.File
	path       string
	mode       Mode
	created    time.Time
	partHashes []wire.Hash
	picker     *picker
	outcome    Outcome
	uploaded   int64
	download   meter
	upload     meter

	// unhashedParts are written parts waiting for the hash set.
	unhashedParts []int
	// hashSetPeer is the peer asked for the hash set; 0 when none is.
	hashSetPeer       uint64
	hashSetAskedPeers map[uint64]bool
	aich              aichState

	sources []*source
	peers   map[uint64]*source
	senders map[uint64]*source
	// bannedHashes and bannedEndpoints map a banned source to when its ban
	// ends.
	bannedHashes    map[wire.Hash]time.Time
	bannedEndpoints map[netip.AddrPort]time.Time

	// tick is the engine's state as of the last OnTick.
	tick Tick

	lastExchangeAsk time.Time
	lastPurge       time.Time
}

// Build creates the Transfer for options.File with the actions to start it:
// hashing parts written before a restart, and the link's sources. Persisted
// state that does not fit the file is dropped and the download starts over;
// a seed whose state is not complete fails at once with a file error.
func Build(options Options, now time.Time) (*Transfer, []Action) {
	t := &Transfer{
		file:              options.File,
		path:              options.Path,
		mode:              options.Mode,
		created:           now,
		partHashes:        options.File.PartHashes,
		hashSetAskedPeers: map[uint64]bool{},
		peers:             map[uint64]*source{},
		senders:           map[uint64]*source{},
		bannedHashes:      map[wire.Hash]time.Time{},
		bannedEndpoints:   map[netip.AddrPort]time.Time{},
		aich:              buildAICHState(options.File.AICHHash, options.Random),
	}
	if state := options.State; state != nil && state.Size == options.File.Size {
		picker, err := buildPicker(state.Size, state.VerifiedParts, state.WrittenBlocks, options.Random)
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
		t.picker, _ = buildPicker(options.File.Size, nil, nil, options.Random)
	}

	var actions []Action
	switch {
	case t.isComplete():
		t.outcome = Outcome{Status: StatusComplete}
		if t.mode == ModeSeed {
			t.outcome = Outcome{Status: StatusRunning}
		}
	case t.mode == ModeSeed:
		t.outcome = Outcome{Status: StatusFailed, Message: "the file is not complete"}
	default:
		for _, part := range t.picker.writtenParts() {
			actions = append(actions, t.requestPartHash(part)...)
		}
		for _, source := range options.File.Sources {
			actions = append(actions, t.addSource(Source{Endpoint: source}, ChannelLink, now)...)
		}
	}
	return t, actions
}

func (t *Transfer) matchHashSet(hashes []wire.Hash) bool {
	return len(hashes) > 0 && len(hashes) == piece.HashCount(t.file.Size) && piece.BuildFileHash(hashes) == t.file.Hash
}

func (t *Transfer) isComplete() bool {
	return t.picker.verifiedParts().IsFull()
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

func (t *Transfer) ToState() State {
	return State{
		Size:          t.file.Size,
		File:          t.path,
		PartHashes:    t.partHashes,
		VerifiedParts: t.picker.verifiedParts(),
		WrittenBlocks: t.picker.writtenBlocks(),
		Uploaded:      uint64(t.uploaded),
		Created:       t.created,
	}
}

func (t *Transfer) Progress(now time.Time) Progress {
	progress := Progress{
		Size:         t.file.Size,
		Received:     t.picker.writtenSize(),
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
// request pipeline full. Near completion, a peer left with nothing to ask
// for takes over the blocks of a source sending at less than half its rate,
// whose slot is given up with a Close (aMule 3.1.0 endgame,
// DownloadClient.cpp:624-697, PartFile.cpp:4709-4734): a block is never
// asked of two peers, whose duplicate data would waste the uploader's
// bandwidth.
func (t *Transfer) Request(peer uint64, n int, now time.Time) ([]piece.Block, []Action) {
	s := t.peers[peer]
	if !t.isDownloading() || s == nil || s.state != stateDownloading {
		return nil, nil
	}
	blocks := t.picker.request(peer, n)
	if len(blocks) > 0 || t.picker.isRequesting(peer) || !t.isNearCompletion() {
		return blocks, nil
	}
	slow := t.slowerSource(s, now)
	if slow == nil {
		return nil, nil
	}
	// aMule leaves the cancelled source DS_NONEEDEDPARTS, so it is reasked
	// at twice the interval.
	slow.isNoNeeded = true
	t.picker.cancel(slow.peer)
	return t.picker.request(peer, n), []Action{Close{Peer: slow.peer, Reason: "slower source"}}
}

// isNearCompletion is aMule's endgame: a file of more than four parts with
// at most four parts' worth of data missing.
func (t *Transfer) isNearCompletion() bool {
	return piece.PartCount(t.file.Size) > 4 && t.file.Size-t.picker.writtenSize() <= 4*piece.PartSize
}

// slowerSource is a downloading source sending at less than half the rate
// of fast and asked for a block in a part fast has (aMule
// GetSlowerDownloadingClient, DROP_FACTOR 2).
func (t *Transfer) slowerSource(fast *source, now time.Time) *source {
	rate := fast.download.rate(now)
	for _, s := range t.sources {
		if s != fast && s.state == stateDownloading && t.isConnected(s) &&
			2*s.download.rate(now) < rate && t.picker.hasBlocksFor(s.peer, fast.peer) {
			return s
		}
	}
	return nil
}

func (t *Transfer) OnPeerParts(peer uint64, parts piece.Set) {
	s := t.peers[peer]
	if t.isDownloading() && s != nil {
		if s.state == stateAsking {
			s.state = stateQueued
		}
		s.isNoNeeded = false
		t.picker.onPeerParts(peer, parts)
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
	s.download.add(now, int64(len(data)))
	s.receivedBytes += int64(len(data))
	fresh, ok := t.picker.onBlockReceived(peer, block)
	if !ok {
		return nil
	}
	return []Action{Write{Block: fresh, Data: data[fresh.Begin-block.Begin:]}}
}

func (t *Transfer) OnBlockWritten(block piece.Block) []Action {
	if !t.isDownloading() || !t.picker.onBlockWritten(block) {
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
	t.outcome = Outcome{Status: StatusFailed, Message: message}
	if isDiskFull {
		t.outcome.Status = StatusDiskFull
	}
}

func (t *Transfer) requestPartHash(part int) []Action {
	if _, ok := t.expectedHash(part); !ok {
		t.unhashedParts = append(t.unhashedParts, part)
		return nil
	}
	return []Action{HashPart{Part: part}}
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

// OnPartHashed verifies a part. A mismatch starts an AICH repair of the
// part, or when none is possible discards it.
func (t *Transfer) OnPartHashed(part int, hash wire.Hash, now time.Time) []Action {
	if !t.isDownloading() {
		return nil
	}
	if expected, _ := t.expectedHash(part); hash == expected {
		for peer, bytes := range t.picker.onPartVerified(part) {
			if s := t.senders[peer]; s != nil {
				s.goodBytes += bytes
			}
		}
		if t.isComplete() {
			t.outcome = Outcome{Status: StatusComplete}
		}
		return nil
	}
	return t.requestRecovery(part, now)
}

// OnHashSet accepts the part hashes a peer sent if they add up to the file
// hash, and starts hashing the parts that waited for them.
func (t *Transfer) OnHashSet(peer uint64, hashes []wire.Hash) []Action {
	if peer == t.hashSetPeer {
		t.hashSetPeer = 0
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
	if !t.needsHashSet() || t.hashSetPeer != 0 {
		return nil
	}
	for _, s := range t.sources {
		if t.isConnected(s) && !t.hashSetAskedPeers[s.peer] {
			t.hashSetPeer = s.peer
			t.hashSetAskedPeers[s.peer] = true
			return []Action{RequestHashSet{Peer: s.peer}}
		}
	}
	return nil
}
