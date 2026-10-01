package transfer

import (
	"fmt"
	"math/rand/v2"
	"slices"
	"sort"

	"github.com/XiaoYouChR/Kelpie/internal/piece"
)

func blockAt(size, offset int64) piece.Block {
	return piece.BlockOf(size, int(offset/piece.PartSize), int(offset%piece.PartSize/piece.BlockSize))
}

// maxRequesters bounds endgame duplication: one original request plus one copy.
const maxRequesters = 2

// blockState tracks a block byte by byte, as aMule keeps byte-granular gaps
// (DownloadClient.cpp:835-848), so a block cut off when a slot ends is
// finished by asking only for its missing tail. Data arrives in order, so
// what is received is always a prefix.
type blockState struct {
	received   int64
	written    int64
	requesters []uint64
	senders    []uint64
}

type partState struct {
	isVerified bool
	// blocks is nil until the part is first touched and again after it is
	// verified or reset.
	blocks []blockState
}

// picker decides which blocks of the file to request from which peer, named
// by its connection id.
type picker struct {
	size         int64
	random       *rand.Rand
	parts        []partState
	availability []int
	peerParts    map[uint64]piece.Set
}

// buildPicker restores the parts verified and the blocks written before a
// restart, as aMule's .part.met keeps its gap list. A written block is a
// whole block or, for a block cut off when a slot ended, its leading piece
// [Begin, Begin+n).
func buildPicker(size int64, verified piece.Set, written []piece.Block, random *rand.Rand) (*picker, error) {
	p := &picker{
		size:         size,
		random:       random,
		parts:        make([]partState, piece.PartCount(size)),
		availability: make([]int, piece.PartCount(size)),
		peerParts:    map[uint64]piece.Set{},
	}
	for part, isVerified := range verified {
		if !isVerified {
			continue
		}
		if part >= len(p.parts) {
			return nil, fmt.Errorf("resume data: part %d out of range", part)
		}
		p.parts[part].isVerified = true
	}
	for _, block := range written {
		whole := blockAt(size, block.Begin)
		if block.Begin < 0 || block.Begin >= size || whole.Begin != block.Begin || block.End <= block.Begin || block.End > whole.End {
			return nil, fmt.Errorf("resume data: [%d, %d) is not the start of a block of this file", block.Begin, block.End)
		}
		if !p.parts[block.Part()].isVerified {
			state := p.blockState(block)
			state.received = block.End - block.Begin
			state.written = state.received
		}
	}
	return p, nil
}

// writtenBlocks lists what buildPicker takes back after a restart: the
// written bytes of parts not yet verified.
func (p *picker) writtenBlocks() []piece.Block {
	var written []piece.Block
	for i, part := range p.parts {
		// Disk workers may finish writes out of order, so a block's
		// received prefix is on disk only once every write of it is done.
		for j, state := range part.blocks {
			if state.written > 0 && state.written == state.received {
				block := piece.BlockOf(p.size, i, j)
				written = append(written, piece.Block{Begin: block.Begin, End: block.Begin + state.written})
			}
		}
	}
	return written
}

func (p *picker) blockState(b piece.Block) *blockState {
	part := &p.parts[b.Part()]
	if part.blocks == nil {
		part.blocks = make([]blockState, piece.BlockCount(p.size, b.Part()))
	}
	return &part.blocks[b.Index()]
}

func (p *picker) verifiedParts() piece.Set {
	set := make(piece.Set, len(p.parts))
	for i, part := range p.parts {
		set[i] = part.isVerified
	}
	return set
}

// writtenParts lists parts whose blocks are all on disk but whose hash has not
// been checked yet, as happens after a restart.
func (p *picker) writtenParts() []int {
	var parts []int
	for i := range p.parts {
		if p.isWritten(i) {
			parts = append(parts, i)
		}
	}
	return parts
}

func (p *picker) isWritten(part int) bool {
	state := p.parts[part]
	if state.isVerified || state.blocks == nil {
		return false
	}
	for j, block := range state.blocks {
		if b := piece.BlockOf(p.size, part, j); block.written != b.End-b.Begin {
			return false
		}
	}
	return true
}

func (p *picker) writtenSize() int64 {
	var written int64
	for i, part := range p.parts {
		if part.isVerified {
			partRange := piece.PartRange(p.size, i)
			written += partRange.End - partRange.Begin
			continue
		}
		for _, block := range part.blocks {
			written += block.written
		}
	}
	return written
}

// onPeerParts replaces what the picker knows a peer has.
func (p *picker) onPeerParts(peer uint64, parts piece.Set) {
	p.removeAvailability(peer)
	p.peerParts[peer] = slices.Clone(parts)
	for i, has := range parts {
		if has {
			p.availability[i]++
		}
	}
}

func (p *picker) onPeerGone(peer uint64) {
	p.cancel(peer)
	p.removeAvailability(peer)
	delete(p.peerParts, peer)
}

func (p *picker) removeAvailability(peer uint64) {
	for i, has := range p.peerParts[peer] {
		if has {
			p.availability[i]--
		}
	}
}

// cancel releases every block the peer was asked for and has not delivered,
// so other peers can take them.
func (p *picker) cancel(peer uint64) {
	for i := range p.parts {
		for j := range p.parts[i].blocks {
			block := &p.parts[i].blocks[j]
			block.requesters = slices.DeleteFunc(block.requesters, func(r uint64) bool { return r == peer })
		}
	}
}

// request picks up to n blocks to ask the peer for and records them as
// requested; a partly received block is asked for from where it stops. It
// prefers parts already in progress, then the rarest parts, breaking ties at
// random. Only when no block is left unrequested anywhere it can be fetched
// from does it hand out blocks already requested from one other peer
// (endgame).
func (p *picker) request(peer uint64, n int) []piece.Block {
	parts := p.candidateParts(peer)
	picked := p.addRequests(peer, parts, n, nil, func(requesters []uint64) bool { return len(requesters) == 0 })
	if len(picked) == n || p.hasUnrequestedBlock() {
		return picked
	}
	return p.addRequests(peer, parts, n, picked, func(requesters []uint64) bool {
		return len(requesters) < maxRequesters && !slices.Contains(requesters, peer)
	})
}

// addRequests fills picked up to n with the missing rest of each block of parts
// whose requesters canJoin accepts, and records peer as requesting it.
func (p *picker) addRequests(peer uint64, parts []int, n int, picked []piece.Block, canJoin func(requesters []uint64) bool) []piece.Block {
	for _, part := range parts {
		for index := range piece.BlockCount(p.size, part) {
			if len(picked) == n {
				return picked
			}
			b := piece.BlockOf(p.size, part, index)
			state := p.blockState(b)
			if state.received < b.End-b.Begin && canJoin(state.requesters) {
				state.requesters = append(state.requesters, peer)
				picked = append(picked, piece.Block{Begin: b.Begin + state.received, End: b.End})
			}
		}
	}
	return picked
}

func (p *picker) candidateParts(peer uint64) []int {
	var parts []int
	for i, has := range p.peerParts[peer] {
		if has && !p.parts[i].isVerified {
			parts = append(parts, i)
		}
	}
	p.random.Shuffle(len(parts), func(i, j int) { parts[i], parts[j] = parts[j], parts[i] })
	sort.SliceStable(parts, func(i, j int) bool {
		a, b := parts[i], parts[j]
		if isStartedA, isStartedB := p.isStarted(a), p.isStarted(b); isStartedA != isStartedB {
			return isStartedA
		}
		return p.availability[a] < p.availability[b]
	})
	return parts
}

func (p *picker) isStarted(part int) bool {
	for _, block := range p.parts[part].blocks {
		if block.received > 0 || len(block.requesters) > 0 {
			return true
		}
	}
	return false
}

func (p *picker) hasUnrequestedBlock() bool {
	for i, part := range p.parts {
		if part.isVerified || p.availability[i] == 0 {
			continue
		}
		if part.blocks == nil {
			return true
		}
		for j, block := range part.blocks {
			if b := piece.BlockOf(p.size, i, j); block.received < b.End-b.Begin && len(block.requesters) == 0 {
				return true
			}
		}
	}
	return false
}

// onBlockReceived records that the data of b, a block or a leading piece of
// what was requested of it, arrived from peer. It returns the bytes of b that
// are new and should be written; false when another peer delivered them first
// or the part is already verified. The block stays requested until it is
// complete or the peer's requests are cancelled.
func (p *picker) onBlockReceived(peer uint64, b piece.Block) (piece.Block, bool) {
	if p.parts[b.Part()].isVerified {
		return piece.Block{}, false
	}
	whole := blockAt(p.size, b.Begin)
	state := p.blockState(b)
	next := whole.Begin + state.received
	if b.Begin > next || b.End <= next {
		return piece.Block{}, false
	}
	state.received = b.End - whole.Begin
	if !slices.Contains(state.senders, peer) {
		state.senders = append(state.senders, peer)
	}
	if b.End == whole.End {
		state.requesters = nil
	}
	return piece.Block{Begin: next, End: b.End}, true
}

// onBlockWritten records that b, as returned by onBlockReceived, is on disk
// and reports whether its whole part is now written and ready to be hashed.
func (p *picker) onBlockWritten(b piece.Block) bool {
	p.blockState(b).written += b.End - b.Begin
	return p.isWritten(b.Part())
}

func (p *picker) onPartVerified(part int) {
	p.parts[part] = partState{isVerified: true}
}

// onPartFailed discards a part whose hash did not match and returns the peers
// that sent any of its blocks, so the caller can ban the corrupt sender.
func (p *picker) onPartFailed(part int) []uint64 {
	senders := addSenders(nil, p.parts[part].blocks)
	p.parts[part] = partState{}
	return senders
}

// senders lists the peers that sent any block of a part not yet verified.
func (p *picker) senders() []uint64 {
	var senders []uint64
	for _, part := range p.parts {
		senders = addSenders(senders, part.blocks)
	}
	return senders
}

func addSenders(senders []uint64, blocks []blockState) []uint64 {
	for _, block := range blocks {
		for _, sender := range block.senders {
			if !slices.Contains(senders, sender) {
				senders = append(senders, sender)
			}
		}
	}
	return senders
}

// onBlockFailed discards one whole block of a part that failed its hash
// check, so only that block is requested again, and returns its senders.
func (p *picker) onBlockFailed(b piece.Block) []uint64 {
	state := p.blockState(b)
	senders := state.senders
	*state = blockState{}
	return senders
}
