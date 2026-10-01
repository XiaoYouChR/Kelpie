package piece

import (
	"fmt"
	"math/rand/v2"
	"slices"
	"sort"
)

// Block is the byte range [Begin, End) of one block inside one part, or of
// the part of a block that is still missing.
type Block struct {
	Begin int64
	End   int64
}

func (b Block) Part() int {
	return int(b.Begin / PartSize)
}

// Index is the block's place within its part.
func (b Block) Index() int {
	return int(b.Begin % PartSize / BlockSize)
}

// PartRange is the bytes of part in a file of size bytes.
func PartRange(size int64, part int) Block {
	begin := int64(part) * PartSize
	return Block{Begin: begin, End: min(begin+PartSize, size)}
}

// BlockAt is the whole block holding offset in a file of size bytes.
func BlockAt(size, offset int64) Block {
	return blockOf(size, int(offset/PartSize), int(offset%PartSize/BlockSize))
}

func blockOf(size int64, part, index int) Block {
	partRange := PartRange(size, part)
	begin := partRange.Begin + int64(index)*BlockSize
	return Block{Begin: begin, End: min(begin+BlockSize, partRange.End)}
}

// ResumeData is the part of a Picker that survives a restart, as aMule's
// .part.met keeps its gap list. A WrittenBlocks entry is a whole block or,
// for a block cut off when a slot ended, its leading piece [Begin, Begin+n).
type ResumeData struct {
	VerifiedParts []int
	WrittenBlocks []Block
}

// maxRequesters bounds endgame duplication: one original request plus one copy.
const maxRequesters = 2

// blockState tracks a block byte by byte, as aMule keeps byte-granular gaps
// (DownloadClient.cpp:835-848), so a block cut off when a slot ends is
// finished by asking only for its missing tail. Data arrives in order, so
// what is received is always a prefix.
type blockState[P comparable] struct {
	received   int64
	written    int64
	requesters []P
	senders    []P
}

type partState[P comparable] struct {
	isVerified bool
	// blocks is nil until the part is first touched and again after it is
	// verified or reset.
	blocks []blockState[P]
}

// Picker decides which blocks of one file to request from which peer. P
// identifies a peer; the caller chooses its type.
type Picker[P comparable] struct {
	size         int64
	random       *rand.Rand
	parts        []partState[P]
	availability []int
	peerParts    map[P]Set
}

func BuildPicker[P comparable](size int64, resume ResumeData, random *rand.Rand) (*Picker[P], error) {
	p := &Picker[P]{
		size:         size,
		random:       random,
		parts:        make([]partState[P], PartCount(size)),
		availability: make([]int, PartCount(size)),
		peerParts:    map[P]Set{},
	}
	for _, part := range resume.VerifiedParts {
		if part < 0 || part >= len(p.parts) {
			return nil, fmt.Errorf("resume data: part %d out of range", part)
		}
		p.parts[part].isVerified = true
	}
	for _, block := range resume.WrittenBlocks {
		if block.Begin < 0 || block.Begin >= size || BlockAt(p.size, block.Begin).Begin != block.Begin ||
			block.End <= block.Begin || block.End > BlockAt(p.size, block.Begin).End {
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

func (p *Picker[P]) ToResumeData() ResumeData {
	resume := ResumeData{VerifiedParts: []int{}, WrittenBlocks: []Block{}}
	for i, part := range p.parts {
		if part.isVerified {
			resume.VerifiedParts = append(resume.VerifiedParts, i)
		}
		// Disk workers may finish writes out of order, so a block's
		// received prefix is on disk only once every write of it is done.
		for j, state := range part.blocks {
			if state.written > 0 && state.written == state.received {
				block := blockOf(p.size, i, j)
				resume.WrittenBlocks = append(resume.WrittenBlocks, Block{Begin: block.Begin, End: block.Begin + state.written})
			}
		}
	}
	return resume
}

func (p *Picker[P]) blockState(b Block) *blockState[P] {
	part := &p.parts[b.Part()]
	if part.blocks == nil {
		part.blocks = make([]blockState[P], BlockCount(p.size, b.Part()))
	}
	return &part.blocks[b.Index()]
}

func (p *Picker[P]) VerifiedParts() Set {
	set := make(Set, len(p.parts))
	for i, part := range p.parts {
		set[i] = part.isVerified
	}
	return set
}

func (p *Picker[P]) IsComplete() bool {
	return p.VerifiedParts().IsFull()
}

// WrittenParts lists parts whose blocks are all on disk but whose hash has not
// been checked yet, as happens after a restart.
func (p *Picker[P]) WrittenParts() []int {
	var parts []int
	for i := range p.parts {
		if p.isWritten(i) {
			parts = append(parts, i)
		}
	}
	return parts
}

func (p *Picker[P]) isWritten(part int) bool {
	state := p.parts[part]
	if state.isVerified || state.blocks == nil {
		return false
	}
	for j, block := range state.blocks {
		if b := blockOf(p.size, part, j); block.written != b.End-b.Begin {
			return false
		}
	}
	return true
}

func (p *Picker[P]) WrittenSize() int64 {
	var written int64
	for i, part := range p.parts {
		if part.isVerified {
			written += partLength(p.size, i)
			continue
		}
		for _, block := range part.blocks {
			written += block.written
		}
	}
	return written
}

// OnPeerParts replaces what the picker knows a peer has.
func (p *Picker[P]) OnPeerParts(peer P, parts Set) {
	p.removeAvailability(peer)
	p.peerParts[peer] = slices.Clone(parts)
	for i, has := range parts {
		if has {
			p.availability[i]++
		}
	}
}

func (p *Picker[P]) OnPeerGone(peer P) {
	p.Cancel(peer)
	p.removeAvailability(peer)
	delete(p.peerParts, peer)
}

func (p *Picker[P]) removeAvailability(peer P) {
	for i, has := range p.peerParts[peer] {
		if has {
			p.availability[i]--
		}
	}
}

// Cancel releases every block the peer was asked for and has not delivered,
// so other peers can take them.
func (p *Picker[P]) Cancel(peer P) {
	for i := range p.parts {
		for j := range p.parts[i].blocks {
			block := &p.parts[i].blocks[j]
			block.requesters = slices.DeleteFunc(block.requesters, func(r P) bool { return r == peer })
		}
	}
}

// Request picks up to n blocks to ask the peer for and records them as
// requested; a partly received block is asked for from where it stops. It
// prefers parts already in progress, then the rarest parts, breaking ties at
// random. Only when no block is left unrequested anywhere it can be fetched
// from does it hand out blocks already requested from one other peer
// (endgame).
func (p *Picker[P]) Request(peer P, n int) []Block {
	parts := p.candidateParts(peer)
	var picked []Block
	for _, part := range parts {
		for index := range BlockCount(p.size, part) {
			if len(picked) == n {
				return picked
			}
			b := blockOf(p.size, part, index)
			state := p.blockState(b)
			if state.received < b.End-b.Begin && len(state.requesters) == 0 {
				state.requesters = append(state.requesters, peer)
				picked = append(picked, Block{Begin: b.Begin + state.received, End: b.End})
			}
		}
	}
	if p.hasUnrequestedBlock() {
		return picked
	}
	for _, part := range parts {
		for index := range BlockCount(p.size, part) {
			if len(picked) == n {
				return picked
			}
			b := blockOf(p.size, part, index)
			state := p.blockState(b)
			if state.received < b.End-b.Begin && len(state.requesters) < maxRequesters && !slices.Contains(state.requesters, peer) {
				state.requesters = append(state.requesters, peer)
				picked = append(picked, Block{Begin: b.Begin + state.received, End: b.End})
			}
		}
	}
	return picked
}

func (p *Picker[P]) candidateParts(peer P) []int {
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

func (p *Picker[P]) isStarted(part int) bool {
	for _, block := range p.parts[part].blocks {
		if block.received > 0 || len(block.requesters) > 0 {
			return true
		}
	}
	return false
}

func (p *Picker[P]) hasUnrequestedBlock() bool {
	for i, part := range p.parts {
		if part.isVerified || p.availability[i] == 0 {
			continue
		}
		if part.blocks == nil {
			return true
		}
		for j, block := range part.blocks {
			if b := blockOf(p.size, i, j); block.received < b.End-b.Begin && len(block.requesters) == 0 {
				return true
			}
		}
	}
	return false
}

// OnBlockReceived records that the data of b, a block or a leading piece of
// what was requested of it, arrived from peer. It returns the bytes of b that
// are new and should be written; false when another peer delivered them first
// or the part is already verified. The block stays requested until it is
// complete or the peer's requests are cancelled.
func (p *Picker[P]) OnBlockReceived(peer P, b Block) (Block, bool) {
	if p.parts[b.Part()].isVerified {
		return Block{}, false
	}
	whole := BlockAt(p.size, b.Begin)
	state := p.blockState(b)
	next := whole.Begin + state.received
	if b.Begin > next || b.End <= next {
		return Block{}, false
	}
	state.received = b.End - whole.Begin
	if !slices.Contains(state.senders, peer) {
		state.senders = append(state.senders, peer)
	}
	if b.End == whole.End {
		state.requesters = nil
	}
	return Block{Begin: next, End: b.End}, true
}

// OnBlockWritten records that b, as returned by OnBlockReceived, is on disk
// and reports whether its whole part is now written and ready to be hashed.
func (p *Picker[P]) OnBlockWritten(b Block) bool {
	p.blockState(b).written += b.End - b.Begin
	return p.isWritten(b.Part())
}

func (p *Picker[P]) OnPartVerified(part int) {
	p.parts[part] = partState[P]{isVerified: true}
}

// OnPartFailed discards a part whose hash did not match and returns the peers
// that sent any of its blocks, so the caller can ban the corrupt sender.
func (p *Picker[P]) OnPartFailed(part int) []P {
	var senders []P
	for _, block := range p.parts[part].blocks {
		for _, sender := range block.senders {
			if !slices.Contains(senders, sender) {
				senders = append(senders, sender)
			}
		}
	}
	p.parts[part] = partState[P]{}
	return senders
}

// Senders lists the peers that sent any block of a part not yet verified.
func (p *Picker[P]) Senders() []P {
	var senders []P
	for _, part := range p.parts {
		for _, block := range part.blocks {
			for _, sender := range block.senders {
				if !slices.Contains(senders, sender) {
					senders = append(senders, sender)
				}
			}
		}
	}
	return senders
}

// OnBlockFailed discards one whole block of a part that failed its hash
// check, so only that block is requested again, and returns its senders.
func (p *Picker[P]) OnBlockFailed(b Block) []P {
	state := p.blockState(b)
	senders := state.senders
	*state = blockState[P]{}
	return senders
}
