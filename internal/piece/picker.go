package piece

import (
	"fmt"
	"math/rand/v2"
	"slices"
	"sort"
)

// Block is the byte range [Begin, End) of one block inside one part.
type Block struct {
	Begin int64
	End   int64
}

func (b Block) Part() int {
	return int(b.Begin / PartSize)
}

func (b Block) index() int {
	return int(b.Begin % PartSize / BlockSize)
}

// ResumeData is the part of a Picker that survives a restart. Blocks received
// but not yet written are lost and requested again.
type ResumeData struct {
	VerifiedParts []int
	WrittenBlocks []Block
}

// maxRequesters bounds endgame duplication: one original request plus one copy.
const maxRequesters = 2

type blockStage uint8

const (
	blockOpen blockStage = iota
	blockReceived
	blockWritten
)

type blockState[P comparable] struct {
	stage      blockStage
	requesters []P
	sender     P
	hasSender  bool
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
		if block.Begin < 0 || block.Begin >= size || block != p.BlockAt(block.Begin) {
			return nil, fmt.Errorf("resume data: block [%d, %d) is not a block of this file", block.Begin, block.End)
		}
		if !p.parts[block.Part()].isVerified {
			p.blockState(block).stage = blockWritten
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
		for j, block := range part.blocks {
			if block.stage == blockWritten {
				resume.WrittenBlocks = append(resume.WrittenBlocks, p.blockOf(i, j))
			}
		}
	}
	return resume
}

func (p *Picker[P]) BlockAt(offset int64) Block {
	part := int(offset / PartSize)
	return p.blockOf(part, int(offset%PartSize/BlockSize))
}

func (p *Picker[P]) blockOf(part, index int) Block {
	partBegin := int64(part) * PartSize
	begin := partBegin + int64(index)*BlockSize
	return Block{Begin: begin, End: min(begin+BlockSize, partBegin+partLength(p.size, part))}
}

func (p *Picker[P]) blockState(b Block) *blockState[P] {
	part := &p.parts[b.Part()]
	if part.blocks == nil {
		part.blocks = make([]blockState[P], BlockCount(p.size, b.Part()))
	}
	return &part.blocks[b.index()]
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
	for _, block := range state.blocks {
		if block.stage != blockWritten {
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
		for j, block := range part.blocks {
			if block.stage == blockWritten {
				b := p.blockOf(i, j)
				written += b.End - b.Begin
			}
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
// requested. It prefers parts already in progress, then the rarest parts,
// breaking ties at random. Only when no block is left unrequested anywhere it
// can be fetched from does it hand out blocks already requested from one other
// peer (endgame).
func (p *Picker[P]) Request(peer P, n int) []Block {
	parts := p.candidateParts(peer)
	var picked []Block
	for _, part := range parts {
		for index := range BlockCount(p.size, part) {
			if len(picked) == n {
				return picked
			}
			b := p.blockOf(part, index)
			state := p.blockState(b)
			if state.stage == blockOpen && len(state.requesters) == 0 {
				state.requesters = append(state.requesters, peer)
				picked = append(picked, b)
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
			b := p.blockOf(part, index)
			state := p.blockState(b)
			if state.stage == blockOpen && len(state.requesters) < maxRequesters && !slices.Contains(state.requesters, peer) {
				state.requesters = append(state.requesters, peer)
				picked = append(picked, b)
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
		if block.stage != blockOpen || len(block.requesters) > 0 {
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
		for _, block := range part.blocks {
			if block.stage == blockOpen && len(block.requesters) == 0 {
				return true
			}
		}
	}
	return false
}

// OnBlockReceived records that the block's data arrived from peer. It reports
// whether the data should be written: false when another peer delivered the
// block first or its part is already verified.
func (p *Picker[P]) OnBlockReceived(peer P, b Block) bool {
	if p.parts[b.Part()].isVerified {
		return false
	}
	state := p.blockState(b)
	if state.stage != blockOpen {
		return false
	}
	state.stage = blockReceived
	state.sender = peer
	state.hasSender = true
	state.requesters = nil
	return true
}

// OnBlockWritten records that the block is on disk and reports whether its
// whole part is now written and ready to be hashed.
func (p *Picker[P]) OnBlockWritten(b Block) bool {
	p.blockState(b).stage = blockWritten
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
		if block.hasSender && !slices.Contains(senders, block.sender) {
			senders = append(senders, block.sender)
		}
	}
	p.parts[part] = partState[P]{}
	return senders
}
