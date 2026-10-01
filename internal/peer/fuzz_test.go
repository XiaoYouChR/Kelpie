package peer

import (
	"encoding/binary"
	"math/rand/v2"
	"net/netip"
	"testing"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/aich"
	"github.com/XiaoYouChR/Kelpie/internal/piece"
	"github.com/XiaoYouChR/Kelpie/internal/wire"
	"github.com/XiaoYouChR/Kelpie/internal/wire/client"
)

// A fuzz script is what one session sees: packets from the peer and our own
// calls, one record each: kind, uint16 payload length, payload.
const (
	stepPacket byte = iota // payload: protocol, opcode, body
	stepStart
	stepRequest // payload[0]: how many blocks after the last requested one
	stepRequestRecovery
	stepRequestHashSet
	stepRequestSources
	stepTick // payload[0]: seconds
	stepStop
	stepRemove
	stepStartUpload
	stepSendQueueRank
	stepSendBlock // payload[0]: block of the shared file
	stepCount
)

// fuzzFiles are the two files of a fuzz session: one we download from the
// peer, which shares it with its AICH tree, and one we share.
type fuzzFiles struct {
	down, up         wire.Hash
	downSize, upSize int64
	downData, upData []byte
	downHashes       []wire.Hash
	downRoot         wire.AICHHash
	upTree           *aich.Tree
}

func buildFuzzFiles() fuzzFiles {
	var f fuzzFiles
	f.downSize = 2*piece.PartSize + 1000
	f.downData = buildData(f.downSize, true, 1)
	for i := range piece.HashCount(f.downSize) {
		f.downHashes = append(f.downHashes, wire.Hash{1, byte(i)})
	}
	f.down = piece.BuildFileHash(f.downHashes)
	f.upSize = 3*piece.BlockSize + 10
	f.upData = buildData(f.upSize, false, 2)
	f.up = hashOf(2)
	var hasher aich.Hasher
	hasher.Write(f.downData)
	f.downRoot = aich.BuildTree(f.downSize, hasher.Leaves()).Root()
	hasher = aich.Hasher{}
	hasher.Write(f.upData)
	f.upTree = aich.BuildTree(f.upSize, hasher.Leaves())
	return f
}

// fuzzSession is our side of a fuzz script: the session under test and the
// state its calls need.
type fuzzSession struct {
	s      *Session
	files  fuzzFiles
	now    time.Time
	next   int64
	events []Event
	// hello is what an outgoing session sends first.
	hello []wire.Packet
}

func buildFuzzSession(cfg Config, isOutgoing bool, files fuzzFiles) *fuzzSession {
	cfg.Random = rand.New(rand.NewPCG(1, 7))
	remote := netip.MustParseAddrPort("198.51.100.2:4662")
	f := &fuzzSession{files: files, now: start}
	cfg.ShareByHash, cfg.SourcesByHash = f.shares, f.sources
	if isOutgoing {
		var out Output
		f.s, out = BuildOutgoing(cfg, remote, f.now)
		f.hello = out.Send
	} else {
		f.s = BuildIncoming(cfg, remote, f.now)
	}
	f.s.Add(files.down, files.downSize, piece.Set{false, false, false})
	return f
}

func (f *fuzzSession) shares(file wire.Hash) (Share, bool) {
	if file != f.files.up {
		return Share{}, false
	}
	return Share{Name: "up.bin", Size: f.files.upSize, Parts: piece.BuildFullSet(piece.PartCount(f.files.upSize)), Tree: f.files.upTree}, true
}

func (f *fuzzSession) sources(wire.Hash, piece.Set) []Source {
	return []Source{
		{IPv4: netip.MustParseAddr("198.51.100.7"), Port: 4662, UserHash: hashOf(7)},
		{LowID: 42, Port: 4663, Server: netip.MustParseAddrPort("198.51.100.8:4661")},
		{IPv6: netip.MustParseAddr("2001:db8::8"), Port: 4664},
	}
}

func (f *fuzzSession) blockOf(index int64, size int64) piece.Block {
	begin := min(index*piece.BlockSize, size-1)
	return piece.Block{Begin: begin, End: min(begin+piece.BlockSize, size)}
}

// run performs one step and returns what the session sent.
func (f *fuzzSession) run(kind byte, payload []byte) []wire.Packet {
	arg := byte(0)
	if len(payload) > 0 {
		arg = payload[0]
	}
	var out Output
	switch kind {
	case stepPacket:
		if len(payload) < 2 {
			return nil
		}
		p, err := client.Parse(payload[0], payload[1], payload[2:])
		if err != nil {
			return nil
		}
		out = f.s.OnPacket(p, f.now)
	case stepStart:
		out = f.s.Start(f.files.down)
	case stepRequest:
		var blocks []piece.Block
		for range int(arg % 4) {
			if f.next*piece.BlockSize < f.files.downSize {
				blocks = append(blocks, f.blockOf(f.next, f.files.downSize))
				f.next++
			}
		}
		out = f.s.Request(f.files.down, blocks)
	case stepRequestRecovery:
		out = f.s.RequestRecovery(f.files.down, int(arg)%piece.PartCount(f.files.downSize), f.files.downRoot)
	case stepRequestHashSet:
		out = f.s.RequestHashSet(f.files.down)
	case stepRequestSources:
		out = f.s.RequestSources(f.files.down, f.now)
	case stepTick:
		f.now = f.now.Add(time.Duration(arg) * time.Second)
		out = f.s.OnTick(f.now)
	case stepStop:
		out = f.s.Stop()
	case stepRemove:
		out = f.s.Remove(f.files.down)
	case stepStartUpload:
		out = f.s.StartUpload()
	case stepSendQueueRank:
		out = f.s.SendQueueRank(uint32(arg))
	case stepSendBlock:
		block := f.blockOf(int64(arg%4), f.files.upSize)
		out = f.s.SendBlock(f.files.up, block, f.files.upData[block.Begin:block.End])
	}
	f.events = append(f.events, out.Events...)
	return out.Send
}

// recorder plays a real peer against a fuzz session and writes down the
// script the session saw, as a seed.
type recorder struct {
	f      *fuzzSession
	peer   *side
	script []byte
}

func (r *recorder) add(kind byte, payload []byte) {
	r.script = append(r.script, kind)
	r.script = binary.LittleEndian.AppendUint16(r.script, uint16(len(payload)))
	r.script = append(r.script, payload...)
}

func (r *recorder) toPeer(sent []wire.Packet) {
	for _, p := range sent {
		frame, _, _ := wire.ParseFrame(wire.BuildPacket(nil, p))
		parsed, err := client.Parse(frame.Protocol, frame.Opcode, frame.Body)
		if err != nil {
			panic(err)
		}
		out := r.peer.s.OnPacket(parsed, r.f.now)
		r.fromPeer(out)
	}
}

func (r *recorder) fromPeer(out Output) {
	r.peer.events = append(r.peer.events, out.Events...)
	for _, p := range out.Send {
		frame, _, _ := wire.ParseFrame(wire.BuildPacket(nil, p))
		payload := append([]byte{frame.Protocol, frame.Opcode}, frame.Body...)
		r.add(stepPacket, payload)
		r.toPeer(r.f.run(stepPacket, payload))
	}
}

func (r *recorder) call(kind byte, arg byte) {
	r.add(kind, []byte{arg})
	r.toPeer(r.f.run(kind, []byte{arg}))
}

// recordSession scripts a session that downloads, uploads, asks for
// recovery data, hash sets and sources, with a peer that is our own code.
func recordSession(t testing.TB, ours, theirs Config, isOutgoing bool, files fuzzFiles) []byte {
	r := &recorder{f: buildFuzzSession(ours, isOutgoing, files), peer: buildSide()}
	var hasher aich.Hasher
	hasher.Write(files.downData)
	r.peer.shares[files.down] = Share{Name: "down.bin", Size: files.downSize, Parts: piece.BuildFullSet(3), PartHashes: files.downHashes, Tree: aich.BuildTree(files.downSize, hasher.Leaves())}
	ourAddr := netip.MustParseAddrPort("198.51.100.1:4662")
	theirs.Random = rand.New(rand.NewPCG(2, 7))
	theirs = r.peer.serve(theirs)
	if isOutgoing {
		r.peer.s = BuildIncoming(theirs, ourAddr, start)
		r.toPeer(r.f.hello)
	} else {
		var hello Output
		r.peer.s, hello = BuildOutgoing(theirs, ourAddr, start)
		r.fromPeer(hello)
	}
	r.call(stepStart, 0)
	r.fromPeer(r.peer.s.StartUpload())
	r.call(stepRequest, 3)
	r.sendRequested(files.down, files.downData)
	r.call(stepRequestHashSet, 0)
	r.call(stepRequestRecovery, 1)
	r.call(stepRequestSources, 0)
	r.fromPeer(r.peer.s.Add(files.up, files.upSize, piece.Set{false}))
	r.fromPeer(r.peer.s.Start(files.up))
	r.call(stepSendQueueRank, 3)
	r.call(stepStartUpload, 0)
	r.fromPeer(r.peer.s.Request(files.up, []piece.Block{r.f.blockOf(0, files.upSize), r.f.blockOf(1, files.upSize)}))
	r.call(stepSendBlock, 0)
	r.call(stepSendBlock, 1)
	r.call(stepTick, 30)
	r.call(stepRequest, 2)
	r.call(stepStop, 0)
	r.call(stepRemove, 0)
	replayed := replay(ours, isOutgoing, files, r.script)
	if len(r.f.events) < 15 || len(replayed.events) != len(r.f.events) {
		t.Fatalf("recorded %d events, replayed %d", len(r.f.events), len(replayed.events))
	}
	return r.script
}

func (r *recorder) sendRequested(file wire.Hash, data []byte) {
	for _, e := range r.peer.events {
		if req, ok := e.(BlocksRequested); ok && req.File == file {
			for _, b := range req.Blocks {
				r.fromPeer(r.peer.s.SendBlock(file, b, data[b.Begin:b.End]))
			}
		}
	}
}

// FuzzSession feeds a session the packets a hostile peer might send, mixed
// with our own calls, so the packets reach every state a real session gets
// into. The seeds are scripts recorded against a peer running this package.
func FuzzSession(f *testing.F) {
	ours, theirs := buildConfig(f, 1), buildConfig(f, 2)
	files := buildFuzzFiles()
	f.Add(true, recordSession(f, ours, theirs, true, files))
	f.Add(false, recordSession(f, ours, theirs, false, files))
	f.Fuzz(func(t *testing.T, isOutgoing bool, script []byte) {
		replay(ours, isOutgoing, files, script).s.Stop()
	})
}

func replay(cfg Config, isOutgoing bool, files fuzzFiles, script []byte) *fuzzSession {
	s := buildFuzzSession(cfg, isOutgoing, files)
	for len(script) >= 3 {
		kind := script[0] % stepCount
		size := min(int(binary.LittleEndian.Uint16(script[1:3])), len(script)-3)
		s.run(kind, script[3:3+size])
		script = script[3+size:]
	}
	return s
}
