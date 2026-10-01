package peer

import (
	"bytes"
	"math/rand/v2"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/identity"
	"github.com/XiaoYouChR/Kelpie/internal/piece"
	"github.com/XiaoYouChR/Kelpie/internal/wire"
	"github.com/XiaoYouChR/Kelpie/internal/wire/client"
)

var start = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// side is one end of a scripted connection.
type side struct {
	s      *Session
	shares map[wire.Hash]Share
	events []Event
	closed CloseReason
}

func (e *side) shareByHash(file wire.Hash) (Share, bool) {
	share, ok := e.shares[file]
	return share, ok
}

// link carries packets between two sessions through their wire form, so the
// codecs are exercised exactly as on a socket.
type link struct {
	t    *testing.T
	a, b *side
	now  time.Time
	// tamper may replace a packet in flight; nil keeps it.
	tamper func(p wire.Packet) wire.Packet
	// sent records every packet delivered, in order.
	sent []wire.Packet
}

func buildConfig(t testing.TB, last byte) Config {
	t.Helper()
	self, err := identity.CreateSelf()
	if err != nil {
		t.Fatal(err)
	}
	ip := netip.AddrFrom4([4]byte{10, 0, 0, last})
	return Config{
		Self:     self,
		Version:  "1.2.3",
		ClientID: wire.ToClientID(ip),
		PublicIP: ip,
		Port:     4662,
		UDPPort:  4672,
		IPv6:     netip.MustParseAddr("2001:db8::" + string('0'+rune(last))),
		Pipeline: 3,
		Random:   rand.New(rand.NewPCG(uint64(last), 7)),
	}
}

// buildLink connects a (outgoing) to b (incoming) and runs the handshake.
func buildLink(t *testing.T) *link {
	t.Helper()
	l := &link{t: t, now: start}
	return l.open(buildConfig(t, 1), buildConfig(t, 2))
}

func (l *link) open(ca, cb Config) *link {
	a, hello := BuildOutgoing(ca, netip.AddrPortFrom(cb.PublicIP, cb.Port), l.now)
	b := BuildIncoming(cb, netip.AddrPortFrom(ca.PublicIP, 50000), l.now)
	l.a = &side{s: a, shares: map[wire.Hash]Share{}}
	l.b = &side{s: b, shares: map[wire.Hash]Share{}}
	l.run(l.a, hello)
	return l
}

func (l *link) other(e *side) *side {
	if e == l.a {
		return l.b
	}
	return l.a
}

// run delivers from's output and every reply until both sides are quiet.
func (l *link) run(from *side, out Output) {
	l.t.Helper()
	type flight struct {
		to *side
		p  wire.Packet
	}
	var queue []flight
	record := func(e *side, out Output) {
		e.events = append(e.events, out.Events...)
		if out.Close != "" {
			e.closed = out.Close
		}
		for _, p := range out.Send {
			queue = append(queue, flight{l.other(e), p})
		}
	}
	record(from, out)
	for len(queue) > 0 {
		f := queue[0]
		queue = queue[1:]
		p := f.p
		if l.tamper != nil {
			p = l.tamper(p)
		}
		l.sent = append(l.sent, p)
		record(f.to, f.to.s.OnPacket(l.toParsed(p), f.to.shareByHash, l.now))
	}
}

func (l *link) toParsed(p wire.Packet) wire.Packet {
	l.t.Helper()
	frame, n, err := wire.ParseFrame(wire.BuildPacket(nil, p))
	if err != nil || n == 0 {
		l.t.Fatalf("frame %T: %v", p, err)
	}
	parsed, err := client.Parse(frame.Protocol, frame.Opcode, frame.Body)
	if err != nil {
		l.t.Fatalf("parse %T: %v", p, err)
	}
	return parsed
}

func eventsOf[T Event](e *side) []T {
	var out []T
	for _, ev := range e.events {
		if v, ok := ev.(T); ok {
			out = append(out, v)
		}
	}
	return out
}

func lastOf[T Event](t *testing.T, e *side) T {
	t.Helper()
	all := eventsOf[T](e)
	if len(all) == 0 {
		var zero T
		t.Fatalf("no %T in %#v", zero, e.events)
	}
	return all[len(all)-1]
}

func sentCount[T wire.Packet](l *link) int {
	n := 0
	for _, p := range l.sent {
		if _, ok := p.(T); ok {
			n++
		}
	}
	return n
}

func hashOf(b byte) wire.Hash { return wire.Hash{b, b, b} }

func buildData(size int64, isCompressible bool, seed uint64) []byte {
	r := rand.New(rand.NewPCG(seed, 1))
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(r.Uint32())
		if isCompressible {
			data[i] %= 4
		}
	}
	return data
}

func TestHandshakeBothDirections(t *testing.T) {
	l := buildLink(t)
	ha := lastOf[HandshakeCompleted](t, l.a)
	hb := lastOf[HandshakeCompleted](t, l.b)
	if ha.UserHash != l.b.s.cfg.Self.UserHash || hb.UserHash != l.a.s.cfg.Self.UserHash {
		t.Fatal("user hashes not exchanged")
	}
	if ha.YourIP != l.a.s.cfg.PublicIP || hb.YourIP != l.b.s.cfg.PublicIP {
		t.Fatalf("YourIP votes %v %v", ha.YourIP, hb.YourIP)
	}
	caps := l.a.s.Capabilities()
	if caps.Name != "Kelpie" || !caps.IsEmule || !caps.CanCompress || !caps.HasSourceExchange2 ||
		!caps.HasExtMultiPacket || !caps.HasLargeFiles || !caps.HasExtendedSources || caps.UDPVersion != 4 ||
		caps.SecureIdent != identity.Support || caps.IPv6 != l.b.s.cfg.IPv6 || caps.UDPPort != 4672 ||
		caps.CryptOptions != wire.CryptSupported|wire.CryptRequested {
		t.Fatalf("capabilities %+v", caps)
	}
	if caps.EmuleVersion != 0x4B<<24|1<<17|2<<10|3<<7 || caps.MuleVersion != 0x99 {
		t.Fatalf("emule version %#x", caps.EmuleVersion)
	}
	if l.b.s.Capabilities().ClientID != l.a.s.cfg.ClientID {
		t.Fatal("incoming side lost the peer's client id")
	}
}

func TestIdentityBothWays(t *testing.T) {
	l := buildLink(t)
	if id := lastOf[Identified](t, l.a); id.UserHash != l.b.s.cfg.Self.UserHash || !bytes.Equal(id.PublicKey, l.b.s.cfg.Self.PublicKey()) {
		t.Fatalf("a identified %+v", id)
	}
	lastOf[Identified](t, l.b)
	if !l.a.s.isIdentified() || !l.b.s.isIdentified() {
		t.Fatal("not identified")
	}
}

func TestIdentityFailsForForgedKey(t *testing.T) {
	mallory, err := identity.CreateSelf()
	if err != nil {
		t.Fatal(err)
	}
	l := &link{t: t, now: start}
	ca, cb := buildConfig(t, 1), buildConfig(t, 2)
	l.tamper = func(p wire.Packet) wire.Packet {
		if k, ok := p.(client.PublicKey); ok && bytes.Equal(k.Key, cb.Self.PublicKey()) {
			return client.PublicKey{Key: mallory.PublicKey()}
		}
		return p
	}
	l.open(ca, cb)
	if failed := lastOf[IdentityFailed](t, l.a); failed.UserHash != cb.Self.UserHash {
		t.Fatalf("failed %+v", failed)
	}
	if len(eventsOf[Identified](l.a)) != 0 || l.a.s.isIdentified() {
		t.Fatal("forged key identified")
	}
	// a signed over the key it was given, so b rejects a too.
	lastOf[IdentityFailed](t, l.b)
}

func TestPacketBeforeHelloCloses(t *testing.T) {
	s := BuildIncoming(buildConfig(t, 1), netip.MustParseAddrPort("10.0.0.9:1"), start)
	if out := s.OnPacket(client.AcceptUploadRequest{}, nil, start); out.Close != CloseProtocol {
		t.Fatalf("close %q", out.Close)
	}
}

// addShare makes e share a file of size and returns its hash and data.
func addShare(e *side, b byte, size int64, isCompressible bool) (wire.Hash, []byte) {
	data := buildData(size, isCompressible, uint64(b))
	share := Share{Name: "file.bin", Size: size, Parts: piece.BuildFullSet(piece.PartCount(size))}
	file := hashOf(b)
	if piece.HashCount(size) > 0 {
		for i := range piece.HashCount(size) {
			share.PartHashes = append(share.PartHashes, wire.Hash{b, byte(i)})
		}
		file = piece.BuildFileHash(share.PartHashes)
	}
	e.shares[file] = share
	return file, data
}

// sendRequestedBlocks answers every BlocksRequested on uploader from data.
func (l *link) sendRequestedBlocks(uploader *side, file wire.Hash, data []byte) {
	for _, r := range eventsOf[BlocksRequested](uploader) {
		for _, b := range r.Blocks {
			l.run(uploader, uploader.s.SendBlock(file, b, data[b.Begin:b.End]))
		}
	}
}

func TestQueueThenSlotOnOutgoingConnection(t *testing.T) {
	l := buildLink(t)
	file, _ := addShare(l.b, 1, 3*piece.BlockSize, false)
	l.run(l.a, l.a.s.Add(file, 3*piece.BlockSize, piece.Set{false}))
	if st := lastOf[StatusReceived](t, l.a); st.File != file || !st.Parts.IsFull() {
		t.Fatalf("status %+v", st)
	}
	l.run(l.a, l.a.s.Start(file))
	if lastOf[UploadRequested](t, l.b).File != file {
		t.Fatal("upload request")
	}
	l.run(l.b, l.b.s.SendQueueRank(7))
	if q := lastOf[Queued](t, l.a); q.File != file || q.Rank != 7 {
		t.Fatalf("queued %+v", q)
	}
	l.run(l.b, l.b.s.StartUpload())
	if g := lastOf[SlotGranted](t, l.a); g.File != file {
		t.Fatalf("granted %+v", g)
	}
	if w := lastOf[BlocksWanted](t, l.a); w.Count != 3 {
		t.Fatalf("wanted %+v", w)
	}
}

// The uploader opens the connection to tell us our slot is ready, before we
// said anything about the file on it.
func TestSlotGrantOnIncomingConnection(t *testing.T) {
	l := buildLink(t)
	downloader, uploader := l.b, l.a
	size := 2 * piece.BlockSize
	file, data := addShare(uploader, 1, size, false)

	l.run(uploader, uploader.s.StartUpload())
	if g := lastOf[SlotGranted](t, downloader); g.File != (wire.Hash{}) {
		t.Fatalf("granted %+v", g)
	}
	l.run(downloader, downloader.s.Add(file, size, piece.Set{false}))
	l.run(downloader, downloader.s.Start(file))
	if sentCount[client.StartUploadRequest](l) != 0 {
		t.Fatal("asked for a slot we already hold")
	}
	w := lastOf[BlocksWanted](t, downloader)
	if w.File != file || w.Count != 3 {
		t.Fatalf("wanted %+v", w)
	}
	blocks := []piece.Block{{Begin: 0, End: piece.BlockSize}, {Begin: piece.BlockSize, End: size}}
	l.run(downloader, downloader.s.Request(file, blocks))
	l.sendRequestedBlocks(uploader, file, data)
	got := eventsOf[BlockReceived](downloader)
	if len(got) != 2 {
		t.Fatalf("received %d blocks", len(got))
	}
	for _, r := range got {
		if !bytes.Equal(r.Data, data[r.Block.Begin:r.Block.End]) {
			t.Fatalf("block %+v corrupted", r.Block)
		}
	}
}

func TestPipelineStaysFull(t *testing.T) {
	l := &link{t: t, now: start}
	ca, cb := buildConfig(t, 1), buildConfig(t, 2)
	ca.Pipeline = 5
	l.open(ca, cb)
	size := 10 * piece.BlockSize
	file, data := addShare(l.b, 1, size, false)
	l.run(l.a, l.a.s.Add(file, size, piece.Set{false, false}))
	l.run(l.a, l.a.s.Start(file))
	l.run(l.b, l.b.s.StartUpload())
	if w := lastOf[BlocksWanted](t, l.a); w.Count != 5 {
		t.Fatalf("wanted %+v", w)
	}
	block := func(i int64) piece.Block {
		return piece.Block{Begin: i * piece.BlockSize, End: (i + 1) * piece.BlockSize}
	}
	l.sent = nil
	l.run(l.a, l.a.s.Request(file, []piece.Block{block(0), block(1), block(2), block(3), block(4)}))
	if n := sentCount[client.RequestParts](l); n != 2 {
		t.Fatalf("%d RequestParts for 5 blocks", n)
	}
	requested := lastOf[BlocksRequested](t, l.b)
	if len(requested.Blocks) != 2 || len(eventsOf[BlocksRequested](l.b)) != 2 {
		t.Fatalf("requested %+v", eventsOf[BlocksRequested](l.b))
	}

	// eMule re-lists blocks still in flight; each is served once.
	l.b.events = nil
	l.run(l.a, Output{Send: []wire.Packet{client.RequestParts{Hash: file, Starts: [3]uint32{0, uint32(piece.BlockSize)}, Ends: [3]uint32{uint32(piece.BlockSize), uint32(2 * piece.BlockSize)}}}})
	if len(eventsOf[BlocksRequested](l.b)) != 0 {
		t.Fatal("duplicate request served again")
	}

	l.a.events = nil
	b0 := block(0)
	l.run(l.b, l.b.s.SendBlock(file, b0, data[b0.Begin:b0.End]))
	if r := lastOf[BlockReceived](t, l.a); r.Block != b0 {
		t.Fatalf("received %+v", r.Block)
	}
	if w := lastOf[BlocksWanted](t, l.a); w.Count != 1 {
		t.Fatalf("after one block wanted %+v", w)
	}
	l.b.events = nil
	l.run(l.a, l.a.s.Request(file, []piece.Block{block(5)}))
	if r := lastOf[BlocksRequested](t, l.b); len(r.Blocks) != 1 || r.Blocks[0] != block(5) {
		t.Fatalf("refill %+v", r)
	}
	l.run(l.a, l.a.s.Remove(file))
	lastOf[UploadCancelled](t, l.b)
}

func TestCompressedPartReassembly(t *testing.T) {
	l := buildLink(t)
	size := piece.BlockSize
	file, data := addShare(l.b, 1, size, true)
	l.run(l.a, l.a.s.Add(file, size, piece.Set{false}))
	l.run(l.a, l.a.s.Start(file))
	l.run(l.b, l.b.s.StartUpload())
	l.run(l.a, l.a.s.Request(file, []piece.Block{{Begin: 0, End: size}}))
	l.sent = nil
	l.sendRequestedBlocks(l.b, file, data)
	if n := sentCount[client.CompressedPart](l); n < 2 {
		t.Fatalf("block packed into %d packets, want a stream spanning several", n)
	}
	if sentCount[client.SendingPart](l) != 0 {
		t.Fatal("compressible block sent plain")
	}
	if r := lastOf[BlockReceived](t, l.a); !bytes.Equal(r.Data, data) {
		t.Fatal("inflated block differs")
	}
}

func TestIncompressibleBlockSentPlain(t *testing.T) {
	l := buildLink(t)
	size := piece.BlockSize
	file, data := addShare(l.b, 1, size, false)
	l.run(l.a, l.a.s.Add(file, size, piece.Set{false}))
	l.run(l.a, l.a.s.Start(file))
	l.run(l.b, l.b.s.StartUpload())
	l.run(l.a, l.a.s.Request(file, []piece.Block{{Begin: 0, End: size}}))
	l.sent = nil
	l.sendRequestedBlocks(l.b, file, data)
	if sentCount[client.CompressedPart](l) != 0 || sentCount[client.SendingPart](l) != 18 {
		t.Fatalf("sent %d plain packets", sentCount[client.SendingPart](l))
	}
	if r := lastOf[BlockReceived](t, l.a); !bytes.Equal(r.Data, data) {
		t.Fatal("block differs")
	}
}

func TestUploadAndDownloadOnOneConnection(t *testing.T) {
	l := buildLink(t)
	size := 2 * piece.BlockSize
	fromB, dataB := addShare(l.b, 1, size, false)
	fromA, dataA := addShare(l.a, 2, size, true)

	l.run(l.a, l.a.s.Add(fromB, size, piece.Set{false}))
	l.run(l.b, l.b.s.Add(fromA, size, piece.Set{false}))
	l.run(l.a, l.a.s.Start(fromB))
	l.run(l.b, l.b.s.Start(fromA))
	if lastOf[UploadRequested](t, l.a).File != fromA || lastOf[UploadRequested](t, l.b).File != fromB {
		t.Fatal("upload requests crossed")
	}
	l.run(l.a, l.a.s.StartUpload())
	l.run(l.b, l.b.s.StartUpload())
	blocks := []piece.Block{{Begin: 0, End: piece.BlockSize}, {Begin: piece.BlockSize, End: size}}
	l.run(l.a, l.a.s.Request(fromB, blocks))
	l.run(l.b, l.b.s.Request(fromA, blocks))

	pending := map[*side][]BlocksRequested{l.a: eventsOf[BlocksRequested](l.a), l.b: eventsOf[BlocksRequested](l.b)}
	for _, e := range []*side{l.a, l.b} {
		file, data := fromA, dataA
		if e == l.b {
			file, data = fromB, dataB
		}
		for _, r := range pending[e] {
			for _, b := range r.Blocks {
				l.run(e, e.s.SendBlock(file, b, data[b.Begin:b.End]))
			}
		}
	}
	matchReceived := func(e *side, file wire.Hash, data []byte) {
		got := eventsOf[BlockReceived](e)
		if len(got) != 2 {
			t.Fatalf("%d blocks received", len(got))
		}
		for _, r := range got {
			if r.File != file || !bytes.Equal(r.Data, data[r.Block.Begin:r.Block.End]) {
				t.Fatalf("wrong block %+v", r.Block)
			}
		}
	}
	matchReceived(l.a, fromB, dataB)
	matchReceived(l.b, fromA, dataA)
}

// aMule asks for the slot right after the file status and fetches the hash
// set only from the one source the transfer picks.
func TestSlotRequestDoesNotWaitForHashSet(t *testing.T) {
	l := buildLink(t)
	size := 2*piece.PartSize + 5
	file, _ := addShare(l.b, 1, size, false)
	l.run(l.a, l.a.s.Add(file, size, piece.Set{false, false, false}))
	l.run(l.a, l.a.s.Start(file))
	if sentCount[client.MultiPacketExt2](l) != 1 || sentCount[client.StartUploadRequest](l) != 1 {
		t.Fatal("file request or slot request missing")
	}
	if sentCount[client.HashSetRequest](l) != 0 {
		t.Fatal("hash set asked without the transfer wanting it")
	}
	l.run(l.a, l.a.s.RequestHashSet(file))
	h := lastOf[HashSetReceived](t, l.a)
	if h.File != file || len(h.Hashes) != 3 {
		t.Fatalf("hash set %+v", h)
	}
	if sentCount[client.HashSetRequest](l) != 1 || sentCount[client.StartUploadRequest](l) != 1 {
		t.Fatal("hash set fetched more than once or slot asked again")
	}
}

// A hash set wanted before the peer told its status is asked right after it.
func TestHashSetWaitsForStatus(t *testing.T) {
	l := buildLink(t)
	size := piece.PartSize + 1
	file, _ := addShare(l.b, 1, size, false)
	add := l.a.s.Add(file, size, piece.Set{false, false})
	if out := l.a.s.RequestHashSet(file); len(out.Send) != 0 {
		t.Fatal("hash set asked before the file status")
	}
	l.run(l.a, add)
	if len(lastOf[HashSetReceived](t, l.a).Hashes) != 2 {
		t.Fatal("hash set")
	}
}

func TestWrongHashSetCloses(t *testing.T) {
	l := buildLink(t)
	size := piece.PartSize + 1
	file, _ := addShare(l.b, 1, size, false)
	share := l.b.shares[file]
	share.PartHashes = []wire.Hash{{9}, {9}}
	l.b.shares[file] = share
	l.run(l.a, l.a.s.Add(file, size, piece.Set{false, false}))
	l.run(l.a, l.a.s.RequestHashSet(file))
	if l.a.closed != CloseProtocol {
		t.Fatalf("closed %q", l.a.closed)
	}
}

func TestFileNotSharedIsRejected(t *testing.T) {
	l := buildLink(t)
	file := hashOf(5)
	l.run(l.a, l.a.s.Add(file, piece.BlockSize, piece.Set{false}))
	if lastOf[FileRejected](t, l.a).File != file {
		t.Fatal("wrong file rejected")
	}
	if out := l.a.s.Start(file); len(out.Send) != 0 {
		t.Fatal("started a rejected file")
	}
}

func TestPartialShareStatus(t *testing.T) {
	l := buildLink(t)
	size := 3 * piece.PartSize
	file, _ := addShare(l.b, 1, size, false)
	share := l.b.shares[file]
	share.Parts = piece.Set{true, false, true}
	l.b.shares[file] = share
	l.run(l.a, l.a.s.Add(file, size, piece.Set{false, false, false}))
	st := lastOf[StatusReceived](t, l.a)
	if len(st.Parts) != 3 || !st.Parts[0] || st.Parts[1] || !st.Parts[2] {
		t.Fatalf("status %v", st.Parts)
	}
}

func TestOutOfPartsRevokesSlot(t *testing.T) {
	l := buildLink(t)
	file, _ := addShare(l.b, 1, piece.BlockSize, false)
	l.run(l.a, l.a.s.Add(file, piece.BlockSize, piece.Set{false}))
	l.run(l.a, l.a.s.Start(file))
	l.run(l.b, l.b.s.StartUpload())
	l.run(l.a, l.a.s.Request(file, []piece.Block{{Begin: 0, End: piece.BlockSize}}))
	l.run(l.b, l.b.s.StopUpload())
	if lastOf[SlotRevoked](t, l.a).File != file {
		t.Fatal("slot not revoked")
	}
	if out := l.a.s.Request(file, []piece.Block{{Begin: 0, End: piece.BlockSize}}); len(out.Send) != 0 {
		t.Fatal("requested without a slot")
	}
	if out := l.a.s.Remove(file); len(out.Send) != 0 {
		t.Fatal("cancelled a slot we no longer hold")
	}
}

func TestNoSlotAskedWithoutNeededParts(t *testing.T) {
	l := buildLink(t)
	size := 3 * piece.PartSize
	file, _ := addShare(l.b, 1, size, false)
	share := l.b.shares[file]
	share.Parts = piece.Set{true, false, false}
	l.b.shares[file] = share
	l.run(l.a, l.a.s.Add(file, size, piece.Set{true, false, false}))
	l.run(l.a, l.a.s.Start(file))
	lastOf[StatusReceived](t, l.a)
	if sentCount[client.StartUploadRequest](l) != 0 {
		t.Fatal("asked a slot of a peer with nothing we need")
	}
	if lastOf[NoNeededParts](t, l.a).File != file {
		t.Fatal("no NoNeededParts for a peer with nothing we need")
	}

	share.Parts = piece.Set{true, false, true}
	l.b.shares[file] = share
	l.run(l.a, Output{Send: []wire.Packet{client.SetRequestFileID{Hash: file}}})
	if sentCount[client.StartUploadRequest](l) != 1 {
		t.Fatal("no slot asked once the peer has a part we need")
	}
}

func TestEmptySlotIsCancelled(t *testing.T) {
	l := buildLink(t)
	file, _ := addShare(l.b, 1, piece.BlockSize, false)
	l.run(l.a, l.a.s.Add(file, piece.BlockSize, piece.Set{false}))
	l.run(l.a, l.a.s.Start(file))
	l.run(l.b, l.b.s.StartUpload())
	l.sent = nil
	l.run(l.a, l.a.s.Request(file, nil))
	if sentCount[client.CancelTransfer](l) != 1 {
		t.Fatal("empty slot kept")
	}
	if lastOf[SlotRevoked](t, l.a).File != file {
		t.Fatal("slot not released")
	}
	if lastOf[NoNeededParts](t, l.a).File != file {
		t.Fatal("empty slot not reported as no needed parts")
	}
	lastOf[UploadCancelled](t, l.b)
}

// startOneBlock has a request one block of a fresh share of b and returns
// the uploader's packets for it, undelivered.
func startOneBlock(t *testing.T, l *link, isCompressible bool) (wire.Hash, []byte, []wire.Packet) {
	t.Helper()
	file, data := addShare(l.b, 1, piece.BlockSize, isCompressible)
	l.run(l.a, l.a.s.Add(file, piece.BlockSize, piece.Set{false}))
	l.run(l.a, l.a.s.Start(file))
	l.run(l.b, l.b.s.StartUpload())
	block := piece.Block{Begin: 0, End: piece.BlockSize}
	l.run(l.a, l.a.s.Request(file, []piece.Block{block}))
	return file, data, l.b.s.SendBlock(file, block, data).Send
}

func TestSlotEndHandsOverReceivedPrefix(t *testing.T) {
	l := buildLink(t)
	file, data, packets := startOneBlock(t, l, false)
	l.run(l.b, Output{Send: []wire.Packet{packets[1], packets[0], packets[3]}})
	l.run(l.b, l.b.s.StopUpload())
	got := lastOf[BlockReceived](t, l.a)
	want := piece.Block{Begin: 0, End: 2 * partPacketSize}
	if got.File != file || got.Block != want || !bytes.Equal(got.Data, data[:want.End]) {
		t.Fatalf("received %+v (%d bytes)", got.Block, len(got.Data))
	}
	if _, ok := l.a.events[len(l.a.events)-1].(SlotRevoked); !ok {
		t.Fatal("slot revoked before the prefix was handed over")
	}
}

func TestClosingHandsOverInflatedPrefix(t *testing.T) {
	l := buildLink(t)
	file, data, packets := startOneBlock(t, l, true)
	if len(packets) < 2 {
		t.Fatalf("block packed into %d packets", len(packets))
	}
	l.run(l.b, Output{Send: packets[:len(packets)/2]})
	out := l.a.s.Stop()
	if len(out.Events) != 1 {
		t.Fatalf("events %+v", out.Events)
	}
	got := out.Events[0].(BlockReceived)
	n := got.Block.End
	if got.File != file || got.Block.Begin != 0 || n == 0 || n >= piece.BlockSize || !bytes.Equal(got.Data, data[:n]) {
		t.Fatalf("received %+v (%d bytes)", got.Block, len(got.Data))
	}
	if again := l.a.s.Stop(); len(again.Events) != 0 {
		t.Fatal("prefix handed over twice")
	}
}

func TestRequestsCarryPeerParts(t *testing.T) {
	l := buildLink(t)
	size := 3 * piece.PartSize
	file, _ := addShare(l.b, 1, size, false)
	parts := piece.Set{true, false, false}
	l.run(l.a, l.a.s.Add(file, size, parts))
	l.run(l.a, l.a.s.Start(file))
	l.run(l.a, l.a.s.RequestSources(file, l.now))
	if got := lastOf[UploadRequested](t, l.b).Parts; !slices.Equal(got, parts) {
		t.Fatalf("upload request parts %v", got)
	}
	if got := lastOf[SourcesRequested](t, l.b).Parts; !slices.Equal(got, parts) {
		t.Fatalf("source request parts %v", got)
	}
}

func TestSourceExchange(t *testing.T) {
	l := buildLink(t)
	file, _ := addShare(l.b, 1, piece.BlockSize, false)
	l.run(l.a, l.a.s.Add(file, piece.BlockSize, piece.Set{false}))
	l.sent = nil
	l.run(l.a, l.a.s.RequestSources(file, l.now))
	// aMule 2.3 closes on a standalone OP_REQUESTSOURCES2 (seen on the real
	// network), so it travels in a multipacket.
	multi := l.sent[0].(client.MultiPacketExt2)
	if r := multi.Requests[0].(client.RequestSources2); len(multi.Requests) != 1 || r.Version != client.ExtendedSourcesVersion {
		t.Fatalf("asked a Kelpie peer with %+v", multi)
	}
	if lastOf[SourcesRequested](t, l.b).File != file {
		t.Fatal("request not seen")
	}
	server := netip.MustParseAddrPort("1.2.3.4:4661")
	sources := []Source{
		{IPv4: netip.MustParseAddr("5.6.7.8"), IPv6: netip.MustParseAddr("2001:db8::7"), Port: 4662, UserHash: hashOf(9), CryptOptions: wire.CryptSupported | wire.CryptRequested},
		{LowID: 42, Port: 4663, Server: server},
		{IPv6: netip.MustParseAddr("2001:db8::8"), Port: 4664},
	}
	l.run(l.b, l.b.s.SendSources(file, sources))
	found := lastOf[SourcesFound](t, l.a)
	if found.File != file || len(found.Sources) != 3 {
		t.Fatalf("found %+v", found)
	}
	for i, src := range found.Sources {
		if src != sources[i] {
			t.Fatalf("source %d = %+v, want %+v", i, src, sources[i])
		}
	}

	l.sent = nil
	l.run(l.a, l.a.s.RequestSources(file, l.now.Add(39*time.Minute)))
	if len(l.sent) != 0 {
		t.Fatal("asked again within SOURCECLIENTREASKS")
	}
	l.run(l.a, l.a.s.RequestSources(file, l.now.Add(41*time.Minute)))
	if len(l.sent) != 1 {
		t.Fatal("did not ask after SOURCECLIENTREASKS")
	}
}

// An eMule peer speaks SX2 version 4 with hybrid ids and no IPv6.
func TestSourceExchangeWithEmule(t *testing.T) {
	s, _ := BuildOutgoing(buildConfig(t, 1), netip.MustParseAddrPort("10.0.0.2:4662"), start)
	file := hashOf(1)
	shares := func(wire.Hash) (Share, bool) { return Share{Size: piece.BlockSize}, true }
	s.OnPacket(client.HelloAnswer{
		UserHash:     hashOf(2),
		Name:         "eMule",
		EmuleVersion: 0<<24 | 0<<17 | 70<<10,
		Misc1:        client.MiscOptions1{ExtendedRequestsVersion: 2, HasMultiPacket: true, DataCompressionVersion: 1},
		Misc2:        client.MiscOptions2{HasSourceExchange2: true},
	}, shares, start)
	s.Add(file, piece.BlockSize, piece.Set{false})
	out := s.RequestSources(file, start)
	if r := out.Send[0].(client.MultiPacket).Requests[0].(client.RequestSources2); r.Version != client.SourceExchange2Version {
		t.Fatalf("version %d", r.Version)
	}
	answer := client.AnswerSources2{Version: 4, Hash: file, Sources: []client.Source{
		{ClientID: 0x05060700, Port: 4662, UserHash: hashOf(3), CryptOptions: 0x07},
		{ClientID: 42, Port: 4663},
	}}
	out = s.OnPacket(answer, shares, start)
	found := out.Events[0].(SourcesFound).Sources
	if found[0].IPv4 != netip.MustParseAddr("5.6.7.0") || found[1].LowID != 42 ||
		found[0].CryptOptions != 0x07 || !found[0].CanObfuscate() || found[1].CanObfuscate() {
		t.Fatalf("found %+v", found)
	}

	out = s.OnPacket(client.RequestSources2{Version: 4, Hash: file}, shares, start)
	if _, ok := out.Events[0].(SourcesRequested); !ok {
		t.Fatal("request not seen")
	}
	out = s.SendSources(file, []Source{
		{IPv4: netip.MustParseAddr("5.6.7.0"), Port: 4662, UserHash: hashOf(3), CryptOptions: wire.CryptSupported},
		{IPv6: netip.MustParseAddr("2001:db8::8"), Port: 4664},
	})
	sent := out.Send[0].(client.AnswerSources2)
	if sent.Version != 4 || len(sent.Sources) != 1 || sent.Sources[0].ClientID != 0x05060700 ||
		sent.Sources[0].UserHash != hashOf(3) || sent.Sources[0].CryptOptions != wire.CryptSupported {
		t.Fatalf("answer %+v", sent)
	}
	if out := s.OnPacket(client.RequestSources2{Version: 4, Hash: file}, shares, start.Add(time.Minute)); len(out.Events) != 0 {
		t.Fatal("answered again within SOURCECLIENTREASKS")
	}
	if out := s.SendQueueRank(70000); out.Send[0] != (client.QueueRanking{Rank: 0xFFFF}) {
		t.Fatalf("rank %+v", out.Send[0])
	}
}

func TestIdleConnectionTimesOut(t *testing.T) {
	l := buildLink(t)
	if out := l.a.s.OnTick(start.Add(39 * time.Second)); out.Close != "" {
		t.Fatal("closed early")
	}
	if out := l.a.s.OnTick(start.Add(41 * time.Second)); out.Close != CloseTimeout {
		t.Fatalf("close %q", out.Close)
	}
	s := BuildIncoming(buildConfig(t, 3), netip.MustParseAddrPort("10.0.0.9:1"), start)
	if out := s.OnTick(start.Add(41 * time.Second)); out.Close != CloseTimeout {
		t.Fatal("silent incoming connection kept")
	}
}

func TestSendingKeepsConnectionAlive(t *testing.T) {
	l := buildLink(t)
	l.a.s.OnSent(start.Add(30 * time.Second))
	if out := l.a.s.OnTick(start.Add(60 * time.Second)); out.Close != "" {
		t.Fatal("closed a connection we sent on 30 s ago")
	}
	if out := l.a.s.OnTick(start.Add(71 * time.Second)); out.Close != CloseTimeout {
		t.Fatalf("close %q", out.Close)
	}
}

func TestStalledSlotIsGivenUp(t *testing.T) {
	l := buildLink(t)
	file, _ := addShare(l.b, 1, piece.BlockSize, false)
	l.run(l.a, l.a.s.Add(file, piece.BlockSize, piece.Set{false}))
	l.run(l.a, l.a.s.Start(file))
	l.run(l.b, l.b.s.StartUpload())
	l.run(l.a, l.a.s.Request(file, []piece.Block{{Begin: 0, End: piece.BlockSize}}))
	keepalive := Output{Send: []wire.Packet{client.IPv6Changed{Addr: netip.MustParseAddr("2001:db8::9")}}}
	for elapsed := 30 * time.Second; elapsed <= 90*time.Second; elapsed += 30 * time.Second {
		l.now = start.Add(elapsed)
		l.run(l.b, keepalive)
		if out := l.a.s.OnTick(l.now); out.Close != "" || len(out.Send) != 0 {
			t.Fatalf("gave up after %v", elapsed)
		}
	}
	l.now = start.Add(101 * time.Second)
	l.run(l.b, keepalive)
	out := l.a.s.OnTick(l.now)
	if out.Close != "" || len(out.Send) != 1 || out.Send[0] != (client.CancelTransfer{}) {
		t.Fatalf("out %+v", out)
	}
	if ev := out.Events[0].(SlotRevoked); ev.File != file {
		t.Fatalf("revoked %+v", ev)
	}
}

// Shareaza and MLDonkey answer our Hello with OP_EMULEINFO first; seen on
// the real network, where closing here lost a working source.
func TestEmuleInfoBeforeHelloAnswer(t *testing.T) {
	s, _ := BuildOutgoing(buildConfig(t, 1), netip.MustParseAddrPort("10.0.0.2:4662"), start)
	out := s.OnPacket(client.EmuleInfo{Version: 0x30, ProtocolVersion: 1, Tags: []wire.Tag{
		{Type: wire.TagUint32, ID: client.InfoCompression, Uint: 1},
		{Type: wire.TagUint32, ID: client.InfoUDPPort, Uint: 4672},
	}}, nil, start)
	if out.Close != "" || len(out.Send) != 1 {
		t.Fatalf("early EmuleInfo: close %q, sent %+v", out.Close, out.Send)
	}
	if _, ok := out.Send[0].(client.EmuleInfoAnswer); !ok {
		t.Fatalf("sent %T", out.Send[0])
	}
	out = s.OnPacket(client.HelloAnswer{UserHash: hashOf(2), Name: "Shareaza", Port: 6346}, nil, start)
	if out.Close != "" {
		t.Fatalf("close %q", out.Close)
	}
	if _, ok := out.Events[0].(HandshakeCompleted); !ok {
		t.Fatalf("events %+v", out.Events)
	}
	if caps := s.Capabilities(); !caps.IsEmule || caps.MuleVersion != 0x30 || !caps.CanCompress || caps.UDPPort != 4672 || caps.Port != 6346 {
		t.Fatalf("capabilities %+v", caps)
	}
}

// Our Hello says what aMule's default says: obfuscation supported and
// requested, not required.
func TestHelloAdvertisesObfuscation(t *testing.T) {
	_, out := BuildOutgoing(buildConfig(t, 1), netip.MustParseAddrPort("10.0.0.2:4662"), start)
	m := out.Send[0].(client.Hello).Misc2
	if !m.CanCrypt || !m.IsCryptRequested || m.IsCryptRequired {
		t.Fatalf("misc2 %+v", m)
	}
}

// eMule ignores a request without support and a requirement without
// request.
func TestCryptOptionsReadAsEmuleDoes(t *testing.T) {
	for _, c := range []struct {
		misc2 client.MiscOptions2
		want  byte
	}{
		{client.MiscOptions2{IsCryptRequested: true, IsCryptRequired: true}, 0},
		{client.MiscOptions2{CanCrypt: true, IsCryptRequired: true}, wire.CryptSupported},
		{client.MiscOptions2{CanCrypt: true, IsCryptRequested: true, IsCryptRequired: true}, wire.CryptSupported | wire.CryptRequested | wire.CryptRequired},
	} {
		s, _ := BuildOutgoing(buildConfig(t, 1), netip.MustParseAddrPort("10.0.0.2:4662"), start)
		s.OnPacket(client.HelloAnswer{UserHash: hashOf(2), Misc2: c.misc2}, nil, start)
		if got := s.Capabilities().CryptOptions; got != c.want {
			t.Errorf("%+v: got %#x, want %#x", c.misc2, got, c.want)
		}
	}
}

func TestBuddyLinkTimesOutLater(t *testing.T) {
	l := buildLink(t)
	l.a.s.SetIdleTimeout(15 * time.Minute)
	if out := l.a.s.OnTick(start.Add(14 * time.Minute)); out.Close != "" {
		t.Fatal("closed a buddy link within its timeout")
	}
	if out := l.a.s.OnTick(start.Add(16 * time.Minute)); out.Close != CloseTimeout {
		t.Fatalf("close %q", out.Close)
	}
}

func TestHelloNamesBuddyAndKadVersion(t *testing.T) {
	cfg := buildConfig(t, 1)
	cfg.Buddy, cfg.KadVersion = netip.MustParseAddrPort("5.6.7.8:4672"), 7
	_, out := BuildOutgoing(cfg, netip.MustParseAddrPort("10.0.0.2:4662"), start)
	if h := out.Send[0].(client.Hello); h.Buddy != cfg.Buddy || h.Misc2.KadVersion != 7 {
		t.Fatalf("hello buddy %v, kad version %d", h.Buddy, h.Misc2.KadVersion)
	}
	b := BuildIncoming(buildConfig(t, 2), netip.MustParseAddrPort("10.0.0.1:4662"), start)
	b.OnPacket(out.Send[0], nil, start)
	if b.Capabilities().KadVersion != 7 {
		t.Fatalf("kad version %d", b.Capabilities().KadVersion)
	}
}

// eMule packs a block only when it shrinks (UploadDiskIOThread.cpp:581-583),
// so a packed size beyond the block is a peer making us buffer without end.
func TestCompressedPartLargerThanBlockCloses(t *testing.T) {
	l := buildLink(t)
	size := piece.BlockSize
	file, _ := addShare(l.b, 1, size, true)
	l.run(l.a, l.a.s.Add(file, size, piece.Set{false}))
	l.run(l.a, l.a.s.Start(file))
	l.run(l.b, l.b.s.StartUpload())
	l.run(l.a, l.a.s.Request(file, []piece.Block{{Begin: 0, End: size}}))
	l.run(l.b, Output{Send: []wire.Packet{client.CompressedPart{Hash: file, Start: 0, PackedSize: 1 << 30, Data: make([]byte, 10)}}})
	if l.a.closed != CloseProtocol {
		t.Fatalf("closed = %q, want protocol", l.a.closed)
	}
}
