package transfer_test

import (
	"math/rand/v2"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/aich"
	"github.com/XiaoYouChR/Kelpie/internal/link"
	"github.com/XiaoYouChR/Kelpie/internal/piece"
	"github.com/XiaoYouChR/Kelpie/internal/transfer"
	"github.com/XiaoYouChR/Kelpie/internal/wire"
	"github.com/XiaoYouChR/Kelpie/internal/wire/client"
)

var start = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

const path = "/downloads/file.bin"

// fileReaskTime is aMule's FILEREASKTIME, the reask interval of a queued
// source.
const fileReaskTime = 1300 * time.Second

func buildData(size int64) []byte {
	data := make([]byte, size)
	random := rand.New(rand.NewPCG(1, 2))
	for i := range data {
		data[i] = byte(random.Uint32())
	}
	return data
}

func buildFile(data []byte, sources ...netip.AddrPort) link.File {
	var hasher piece.FileHasher
	hasher.Write(data)
	return link.File{Name: "file.bin", Size: int64(len(data)), Hash: hasher.FileHash(), PartHashes: hasher.PartHashes(), Sources: sources}
}

func endpoint(i int) netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, byte(i >> 8), byte(i)}), 4662)
}

func userHash(i int) wire.Hash {
	return wire.Hash{byte(i), 0xAA}
}

// harness plays the engine: it performs Write and HashPart against an
// in-memory disk and feeds the answers back.
type harness struct {
	t        *testing.T
	transfer *transfer.Transfer
	// started holds the actions Build returned; a test runs them when it
	// needs them.
	started []transfer.Action
	data    []byte
	disk    []byte
	actions []transfer.Action
	now     time.Time
}

func buildHarness(t *testing.T, data []byte, options transfer.Options) *harness {
	if options.Random == nil {
		options.Random = rand.New(rand.NewPCG(3, 4))
	}
	if options.Path == "" {
		options.Path = path
	}
	tr, started := transfer.Build(options, start)
	return &harness{t: t, transfer: tr, started: started, data: data, disk: make([]byte, len(data)), now: start}
}

func (h *harness) run(actions []transfer.Action) {
	for len(actions) > 0 {
		action := actions[0]
		actions = actions[1:]
		h.actions = append(h.actions, action)
		switch a := action.(type) {
		case transfer.Write:
			copy(h.disk[a.Block.Begin:a.Block.End], a.Data)
			actions = append(actions, h.transfer.OnBlockWritten(a.Block)...)
		case transfer.HashPart:
			var hasher piece.MD4
			r := piece.PartRange(int64(len(h.disk)), a.Part)
			hasher.Write(h.disk[r.Begin:r.End])
			actions = append(actions, h.transfer.OnPartHashed(a.Part, hasher.Digest(), h.now)...)
		case transfer.HashBlocks:
			var hasher aich.Hasher
			r := piece.PartRange(int64(len(h.disk)), a.Part)
			hasher.Write(h.disk[r.Begin:r.End])
			actions = append(actions, h.transfer.OnBlocksHashed(a.Part, hasher.Leaves(), h.now)...)
		}
	}
}

func (h *harness) tick(tick transfer.Tick) []transfer.Action {
	if tick.Now.IsZero() {
		tick.Now = h.now
	}
	before := len(h.actions)
	h.run(h.transfer.OnTick(tick))
	return h.actions[before:]
}

func (h *harness) connect(peer uint64, i int, parts piece.Set) {
	h.run(h.transfer.OnPeerConnected(peer, transfer.Source{Endpoint: endpoint(i), UserHash: userHash(i)}, h.now))
	h.transfer.OnPeerParts(peer, parts)
	h.transfer.OnSlotAsked(peer, h.now)
	h.run(h.transfer.OnSlotGranted(peer, h.now))
}

// request asks the transfer for up to n blocks for peer and runs the
// actions that come with them.
func (h *harness) request(peer uint64, n int) []piece.Block {
	blocks, actions := h.transfer.Request(peer, n, h.now)
	h.run(actions)
	return blocks
}

// deliver requests up to n blocks for peer and answers each with data,
// corrupted when isCorrupt is set. It reports how many blocks were sent.
func (h *harness) deliver(peer uint64, n int, isCorrupt bool) int {
	blocks := h.request(peer, n)
	for _, block := range blocks {
		data := append([]byte(nil), h.data[block.Begin:block.End]...)
		if isCorrupt {
			data[0] ^= 0xFF
		}
		h.run(h.transfer.OnBlockReceived(peer, block, data, h.now))
	}
	return len(blocks)
}

func countActions[A transfer.Action](actions []transfer.Action) int {
	count := 0
	for _, action := range actions {
		if _, ok := action.(A); ok {
			count++
		}
	}
	return count
}

func traces(actions []transfer.Action, event transfer.Event) []transfer.TraceEvent {
	var events []transfer.TraceEvent
	for _, action := range actions {
		if e, ok := action.(transfer.TraceEvent); ok && e.Event == event {
			events = append(events, e)
		}
	}
	return events
}

func TestMultiSourceDownloadCompletes(t *testing.T) {
	data := buildData(2*piece.PartSize + 5000)
	file := buildFile(data, endpoint(1), endpoint(2))
	h := buildHarness(t, data, transfer.Options{File: file})

	if got := len(traces(h.started, transfer.EventFound)); got != 2 {
		t.Fatalf("found traces = %d, want 2", got)
	}
	connects := h.tick(transfer.Tick{ConnectBudget: 10})
	if got := countActions[transfer.Connect](connects); got != 2 {
		t.Fatalf("Connect actions = %d, want 2", got)
	}
	if got := len(traces(connects, transfer.EventFound)); got != 0 {
		t.Fatalf("found traces = %d, want 2", got)
	}
	full := piece.BuildFullSet(piece.PartCount(file.Size))
	h.connect(1, 1, full)
	h.connect(2, 2, full)

	sent := map[uint64]int{}
	for h.transfer.Outcome().Status == transfer.StatusRunning {
		n1, n2 := h.deliver(1, 3, false), h.deliver(2, 3, false)
		sent[1] += n1
		sent[2] += n2
		if n1+n2 == 0 {
			t.Fatal("no blocks left to request before completion")
		}
	}
	if got := h.transfer.Outcome(); got.Status != transfer.StatusComplete {
		t.Fatalf("outcome = %+v, want complete", got)
	}
	if sent[1] == 0 || sent[2] == 0 {
		t.Fatalf("blocks per peer = %v, want both peers used", sent)
	}
	if string(h.disk) != string(data) {
		t.Fatal("disk content differs from the source data")
	}
	progress := h.transfer.Progress(h.now)
	if progress.Received != file.Size || progress.Size != file.Size || progress.DownloadRate == 0 {
		t.Fatalf("progress = %+v", progress)
	}
}

func TestResumeFromPersistedState(t *testing.T) {
	data := buildData(2*piece.PartSize + 5000)
	file := buildFile(data)
	h := buildHarness(t, data, transfer.Options{File: file})
	parts := piece.Set{true, false, false}
	h.connect(1, 1, parts)
	for h.deliver(1, 10, false) > 0 {
	}
	h.transfer.OnPeerParts(1, piece.Set{false, true, false})
	h.deliver(1, 5, false)
	state := h.transfer.ToState()
	if !state.VerifiedParts[0] || len(state.WrittenBlocks) != 5 {
		t.Fatalf("state = verified %v, written %d blocks", state.VerifiedParts, len(state.WrittenBlocks))
	}

	resumed := buildHarness(t, data, transfer.Options{File: file, State: &state})
	if got, want := resumed.transfer.Progress(start).Received, piece.PartSize+5*piece.BlockSize; got != want {
		t.Fatalf("resumed received = %d, want %d", got, want)
	}
	again := resumed.transfer.ToState()
	if len(again.WrittenBlocks) != 5 || !again.VerifiedParts[0] || again.Created != state.Created {
		t.Fatalf("state after resume = %+v", again)
	}
}

func TestResumeHashesWrittenParts(t *testing.T) {
	data := buildData(piece.PartSize + 100)
	file := buildFile(data)
	var blocks []piece.Block
	for i := range piece.BlockCount(file.Size, 0) {
		blocks = append(blocks, piece.BlockOf(file.Size, 0, i))
	}
	state := transfer.State{Size: file.Size, File: path, VerifiedParts: []bool{false, false}, WrittenBlocks: blocks, Created: start}
	h := buildHarness(t, data, transfer.Options{File: file, State: &state})
	copy(h.disk, data[:piece.PartSize])

	if got := countActions[transfer.HashPart](h.started); got != 1 {
		t.Fatalf("HashPart actions = %d, want 1", got)
	}
	h.run(h.started)
	if !h.transfer.ToState().VerifiedParts[0] {
		t.Fatal("part 0 not verified after resume hashing")
	}
}

func TestHashSetRequestedWhenMissing(t *testing.T) {
	data := buildData(piece.PartSize + 100)
	file := buildFile(data)
	partHashes := file.PartHashes
	file.PartHashes = nil
	h := buildHarness(t, data, transfer.Options{File: file})
	h.connect(1, 1, piece.Set{true, true})
	for h.deliver(1, 100, false) > 0 {
	}
	if got := countActions[transfer.HashPart](h.actions); got != 0 {
		t.Fatalf("HashPart before hash set = %d, want 0", got)
	}
	if got := countActions[transfer.RequestHashSet](h.tick(transfer.Tick{})); got != 1 {
		t.Fatalf("RequestHashSet = %d, want 1", got)
	}
	if got := countActions[transfer.RequestHashSet](h.tick(transfer.Tick{})); got != 0 {
		t.Fatalf("second RequestHashSet while one is pending = %d, want 0", got)
	}
	h.run(h.transfer.OnHashSet(1, partHashes))
	if got := h.transfer.Outcome().Status; got != transfer.StatusComplete {
		t.Fatalf("status = %v, want complete", got)
	}
}

// Without AICH a corrupt part is downloaded again whole and nobody is
// banned: MD4 cannot tell which sender was corrupt (aMule
// PartFile.cpp:3719-3732).
func TestCorruptPartWithoutAICHIsDownloadedAgain(t *testing.T) {
	data := buildData(2*piece.PartSize + 5000)
	file := buildFile(data)
	h := buildHarness(t, data, transfer.Options{File: file})
	h.connect(1, 1, piece.Set{true, false, false})
	h.connect(2, 2, piece.Set{false, true, true})

	before := len(h.actions)
	if got := h.deliver(1, 100, true); got != piece.BlockCount(file.Size, 0) {
		t.Fatalf("delivered %d blocks, want all of part 0", got)
	}
	if countActions[transfer.HashPart](h.actions[before:]) != 1 || h.transfer.ToState().VerifiedParts[0] {
		t.Fatalf("corrupt part not hashed once and refused: %+v", h.actions[before:])
	}
	if closed := closedPeers(h.actions[before:]); len(closed) != 0 {
		t.Fatalf("closed %v without AICH to tell the corrupt sender", closed)
	}
	if !h.transfer.MatchSource(transfer.Source{UserHash: userHash(1)}) {
		t.Fatal("sender of the corrupt part dropped")
	}

	h.transfer.OnPeerParts(2, piece.BuildFullSet(3))
	for h.transfer.Outcome().Status == transfer.StatusRunning {
		if h.deliver(2, 10, false) == 0 {
			t.Fatal("peer 2 has nothing to send before completion")
		}
	}
	if string(h.disk) != string(data) {
		t.Fatal("disk content differs after redownload")
	}
}

func TestDiskFailure(t *testing.T) {
	for isDiskFull, want := range map[bool]transfer.Status{true: transfer.StatusDiskFull, false: transfer.StatusFailed} {
		data := buildData(1000)
		h := buildHarness(t, data, transfer.Options{File: buildFile(data)})
		h.connect(1, 1, piece.Set{true})
		blocks := h.request(1, 1)
		actions := h.transfer.OnBlockReceived(1, blocks[0], data, h.now)
		if countActions[transfer.Write](actions) != 1 {
			t.Fatalf("no Write for a received block: %+v", actions)
		}
		h.transfer.OnDiskFailed(isDiskFull, "no space left on device")
		got := h.transfer.Outcome()
		if got.Status != want {
			t.Fatalf("isDiskFull=%v: outcome = %+v", isDiskFull, got)
		}
		if h.request(1, 1) != nil {
			t.Fatal("failed transfer still hands out requests")
		}
	}
}

func TestReaskTiming(t *testing.T) {
	data := buildData(1000)
	for _, test := range []struct {
		name        string
		canReaskUDP bool
	}{{"udp", true}, {"tcp", false}} {
		t.Run(test.name, func(t *testing.T) {
			h := buildHarness(t, data, transfer.Options{File: buildFile(data, endpoint(1))})
			h.tick(transfer.Tick{ConnectBudget: 1})
			h.run(h.transfer.OnPeerConnected(1, transfer.Source{Endpoint: endpoint(1), UserHash: userHash(1), UDPPort: 4672, CanReaskUDP: test.canReaskUDP, CanObfuscate: true}, start))
			h.run(h.transfer.OnQueued(1, 42, start))
			h.run(h.transfer.OnPeerGone(1, "idle", start))

			at := func(d time.Duration) []transfer.Action {
				return h.tick(transfer.Tick{Now: start.Add(d), ConnectBudget: 1})
			}
			if got := at(fileReaskTime - 20*time.Second); len(got) != 0 {
				t.Fatalf("actions 20 s before reask: %+v", got)
			}
			udp := at(fileReaskTime - 20*time.Second + time.Second)
			wantUDP := 0
			if test.canReaskUDP {
				wantUDP = 1
			}
			if countActions[transfer.ReaskUDP](udp) != wantUDP || countActions[transfer.Connect](udp) != 0 {
				t.Fatalf("near reask: %+v", udp)
			}
			if test.canReaskUDP {
				want := transfer.ReaskUDP{Endpoint: netip.AddrPortFrom(endpoint(1).Addr(), 4672), UserHash: userHash(1), CanObfuscate: true}
				if udp[0] != want {
					t.Fatalf("reask %+v, want %+v: obfuscated with the Hello's user hash", udp[0], want)
				}
				h.run(h.transfer.OnReaskAnswered(netip.AddrPortFrom(endpoint(1).Addr(), 4672), client.ReaskAck{Rank: 7}, start.Add(fileReaskTime-20*time.Second+2*time.Second)))
				if got := at(fileReaskTime); countActions[transfer.Connect](got) != 0 {
					t.Fatalf("TCP reask after a UDP answer: %+v", got)
				}
				return
			}
			if got := at(fileReaskTime - time.Second); countActions[transfer.Connect](got) != 0 {
				t.Fatalf("Connect before FILEREASKTIME: %+v", got)
			}
			if got := at(fileReaskTime); countActions[transfer.Connect](got) != 1 {
				t.Fatalf("no Connect at FILEREASKTIME: %+v", got)
			}
		})
	}
}

// A source that failed waits 30 minutes, one reached by callback 45
// (aMule's global DeadSourceList).
// OP_QUEUEFULL answers a UDP reask as rank 0; OP_FILENOTFOUND puts the
// source on the file's dead list for 45 minutes.
func TestReaskRefusals(t *testing.T) {
	data := buildData(1000)
	udp := netip.AddrPortFrom(endpoint(1).Addr(), 4672)
	reaskAt := fileReaskTime - 19*time.Second
	for _, test := range []struct {
		name     string
		answer   func(*transfer.Transfer, time.Time) []transfer.Action
		wantNext time.Duration
	}{
		{"queue full", func(tr *transfer.Transfer, now time.Time) []transfer.Action {
			return tr.OnReaskAnswered(udp, client.QueueFull{}, now)
		}, reaskAt + reaskAt},
		{"file not found", func(tr *transfer.Transfer, now time.Time) []transfer.Action {
			return tr.OnReaskAnswered(udp, client.FileNotFound{}, now)
		}, reaskAt + 45*time.Minute},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := buildHarness(t, data, transfer.Options{File: buildFile(data, endpoint(1))})
			h.tick(transfer.Tick{ConnectBudget: 1})
			h.run(h.transfer.OnPeerConnected(1, transfer.Source{Endpoint: endpoint(1), UserHash: userHash(1), UDPPort: 4672, CanReaskUDP: true}, start))
			h.run(h.transfer.OnQueued(1, 42, start))
			h.run(h.transfer.OnPeerGone(1, "idle", start))
			at := func(d time.Duration) []transfer.Action {
				return h.tick(transfer.Tick{Now: start.Add(d), ConnectBudget: 1})
			}
			if got := at(reaskAt); countActions[transfer.ReaskUDP](got) != 1 {
				t.Fatalf("no UDP reask: %+v", got)
			}
			h.run(test.answer(h.transfer, start.Add(reaskAt)))
			if got := at(test.wantNext - time.Second); len(got) != 0 {
				t.Fatalf("asked again early: %+v", got)
			}
			if got := at(test.wantNext); len(got) == 0 {
				t.Fatal("not asked again")
			}
		})
	}
}

// A source due a Source Exchange is reasked over TCP, which can carry it,
// instead of over UDP.
func TestReaskDueExchangeSkipsUDP(t *testing.T) {
	data := buildData(1000)
	h := buildHarness(t, data, transfer.Options{File: buildFile(data, endpoint(1))})
	h.tick(transfer.Tick{ConnectBudget: 1})
	hello := transfer.Source{Endpoint: endpoint(1), UserHash: userHash(1), UDPPort: 4672, CanReaskUDP: true, CanExchange: true}
	if got := h.transfer.OnPeerConnected(1, hello, start); countActions[transfer.RequestSources](got) != 1 {
		t.Fatalf("no Source Exchange at the first connection: %+v", got)
	}
	h.run(h.transfer.OnQueued(1, 42, start))
	h.run(h.transfer.OnPeerGone(1, "idle", start))
	reaskAt := fileReaskTime - 10*time.Second
	if got := h.tick(transfer.Tick{Now: start.Add(reaskAt), ConnectBudget: 1}); countActions[transfer.ReaskUDP](got) != 1 {
		t.Fatalf("no UDP reask before the exchange is due: %+v", got)
	}
	answered := start.Add(reaskAt)
	h.run(h.transfer.OnReaskAnswered(netip.AddrPortFrom(endpoint(1).Addr(), 4672), client.ReaskAck{Rank: 7}, answered))

	next := answered.Add(fileReaskTime - 10*time.Second)
	if got := h.tick(transfer.Tick{Now: next, ConnectBudget: 1}); len(got) != 0 {
		t.Fatalf("UDP reask while an exchange is due: %+v", got)
	}
	if got := h.tick(transfer.Tick{Now: answered.Add(fileReaskTime), ConnectBudget: 1}); countActions[transfer.Connect](got) != 1 {
		t.Fatalf("no TCP reask: %+v", got)
	}
}

func TestFailedSourceBacksOff(t *testing.T) {
	data := buildData(1000)
	server := endpoint(9999)
	h := buildHarness(t, data, transfer.Options{File: buildFile(data, endpoint(1))})
	h.transfer.OnSourcesFound([]transfer.Source{lowIDSource(2, server)}, transfer.ChannelServer, start)
	h.tick(transfer.Tick{ConnectBudget: 2, Server: server})
	failed := h.transfer.OnConnectFailed(endpoint(1), "refused", start)
	if events := traces(failed, transfer.EventFailed); len(events) != 1 || events[0].Reason != "refused" {
		t.Fatalf("failed trace: %+v", failed)
	}
	h.tick(transfer.Tick{Now: start.Add(40 * time.Second), ConnectBudget: 2, Server: server})

	at := func(d time.Duration) []transfer.Action {
		return h.tick(transfer.Tick{Now: start.Add(d), ConnectBudget: 2, Server: server})
	}
	if got := at(30*time.Minute - time.Second); len(got) != 0 {
		t.Fatalf("asked during backoff: %+v", got)
	}
	if got := at(30 * time.Minute); countActions[transfer.Connect](got) != 1 || countActions[transfer.RequestServerCallback](got) != 0 {
		t.Fatalf("want only the HighID source asked after 30 minutes: %+v", got)
	}
	if got := at(40*time.Second + 45*time.Minute); countActions[transfer.RequestServerCallback](got) != 1 {
		t.Fatalf("no callback 45 minutes after it timed out: %+v", got)
	}
}

func TestConnectBudget(t *testing.T) {
	data := buildData(1000)
	h := buildHarness(t, data, transfer.Options{File: buildFile(data, endpoint(1), endpoint(2), endpoint(3))})
	if got := countActions[transfer.Connect](h.tick(transfer.Tick{ConnectBudget: 1})); got != 1 {
		t.Fatalf("Connect with budget 1 = %d", got)
	}
	if got := countActions[transfer.Connect](h.tick(transfer.Tick{ConnectBudget: 0})); got != 0 {
		t.Fatalf("Connect with budget 0 = %d", got)
	}
	if got := countActions[transfer.Connect](h.tick(transfer.Tick{ConnectBudget: 5})); got != 2 {
		t.Fatalf("Connect for waiting sources = %d, want 2", got)
	}
}

func TestSourceCap(t *testing.T) {
	data := buildData(1000)
	h := buildHarness(t, data, transfer.Options{File: buildFile(data)})
	var found []transfer.Source
	for i := range 450 {
		found = append(found, transfer.Source{Endpoint: endpoint(i + 1)})
	}
	found = append(found, found[0])
	actions := h.transfer.OnSourcesFound(found, transfer.ChannelServer, start)
	if got := len(traces(actions, transfer.EventFound)); got != 400 {
		t.Fatalf("found traces = %d, want 400", got)
	}
	if got := h.transfer.Progress(start).Peers; got != 400 {
		t.Fatalf("peers = %d, want 400", got)
	}
	incoming := h.transfer.OnPeerConnected(1, transfer.Source{Endpoint: endpoint(1000)}, start)
	if len(incoming) != 1 || incoming[0] != (transfer.Close{Peer: 1, Reason: "too many sources"}) {
		t.Fatalf("incoming beyond the cap: %+v", incoming)
	}
}

// A peer is a known source by user hash or LowID while the transfer keeps
// it.
func TestMatchSource(t *testing.T) {
	data := buildData(1000)
	h := buildHarness(t, data, transfer.Options{File: buildFile(data)})
	server := endpoint(9999)
	h.run(h.transfer.OnSourcesFound([]transfer.Source{
		{Endpoint: endpoint(1), UserHash: userHash(1)},
		lowIDSource(2, server),
		{Endpoint: endpoint(3)},
	}, transfer.ChannelServer, start))

	for _, found := range []transfer.Source{
		{UserHash: userHash(1)},
		{UserHash: userHash(7), ClientID: 3, Server: server},
	} {
		if !h.transfer.MatchSource(found) {
			t.Fatalf("%+v not matched", found)
		}
	}
	for _, found := range []transfer.Source{
		{UserHash: userHash(2)},
		{ClientID: 3, Server: endpoint(8888)},
		{ClientID: wire.ToClientID(endpoint(3).Addr())},
		{},
	} {
		if h.transfer.MatchSource(found) {
			t.Fatalf("%+v matched", found)
		}
	}

	h.transfer.OnPeerConnected(1, transfer.Source{Endpoint: endpoint(3), UserHash: userHash(3)}, start)
	if !h.transfer.MatchSource(transfer.Source{UserHash: userHash(3)}) {
		t.Fatal("user hash from the Hello not matched")
	}
}

func TestLowIDSourceNeedsServerCallback(t *testing.T) {
	data := buildData(1000)
	h := buildHarness(t, data, transfer.Options{File: buildFile(data)})
	server := endpoint(9999)
	h.run(h.transfer.OnSourcesFound([]transfer.Source{{ClientID: 1234, Server: server}}, transfer.ChannelServer, start))

	if got := h.tick(transfer.Tick{ConnectBudget: 1, Server: endpoint(8888)}); countActions[transfer.RequestServerCallback](got) != 0 {
		t.Fatalf("callback through another server: %+v", got)
	}
	got := h.tick(transfer.Tick{ConnectBudget: 1, Server: server})
	if countActions[transfer.RequestServerCallback](got) != 1 {
		t.Fatalf("no callback on the shared server: %+v", got)
	}
	timeout := h.tick(transfer.Tick{Now: start.Add(40 * time.Second), Server: server})
	if events := traces(timeout, transfer.EventFailed); len(events) != 1 {
		t.Fatalf("callback timeout not reported: %+v", timeout)
	}
}

// A callback is the peer connecting to us, so it needs no room in the
// budget for connections we open.
func TestCallbackNeedsNoConnectBudget(t *testing.T) {
	data := buildData(1000)
	h := buildHarness(t, data, transfer.Options{File: buildFile(data)})
	server := endpoint(9999)
	h.run(h.transfer.OnSourcesFound([]transfer.Source{{ClientID: 1234, Server: server}}, transfer.ChannelServer, start))
	if got := h.tick(transfer.Tick{ConnectBudget: 0, Server: server}); countActions[transfer.RequestServerCallback](got) != 1 {
		t.Fatalf("callback held back by a spent budget: %+v", got)
	}
}

func TestSeedMode(t *testing.T) {
	data := buildData(piece.PartSize + 100)
	file := buildFile(data)
	incomplete := buildHarness(t, data, transfer.Options{File: file, Mode: transfer.ModeSeed})
	if got := incomplete.transfer.Outcome(); got.Status != transfer.StatusFailed {
		t.Fatalf("seed of an incomplete file: %+v", got)
	}

	state := transfer.State{Size: file.Size, File: path, PartHashes: file.PartHashes, VerifiedParts: []bool{true, true}, Uploaded: 500, Created: start}
	h := buildHarness(t, data, transfer.Options{File: file, Mode: transfer.ModeSeed, State: &state})
	if got := h.transfer.Outcome(); got.Status != transfer.StatusRunning {
		t.Fatalf("seed of a complete file: %+v", got)
	}
	if got := h.tick(transfer.Tick{ConnectBudget: 5, Server: endpoint(1)}); len(got) != 0 {
		t.Fatalf("seed tick: %+v", got)
	}
	h.transfer.OnUploaded(1000, start)
	if got := h.transfer.Progress(start); got.Uploaded != 1500 || got.UploadRate == 0 {
		t.Fatalf("seed progress: %+v", got)
	}
	if got := h.transfer.ToState().Uploaded; got != 1500 {
		t.Fatalf("persisted uploaded = %d", got)
	}
}

// Sources that require obfuscation close a plain connection at once, so a
// Connect carries what the engine needs to obfuscate: the user hash and the
// support bit, which a later channel may add.
func TestConnectCarriesObfuscation(t *testing.T) {
	data := buildData(1000)
	h := buildHarness(t, data, transfer.Options{File: buildFile(data)})
	h.run(h.transfer.OnSourcesFound([]transfer.Source{{Endpoint: endpoint(1)}}, transfer.ChannelServer, start))
	h.run(h.transfer.OnSourcesFound([]transfer.Source{{Endpoint: endpoint(1), UserHash: userHash(1), CanObfuscate: true}}, transfer.ChannelKad, start))
	var connects []transfer.Connect
	for _, action := range h.tick(transfer.Tick{ConnectBudget: 1}) {
		if c, ok := action.(transfer.Connect); ok {
			connects = append(connects, c)
		}
	}
	want := transfer.Connect{Endpoint: endpoint(1), UserHash: userHash(1), CanObfuscate: true}
	if len(connects) != 1 || connects[0] != want {
		t.Fatalf("connects %+v", connects)
	}
}

func connects(actions []transfer.Action) []transfer.Connect {
	var found []transfer.Connect
	for _, action := range actions {
		if c, ok := action.(transfer.Connect); ok {
			found = append(found, c)
		}
	}
	return found
}

func TestPlainDialIsRetriedObfuscatedOnceTheHashIsKnown(t *testing.T) {
	obfuscated := transfer.Connect{Endpoint: endpoint(1), UserHash: userHash(1), CanObfuscate: true}
	for _, isHashLate := range []bool{false, true} {
		data := buildData(1000)
		h := buildHarness(t, data, transfer.Options{File: buildFile(data)})
		h.run(h.transfer.OnSourcesFound([]transfer.Source{{Endpoint: endpoint(1)}}, transfer.ChannelGlobalServer, start))
		if got := connects(h.tick(transfer.Tick{ConnectBudget: 1})); len(got) != 1 || got[0].CanObfuscate {
			t.Fatalf("first connects %+v", got)
		}
		kad := []transfer.Source{{Endpoint: endpoint(1), UserHash: userHash(1), CanObfuscate: true}}
		if !isHashLate {
			h.run(h.transfer.OnSourcesFound(kad, transfer.ChannelKad, start))
		}
		h.run(h.transfer.OnConnectFailed(endpoint(1), "EOF", start))
		if isHashLate {
			h.run(h.transfer.OnSourcesFound(kad, transfer.ChannelKad, start))
		}
		if got := connects(h.tick(transfer.Tick{ConnectBudget: 1})); len(got) != 1 || got[0] != obfuscated {
			t.Fatalf("isHashLate=%v retry connects %+v", isHashLate, got)
		}
		h.run(h.transfer.OnConnectFailed(endpoint(1), "EOF", start))
		h.run(h.transfer.OnSourcesFound(kad, transfer.ChannelKad, start))
		if got := connects(h.tick(transfer.Tick{ConnectBudget: 1})); len(got) != 0 {
			t.Fatalf("isHashLate=%v obfuscated failure retried: %+v", isHashLate, got)
		}
	}
}

func TestPlainDialFailureWithoutHashStaysDead(t *testing.T) {
	data := buildData(1000)
	h := buildHarness(t, data, transfer.Options{File: buildFile(data)})
	h.run(h.transfer.OnSourcesFound([]transfer.Source{{Endpoint: endpoint(1)}}, transfer.ChannelGlobalServer, start))
	h.tick(transfer.Tick{ConnectBudget: 1})
	h.run(h.transfer.OnConnectFailed(endpoint(1), "EOF", start))
	h.run(h.transfer.OnSourcesFound([]transfer.Source{{Endpoint: endpoint(1)}}, transfer.ChannelServer, start))
	if got := connects(h.tick(transfer.Tick{ConnectBudget: 1})); len(got) != 0 {
		t.Fatalf("connects %+v", got)
	}
}

func lowIDSource(i int, server netip.AddrPort) transfer.Source {
	return transfer.Source{ClientID: uint32(i + 1), Server: server}
}

func buddySource(i int) transfer.Source {
	return transfer.Source{Buddy: endpoint(5000 + i), BuddyID: userHash(i), UserHash: userHash(i)}
}

func TestFirewalledDropsLowIDSources(t *testing.T) {
	data := buildData(1000)
	h := buildHarness(t, data, transfer.Options{File: buildFile(data)})
	server := endpoint(9999)
	h.run(h.transfer.OnSourcesFound([]transfer.Source{lowIDSource(1, server)}, transfer.ChannelServer, start))
	if got := h.transfer.Progress(start).Peers; got != 1 {
		t.Fatalf("peers while HighID = %d, want 1", got)
	}

	h.tick(transfer.Tick{Server: server, IsFirewalled: true})
	if got := h.transfer.Progress(start).Peers; got != 0 {
		t.Fatalf("stored LowID source kept after we became firewalled: peers = %d", got)
	}
	for i, channel := range []transfer.Channel{transfer.ChannelServer, transfer.ChannelGlobalServer, transfer.ChannelExchange} {
		actions := h.transfer.OnSourcesFound([]transfer.Source{lowIDSource(2, server), buddySource(i)}, channel, start)
		if found := traces(actions, transfer.EventFound); len(found) != 1 || found[0].Source != "kad:"+userHash(i).String() {
			t.Fatalf("%s while firewalled: found %+v, want only the Kad buddy source", channel, found)
		}
	}
}

// Sources we cannot reach must not fill the cap.
func TestUnreachableSourcesAreNotCounted(t *testing.T) {
	data := buildData(1000)
	h := buildHarness(t, data, transfer.Options{File: buildFile(data)})
	server := endpoint(9999)
	h.tick(transfer.Tick{Server: server, IsFirewalled: true})
	var found []transfer.Source
	for i := range 400 {
		found = append(found, buddySource(i))
	}
	h.run(h.transfer.OnSourcesFound(found, transfer.ChannelKad, start))

	actions := h.transfer.OnSourcesFound([]transfer.Source{{Endpoint: endpoint(1)}}, transfer.ChannelKad, start)
	if got := len(traces(actions, transfer.EventFound)); got != 1 {
		t.Fatalf("HighID source refused at the cap of unreachable sources: %+v", actions)
	}
}

func TestSlotAskedSourceStaysQueuedWhenClosedBeforeRank(t *testing.T) {
	data := buildData(1000)
	h := buildHarness(t, data, transfer.Options{File: buildFile(data, endpoint(1), endpoint(2))})
	h.tick(transfer.Tick{ConnectBudget: 2})
	h.run(h.transfer.OnPeerConnected(1, transfer.Source{Endpoint: endpoint(1), UserHash: userHash(1)}, start))
	h.run(h.transfer.OnPeerConnected(2, transfer.Source{Endpoint: endpoint(2), UserHash: userHash(2)}, start))
	h.transfer.OnPeerParts(1, piece.Set{true})

	asked := h.transfer.OnPeerGone(1, "idle", start.Add(40*time.Second))
	if got := traces(asked, transfer.EventFailed); len(got) != 0 {
		t.Fatalf("source asked for a slot marked failed: %+v", asked)
	}
	silent := h.transfer.OnPeerGone(2, "idle", start.Add(40*time.Second))
	if got := traces(silent, transfer.EventFailed); len(got) != 1 {
		t.Fatalf("source that never answered the file request not failed: %+v", silent)
	}

	at := func(d time.Duration) []transfer.Action {
		return h.tick(transfer.Tick{Now: start.Add(d), ConnectBudget: 2})
	}
	if got := at(fileReaskTime - time.Second); countActions[transfer.Connect](got) != 0 {
		t.Fatalf("Connect before the reask interval: %+v", got)
	}
	got := at(fileReaskTime)
	if countActions[transfer.Connect](got) != 1 || got[0] != (transfer.Connect{Endpoint: endpoint(1), UserHash: userHash(1)}) {
		t.Fatalf("queued source not reasked at the reask interval: %+v", got)
	}
}

// A source whose slot ended goes back to its queue and is reasked a whole
// reask interval later, not after MIN_REQUESTTIME.
// The reask after a slot counts from when we connected, not from the end of
// the slot: a source whose reask came due meanwhile is asked again at once
// (aMule sets m_dwLastAskedTime only when it asks).
func TestEndedSlotIsReaskedAfterReaskTime(t *testing.T) {
	for _, test := range []struct {
		name     string
		slot     time.Duration
		reaskAt  time.Duration
		isQueued bool
	}{
		{"short slot closed", time.Minute, fileReaskTime, false},
		{"short slot queued", time.Minute, fileReaskTime, true},
		{"long slot", fileReaskTime + time.Hour, fileReaskTime + time.Hour + 40*time.Second, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := buildData(piece.PartSize + 100)
			h := buildHarness(t, data, transfer.Options{File: buildFile(data)})
			h.connect(1, 1, piece.Set{true, true})
			h.deliver(1, 1, false)
			ended := start.Add(test.slot)
			if test.isQueued {
				h.run(h.transfer.OnQueued(1, 0, ended))
			}
			closed := test.slot + 40*time.Second
			h.run(h.transfer.OnPeerGone(1, "idle", start.Add(closed)))

			at := func(d time.Duration) []transfer.Action {
				return h.tick(transfer.Tick{Now: start.Add(d), ConnectBudget: 1})
			}
			if before := test.reaskAt - time.Second; before >= closed {
				if got := at(before); countActions[transfer.Connect](got) != 0 {
					t.Fatalf("Connect before the reask: %+v", got)
				}
			}
			if got := at(test.reaskAt); countActions[transfer.Connect](got) != 1 {
				t.Fatalf("no Connect at the reask: %+v", got)
			}
		})
	}
}

func TestBadSourceAddressesAreDropped(t *testing.T) {
	data := buildData(1000)
	self := netip.MustParseAddr("203.0.113.7")
	bad := []string{
		"10.1.2.3:4662", "172.16.0.1:4662", "192.168.1.2:4662", "[fd00::1]:4662",
		"127.0.0.1:4662", "[::1]:4662", "169.254.1.1:4662", "[fe80::1]:4662",
		"224.0.0.1:4662", "[ff02::1]:4662", "0.0.0.0:4662", "[::]:4662",
		"0.1.2.3:4662", "255.1.2.3:4662", "255.255.255.255:4662", "[::ffff:192.168.1.2]:4662",
		"203.0.113.7:4662",
	}
	channels := []transfer.Channel{transfer.ChannelServer, transfer.ChannelGlobalServer, transfer.ChannelKad, transfer.ChannelExchange}
	for _, channel := range channels {
		h := buildHarness(t, data, transfer.Options{File: buildFile(data)})
		h.tick(transfer.Tick{PublicIP: self, Port: 4662})
		var found []transfer.Source
		for _, endpoint := range bad {
			found = append(found, transfer.Source{Endpoint: netip.MustParseAddrPort(endpoint)})
		}
		found = append(found,
			transfer.Source{Buddy: netip.MustParseAddrPort("192.168.1.9:4672"), BuddyID: userHash(1), UserHash: userHash(1)},
			transfer.Source{Endpoint: netip.MustParseAddrPort("203.0.113.7:4663")},
			transfer.Source{Endpoint: netip.MustParseAddrPort("[2001:db8::1]:4662")},
		)
		got := traces(h.transfer.OnSourcesFound(found, channel, start), transfer.EventFound)
		if len(got) != 2 || got[0].Source != "203.0.113.7:4663" || got[1].Source != "[2001:db8::1]:4662" {
			t.Fatalf("%s: found %+v, want only another client behind our IP and the public IPv6 source", channel, got)
		}
	}

	link := buildFile(data, netip.MustParseAddrPort("192.168.1.2:4662"), endpoint(1))
	h := buildHarness(t, data, transfer.Options{File: link})
	if got := countActions[transfer.Connect](h.tick(transfer.Tick{ConnectBudget: 5})); got != 1 {
		t.Fatalf("Connect for link sources = %d, want 1", got)
	}

	firewalled := buildHarness(t, data, transfer.Options{File: buildFile(data)})
	firewalled.tick(transfer.Tick{PublicIP: self, Port: 4662, IsFirewalled: true})
	found := []transfer.Source{{Endpoint: netip.MustParseAddrPort("203.0.113.7:5000")}}
	if got := traces(firewalled.transfer.OnSourcesFound(found, transfer.ChannelServer, start), transfer.EventFound); len(got) != 0 {
		t.Fatalf("our public IP while firewalled: found %+v", got)
	}
}

func TestSourceAtOurInterfaceAddressOnOurPortIsUs(t *testing.T) {
	data := buildData(1000)
	h := buildHarness(t, data, transfer.Options{File: buildFile(data)})
	h.tick(transfer.Tick{Port: 4662, LocalAddrs: []netip.Addr{netip.MustParseAddr("2001:db8::5"), netip.MustParseAddr("198.51.100.5")}})
	found := []transfer.Source{
		{Endpoint: netip.MustParseAddrPort("[2001:db8::5]:4662")},
		{Endpoint: netip.MustParseAddrPort("198.51.100.5:4662")},
		{Endpoint: netip.MustParseAddrPort("198.51.100.5:4663")},
	}
	got := traces(h.transfer.OnSourcesFound(found, transfer.ChannelKad, start), transfer.EventFound)
	if len(got) != 1 || got[0].Source != "198.51.100.5:4663" {
		t.Fatalf("found %+v, want only the other client on our host", got)
	}
}

func TestSlotEndKeepsPartOfBlock(t *testing.T) {
	data := buildData(piece.BlockSize + 1000)
	h := buildHarness(t, data, transfer.Options{File: buildFile(data)})
	h.connect(1, 1, piece.Set{true})
	block := h.request(1, 1)[0]
	head := piece.Block{Begin: block.Begin, End: block.Begin + 400}
	h.run(h.transfer.OnBlockReceived(1, head, data[head.Begin:head.End], h.now))
	h.run(h.transfer.OnQueued(1, 0, h.now))

	h.connect(2, 2, piece.Set{true})
	var rest []piece.Block
	for {
		blocks := h.request(2, 3)
		if len(blocks) == 0 {
			break
		}
		rest = append(rest, blocks...)
		for _, b := range blocks {
			h.run(h.transfer.OnBlockReceived(2, b, data[b.Begin:b.End], h.now))
		}
	}
	if !slices.Contains(rest, piece.Block{Begin: head.End, End: block.End}) {
		t.Fatalf("second peer was asked for %v, want the missing tail of the cut block", rest)
	}
	if got := h.transfer.Outcome().Status; got != transfer.StatusComplete || string(h.disk) != string(data) {
		t.Fatalf("status %v, disk matches %v", got, string(h.disk) == string(data))
	}
}

// The written head of a block cut off by a slot end survives a restart, as
// aMule's .part.met gap list keeps it.
func TestResumeKeepsPartOfBlock(t *testing.T) {
	data := buildData(piece.BlockSize + 1000)
	file := buildFile(data)
	h := buildHarness(t, data, transfer.Options{File: file})
	h.connect(1, 1, piece.Set{true})
	block := h.request(1, 1)[0]
	head := piece.Block{Begin: block.Begin, End: block.Begin + 400}
	h.run(h.transfer.OnBlockReceived(1, head, data[head.Begin:head.End], h.now))

	state := h.transfer.ToState()
	if !slices.Equal(state.WrittenBlocks, []piece.Block{head}) {
		t.Fatalf("state = written %v, want the head %v", state.WrittenBlocks, head)
	}
	resumed := buildHarness(t, data, transfer.Options{File: file, State: &state})
	if got := resumed.transfer.Progress(start).Received; got != 400 {
		t.Fatalf("resumed received = %d, want 400", got)
	}
	resumed.connect(1, 1, piece.Set{true})
	if got := resumed.request(1, 3); len(got) == 0 || got[0] != (piece.Block{Begin: head.End, End: block.End}) {
		t.Fatalf("resumed transfer asked for %v, want the tail after the head first", got)
	}
}

// An OP_REASKACK that arrives after the source connected to us is late: the
// connection already tells where we stand, and the slot it gave stays.
func TestLateReaskAnswerKeepsSlot(t *testing.T) {
	data := buildData(1000)
	h := buildHarness(t, data, transfer.Options{File: buildFile(data, endpoint(1))})
	h.tick(transfer.Tick{ConnectBudget: 1})
	h.run(h.transfer.OnPeerConnected(1, transfer.Source{Endpoint: endpoint(1), UserHash: userHash(1), UDPPort: 4672, CanReaskUDP: true}, start))
	h.run(h.transfer.OnQueued(1, 42, start))
	h.run(h.transfer.OnPeerGone(1, "idle", start))
	reaskAt := start.Add(fileReaskTime - 10*time.Second)
	if got := h.tick(transfer.Tick{Now: reaskAt, ConnectBudget: 1}); countActions[transfer.ReaskUDP](got) != 1 {
		t.Fatalf("no UDP reask: %+v", got)
	}

	h.run(h.transfer.OnPeerConnected(2, transfer.Source{Endpoint: endpoint(1), UserHash: userHash(1), UDPPort: 4672, CanReaskUDP: true}, reaskAt))
	h.transfer.OnPeerParts(2, piece.Set{true})
	h.run(h.transfer.OnSlotGranted(2, reaskAt))
	h.run(h.transfer.OnReaskAnswered(netip.AddrPortFrom(endpoint(1).Addr(), 4672), client.ReaskAck{Rank: 7}, reaskAt.Add(time.Second)))
	if got := h.request(2, 1); len(got) != 1 {
		t.Fatalf("late UDP answer took the slot away: requested %v", got)
	}
}

// A source with no part we need is reasked only after twice the reask
// interval and never over UDP (aMule PartFile.cpp:1574-1580).
func TestNoNeededPartsSourceWaitsTwiceTheReask(t *testing.T) {
	data := buildData(2 * piece.PartSize)
	h := buildHarness(t, data, transfer.Options{File: buildFile(data, endpoint(1))})
	h.tick(transfer.Tick{ConnectBudget: 1})
	h.run(h.transfer.OnPeerConnected(1, transfer.Source{Endpoint: endpoint(1), UserHash: userHash(1), UDPPort: 4672, CanReaskUDP: true}, start))
	h.transfer.OnPeerParts(1, piece.Set{false, false, false})
	h.transfer.OnNoNeededParts(1)
	h.run(h.transfer.OnPeerGone(1, "idle", start.Add(40*time.Second)))

	at := func(d time.Duration) []transfer.Action {
		return h.tick(transfer.Tick{Now: start.Add(d), ConnectBudget: 1})
	}
	if got := at(fileReaskTime); len(got) != 0 {
		t.Fatalf("source with nothing we need asked at the reask interval: %+v", got)
	}
	if got := at(2*fileReaskTime - 10*time.Second); len(got) != 0 {
		t.Fatalf("source with nothing we need UDP-reasked: %+v", got)
	}
	if got := at(2 * fileReaskTime); countActions[transfer.Connect](got) != 1 {
		t.Fatalf("source with nothing we need not reasked at twice the interval: %+v", got)
	}
	h.run(h.transfer.OnPeerConnected(2, transfer.Source{Endpoint: endpoint(1), UserHash: userHash(1)}, start.Add(2*fileReaskTime)))
	h.transfer.OnPeerParts(2, piece.Set{true, false, false})
	h.run(h.transfer.OnPeerGone(2, "idle", start.Add(2*fileReaskTime)))
	if got := at(3 * fileReaskTime); countActions[transfer.Connect](got) != 1 {
		t.Fatalf("source that has parts again not reasked at the normal interval: %+v", got)
	}
}

// Near the source cap, sources with nothing we need are dropped one per
// 40 s (aMule PartFile.cpp:1559-1573).
func TestNoNeededPartsSourcesArePurgedNearTheCap(t *testing.T) {
	data := buildData(2 * piece.PartSize)
	for _, test := range []struct {
		sources  int
		wantGone int
	}{{319, 0}, {321, 2}} {
		h := buildHarness(t, data, transfer.Options{File: buildFile(data)})
		var found []transfer.Source
		for i := range test.sources {
			found = append(found, transfer.Source{Endpoint: endpoint(i + 1)})
		}
		h.transfer.OnSourcesFound(found, transfer.ChannelServer, start)
		for peer := range uint64(3) {
			h.run(h.transfer.OnPeerConnected(peer+1, transfer.Source{Endpoint: endpoint(int(peer) + 1)}, start))
			h.transfer.OnPeerParts(peer+1, piece.Set{false, false, false})
			h.transfer.OnNoNeededParts(peer + 1)
			h.run(h.transfer.OnPeerGone(peer+1, "idle", start))
		}
		for _, d := range []time.Duration{41 * time.Second, 60 * time.Second, 82 * time.Second} {
			h.tick(transfer.Tick{Now: start.Add(d)})
		}
		if got := test.sources - h.transfer.Progress(start).Peers; got != test.wantGone {
			t.Errorf("%d sources: %d dropped, want %d", test.sources, got, test.wantGone)
		}
	}
}

// A source another Transfer asks for a slot is left alone until the time the
// engine gives, then asked as usual; connecting to it for this file ends the
// hold.
func TestA4AFSourceWaits(t *testing.T) {
	data := buildData(1000)
	h := buildHarness(t, data, transfer.Options{File: buildFile(data, endpoint(1))})
	if got := h.tick(transfer.Tick{ConnectBudget: 1}); countActions[transfer.Connect](got) != 1 {
		t.Fatalf("no Connect for the link source: %+v", got)
	}
	until := start.Add(10 * time.Minute)
	h.transfer.SetA4AF(transfer.Source{Endpoint: endpoint(1), UserHash: userHash(1)}, until)

	at := func(d time.Duration) []transfer.Action {
		return h.tick(transfer.Tick{Now: start.Add(d), ConnectBudget: 1})
	}
	if got := at(10*time.Minute - time.Second); len(got) != 0 {
		t.Fatalf("source asked while another Transfer holds it: %+v", got)
	}
	got := at(10 * time.Minute)
	if countActions[transfer.Connect](got) != 1 || got[0] != (transfer.Connect{Endpoint: endpoint(1), UserHash: userHash(1)}) {
		t.Fatalf("source not asked once the hold ended, with its user hash: %+v", got)
	}

	h.transfer.SetA4AF(transfer.Source{UserHash: userHash(1)}, start.Add(time.Hour))
	h.run(h.transfer.OnPeerConnected(1, transfer.Source{Endpoint: endpoint(1), UserHash: userHash(1)}, start.Add(11*time.Minute)))
	h.transfer.OnPeerParts(1, piece.Set{true})
	h.run(h.transfer.OnPeerGone(1, "idle", start.Add(11*time.Minute)))
	if got := at(11*time.Minute + fileReaskTime); countActions[transfer.Connect](got) != 1 {
		t.Fatalf("source connected for this Transfer still held: %+v", got)
	}
}

// Offline, a source asked before waits for the network, and a failure does
// not mark it dead; a link source never asked is still dialled.
func TestOfflineSourcesWait(t *testing.T) {
	data := buildData(1000)
	h := buildHarness(t, data, transfer.Options{File: buildFile(data, endpoint(1), endpoint(2))})
	offline := func(d time.Duration) []transfer.Action {
		return h.tick(transfer.Tick{Now: start.Add(d), ConnectBudget: 2, IsOffline: true})
	}
	if got := offline(0); countActions[transfer.Connect](got) != 2 {
		t.Fatalf("link sources not dialled offline at startup: %+v", got)
	}
	h.run(h.transfer.OnConnectFailed(endpoint(1), "no route to host", start))
	h.run(h.transfer.OnPeerConnected(1, transfer.Source{Endpoint: endpoint(2), UserHash: userHash(2)}, start))
	h.run(h.transfer.OnQueued(1, 5, start))
	h.run(h.transfer.OnPeerGone(1, "idle", start))

	if got := offline(2 * time.Hour); len(got) != 0 {
		t.Fatalf("sources asked offline: %+v", got)
	}
	back := start.Add(2 * time.Hour)
	if got := h.tick(transfer.Tick{Now: back, ConnectBudget: 2}); countActions[transfer.Connect](got) != 2 {
		t.Fatalf("want both sources asked once back online, the failed one too: %+v", got)
	}
}

// A LowID peer on no server, as a firewalled Kad client names itself 1,
// cannot be called back through a server, even while we have none either.
func TestLowIDHelloWithoutServerIsNotCalledBack(t *testing.T) {
	data := buildData(1000)
	h := buildHarness(t, data, transfer.Options{File: buildFile(data)})
	h.run(h.transfer.OnPeerConnected(1, transfer.Source{Endpoint: endpoint(1), ClientID: 1, UserHash: userHash(1)}, start))
	h.transfer.OnPeerParts(1, piece.Set{true})
	h.run(h.transfer.OnPeerGone(1, "idle", start))
	if got := h.tick(transfer.Tick{Now: start.Add(fileReaskTime), ConnectBudget: 1}); len(got) != 0 {
		t.Fatalf("reask %+v", got)
	}
}

// A LowID peer whose Hello offers direct callbacks is called back over UDP
// when its reask is due, whatever server it is on; without that offer it
// needs our own server (aMule BaseClient.cpp:1718-1747).
func TestLowIDHelloTakesDirectCallback(t *testing.T) {
	for _, isDirect := range []bool{true, false} {
		data := buildData(1000)
		h := buildHarness(t, data, transfer.Options{File: buildFile(data)})
		kadPort := netip.AddrPortFrom(endpoint(1).Addr(), 4672)
		hello := transfer.Source{Endpoint: endpoint(1), ClientID: 1234, Server: endpoint(9999), UserHash: userHash(1)}
		if isDirect {
			hello.Buddy, hello.IsDirectCallback = kadPort, true
		}
		h.run(h.transfer.OnPeerConnected(1, hello, start))
		h.transfer.OnPeerParts(1, piece.Set{true})
		h.run(h.transfer.OnPeerGone(1, "idle", start))

		got := h.tick(transfer.Tick{Now: start.Add(fileReaskTime), ConnectBudget: 1, Server: endpoint(8888)})
		want := transfer.RequestKadCallback{Buddy: kadPort, IsDirect: true, UserHash: userHash(1)}
		switch {
		case isDirect && (len(got) != 1 || got[0] != want):
			t.Fatalf("reask %+v, want %+v", got, want)
		case !isDirect && len(got) != 0:
			t.Fatalf("reask through another server: %+v", got)
		}
	}
}
