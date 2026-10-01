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
	"github.com/XiaoYouChR/Kelpie/internal/store"
	"github.com/XiaoYouChR/Kelpie/internal/transfer"
	"github.com/XiaoYouChR/Kelpie/internal/wire"
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
	data     []byte
	disk     []byte
	actions  []transfer.Action
	now      time.Time
}

func buildHarness(t *testing.T, data []byte, options transfer.Options) *harness {
	if options.Random == nil {
		options.Random = rand.New(rand.NewPCG(3, 4))
	}
	if options.Path == "" {
		options.Path = path
	}
	return &harness{t: t, transfer: transfer.Build(options, start), data: data, disk: make([]byte, len(data)), now: start}
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
			hasher.Write(h.disk[a.Begin:a.End])
			actions = append(actions, h.transfer.OnPartHashed(a.Part, hasher.Digest(), h.now)...)
		case transfer.HashBlocks:
			var hasher aich.Hasher
			hasher.Write(h.disk[a.Begin:a.End])
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
	h.run(h.transfer.OnPeerConnected(peer, transfer.Hello{Endpoint: endpoint(i), UserHash: userHash(i)}, h.now))
	h.transfer.OnPeerParts(peer, parts)
	h.run(h.transfer.OnSlotGranted(peer, h.now))
}

// deliver requests up to n blocks for peer and answers each with data,
// corrupted when isCorrupt is set. It reports how many blocks were sent.
func (h *harness) deliver(peer uint64, n int, isCorrupt bool) int {
	blocks := h.transfer.Request(peer, n)
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

	connects := h.tick(transfer.Tick{ConnectBudget: 10})
	if got := countActions[transfer.Connect](connects); got != 2 {
		t.Fatalf("Connect actions = %d, want 2", got)
	}
	if got := len(traces(connects, transfer.EventFound)); got != 2 {
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

	elsewhere := buildHarness(t, data, transfer.Options{File: file, State: &state, Path: "/other/file.bin"})
	if got := elsewhere.transfer.Progress(start).Received; got != 0 {
		t.Fatalf("state for another path: received = %d, want 0", got)
	}
}

func TestResumeHashesWrittenParts(t *testing.T) {
	data := buildData(piece.PartSize + 100)
	file := buildFile(data)
	var blocks []store.Block
	for i := range piece.BlockCount(file.Size, 0) {
		blocks = append(blocks, store.Block{Part: 0, Index: i})
	}
	state := store.Transfer{Size: file.Size, File: path, VerifiedParts: []bool{false, false}, WrittenBlocks: blocks, Created: start}
	h := buildHarness(t, data, transfer.Options{File: file, State: &state})
	copy(h.disk, data[:piece.PartSize])

	actions := h.tick(transfer.Tick{})
	if got := countActions[transfer.HashPart](actions); got != 1 {
		t.Fatalf("HashPart actions = %d, want 1", got)
	}
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

func TestCorruptPartBansSenderAndIsDownloadedAgain(t *testing.T) {
	data := buildData(2*piece.PartSize + 5000)
	file := buildFile(data)
	h := buildHarness(t, data, transfer.Options{File: file})
	h.connect(1, 1, piece.Set{true, false, false})
	h.connect(2, 2, piece.Set{false, true, true})

	before := len(h.actions)
	for h.deliver(1, 10, true) > 0 {
	}
	actions := h.actions[before:]
	closes := 0
	for _, action := range actions {
		if c, ok := action.(transfer.Close); ok {
			closes++
			if c.Peer != 1 {
				t.Fatalf("closed peer %d, want 1", c.Peer)
			}
		}
	}
	if closes != 1 || len(traces(actions, transfer.EventClosed)) != 1 {
		t.Fatalf("closes = %d, closed traces = %d; want 1 each", closes, len(traces(actions, transfer.EventClosed)))
	}
	if h.transfer.ToState().VerifiedParts[0] {
		t.Fatal("corrupt part verified")
	}

	reconnect := h.transfer.OnPeerConnected(3, transfer.Hello{Endpoint: endpoint(9), UserHash: userHash(1)}, h.now)
	if len(reconnect) != 1 || reconnect[0] != (transfer.Close{Peer: 3, Reason: "banned"}) {
		t.Fatalf("banned peer reconnecting: %+v", reconnect)
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
	for _, test := range []struct {
		isDiskFull bool
		want       transfer.Code
	}{{true, transfer.CodeDiskFull}, {false, transfer.CodeFileError}} {
		data := buildData(1000)
		h := buildHarness(t, data, transfer.Options{File: buildFile(data)})
		h.connect(1, 1, piece.Set{true})
		blocks := h.transfer.Request(1, 1)
		actions := h.transfer.OnBlockReceived(1, blocks[0], data, h.now)
		if countActions[transfer.Write](actions) != 1 {
			t.Fatalf("no Write for a received block: %+v", actions)
		}
		h.transfer.OnDiskFailed(test.isDiskFull, "no space left on device")
		got := h.transfer.Outcome()
		if got.Status != transfer.StatusFailed || got.Code != test.want {
			t.Fatalf("isDiskFull=%v: outcome = %+v, want %s", test.isDiskFull, got, test.want)
		}
		if h.transfer.Request(1, 1) != nil {
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
			h.run(h.transfer.OnPeerConnected(1, transfer.Hello{Endpoint: endpoint(1), UserHash: userHash(1), UDPPort: 4672, CanReaskUDP: test.canReaskUDP}, start))
			h.run(h.transfer.OnQueued(1, 42, start))
			h.run(h.transfer.OnPeerGone(1, "idle", start))

			at := func(d time.Duration) []transfer.Action {
				return h.tick(transfer.Tick{Now: start.Add(d), ConnectBudget: 1})
			}
			if got := at(fileReaskTime - 3*time.Minute); len(got) != 0 {
				t.Fatalf("actions 3 min before reask: %+v", got)
			}
			udp := at(fileReaskTime - 2*time.Minute + time.Second)
			wantUDP := 0
			if test.canReaskUDP {
				wantUDP = 1
			}
			if countActions[transfer.ReaskUDP](udp) != wantUDP || countActions[transfer.Connect](udp) != 0 {
				t.Fatalf("near reask: %+v", udp)
			}
			if test.canReaskUDP {
				h.run(h.transfer.OnReaskAnswered(netip.AddrPortFrom(endpoint(1).Addr(), 4672), 7, start.Add(fileReaskTime-2*time.Minute+2*time.Second)))
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

func TestFailedSourceBacksOff(t *testing.T) {
	data := buildData(1000)
	h := buildHarness(t, data, transfer.Options{File: buildFile(data, endpoint(1))})
	h.tick(transfer.Tick{ConnectBudget: 1})
	failed := h.transfer.OnConnectFailed(endpoint(1), "refused", start)
	if events := traces(failed, transfer.EventFailed); len(events) != 1 || events[0].Reason != "refused" {
		t.Fatalf("failed trace: %+v", failed)
	}
	if got := h.tick(transfer.Tick{Now: start.Add(44 * time.Minute), ConnectBudget: 1}); countActions[transfer.Connect](got) != 0 {
		t.Fatalf("Connect during backoff: %+v", got)
	}
	if got := h.tick(transfer.Tick{Now: start.Add(45 * time.Minute), ConnectBudget: 1}); countActions[transfer.Connect](got) != 1 {
		t.Fatalf("no Connect after backoff: %+v", got)
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
	incoming := h.transfer.OnPeerConnected(1, transfer.Hello{Endpoint: endpoint(1000)}, start)
	if len(incoming) != 1 || incoming[0] != (transfer.Close{Peer: 1, Reason: "too many sources"}) {
		t.Fatalf("incoming beyond the cap: %+v", incoming)
	}
	if got := h.tick(transfer.Tick{Server: endpoint(9999), IsKadRunning: true}); countActions[transfer.RequestSources](got) != 0 {
		t.Fatalf("source requests above the soft limit: %+v", got)
	}
}

func TestSourceRequestIntervals(t *testing.T) {
	data := buildData(1000)
	h := buildHarness(t, data, transfer.Options{File: buildFile(data)})
	server := endpoint(9999)
	channels := func(d time.Duration) map[transfer.Channel]bool {
		got := map[transfer.Channel]bool{}
		for _, action := range h.tick(transfer.Tick{Now: start.Add(d), Server: server, IsKadRunning: true}) {
			if r, ok := action.(transfer.RequestSources); ok {
				got[r.Channel] = true
			}
		}
		return got
	}
	if got := channels(0); !got[transfer.ChannelServer] || !got[transfer.ChannelGlobalServer] || !got[transfer.ChannelKad] {
		t.Fatalf("first tick requests %v", got)
	}
	if got := channels(15 * time.Minute); len(got) != 0 {
		t.Fatalf("requests at 15 min: %v", got)
	}
	if got := channels(15*time.Minute + time.Second); !got[transfer.ChannelServer] || len(got) != 1 {
		t.Fatalf("requests after SERVERREASKTIME: %v", got)
	}
	if got := channels(time.Hour); !got[transfer.ChannelKad] {
		t.Fatalf("no Kad request after KADEMLIAREASKTIME: %v", got)
	}
	if got := channels(2*time.Hour + time.Minute); got[transfer.ChannelKad] {
		t.Fatalf("second Kad search did not back off: %v", got)
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

func TestSeedMode(t *testing.T) {
	data := buildData(piece.PartSize + 100)
	file := buildFile(data)
	incomplete := buildHarness(t, data, transfer.Options{File: file, Mode: transfer.ModeSeed})
	if got := incomplete.transfer.Outcome(); got.Status != transfer.StatusFailed || got.Code != transfer.CodeFileError {
		t.Fatalf("seed of an incomplete file: %+v", got)
	}

	state := store.Transfer{Size: file.Size, File: path, PartHashes: file.PartHashes, VerifiedParts: []bool{true, true}, Uploaded: 500, Created: start}
	h := buildHarness(t, data, transfer.Options{File: file, Mode: transfer.ModeSeed, State: &state})
	if got := h.transfer.Outcome(); got.Status != transfer.StatusRunning {
		t.Fatalf("seed of a complete file: %+v", got)
	}
	if got := h.tick(transfer.Tick{ConnectBudget: 5, Server: endpoint(1)}); len(got) != 1 || countActions[transfer.Publish](got) != 1 {
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

// Sources we cannot reach must not switch off the channels that could bring
// reachable ones, nor fill the cap.
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

	channels := map[transfer.Channel]bool{}
	for _, action := range h.tick(transfer.Tick{Now: start.Add(2 * time.Hour), Server: server, IsFirewalled: true, IsKadRunning: true}) {
		if r, ok := action.(transfer.RequestSources); ok {
			channels[r.Channel] = true
		}
	}
	if !channels[transfer.ChannelServer] || !channels[transfer.ChannelGlobalServer] || !channels[transfer.ChannelKad] {
		t.Fatalf("source requests with 400 unreachable sources: %v", channels)
	}
	actions := h.transfer.OnSourcesFound([]transfer.Source{{Endpoint: endpoint(1)}}, transfer.ChannelKad, start)
	if got := len(traces(actions, transfer.EventFound)); got != 1 {
		t.Fatalf("HighID source refused at the cap of unreachable sources: %+v", actions)
	}

	other := buildHarness(t, data, transfer.Options{File: buildFile(data)})
	other.tick(transfer.Tick{Server: server})
	found = nil
	for i := range 60 {
		found = append(found, lowIDSource(i, endpoint(8888)))
	}
	other.run(other.transfer.OnSourcesFound(found, transfer.ChannelExchange, start))
	channels = map[transfer.Channel]bool{}
	for _, action := range other.tick(transfer.Tick{Now: start.Add(time.Hour), Server: server, IsKadRunning: true}) {
		if r, ok := action.(transfer.RequestSources); ok {
			channels[r.Channel] = true
		}
	}
	if !channels[transfer.ChannelGlobalServer] || !channels[transfer.ChannelKad] {
		t.Fatalf("source requests with 60 LowID sources on another server: %v", channels)
	}
}

func TestSlotAskedSourceStaysQueuedWhenClosedBeforeRank(t *testing.T) {
	data := buildData(1000)
	h := buildHarness(t, data, transfer.Options{File: buildFile(data, endpoint(1), endpoint(2))})
	h.tick(transfer.Tick{ConnectBudget: 2})
	h.run(h.transfer.OnPeerConnected(1, transfer.Hello{Endpoint: endpoint(1), UserHash: userHash(1)}, start))
	h.run(h.transfer.OnPeerConnected(2, transfer.Hello{Endpoint: endpoint(2), UserHash: userHash(2)}, start))
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
func TestEndedSlotIsReaskedAfterReaskTime(t *testing.T) {
	data := buildData(piece.PartSize + 100)
	h := buildHarness(t, data, transfer.Options{File: buildFile(data)})
	h.connect(1, 1, piece.Set{true, true})
	h.deliver(1, 1, false)
	ended := start.Add(time.Minute)
	h.run(h.transfer.OnPeerGone(1, "idle", ended))

	at := func(d time.Duration) []transfer.Action {
		return h.tick(transfer.Tick{Now: ended.Add(d), ConnectBudget: 1})
	}
	if got := at(fileReaskTime - time.Second); countActions[transfer.Connect](got) != 0 {
		t.Fatalf("Connect before the reask interval: %+v", got)
	}
	if got := at(fileReaskTime); countActions[transfer.Connect](got) != 1 {
		t.Fatalf("no Connect at the reask interval: %+v", got)
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
	block := h.transfer.Request(1, 1)[0]
	head := piece.Block{Begin: block.Begin, End: block.Begin + 400}
	h.run(h.transfer.OnBlockReceived(1, head, data[head.Begin:head.End], h.now))
	h.run(h.transfer.OnQueued(1, 0, h.now))

	h.connect(2, 2, piece.Set{true})
	var rest []piece.Block
	for {
		blocks := h.transfer.Request(2, 3)
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
