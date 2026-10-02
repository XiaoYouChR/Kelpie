package engine

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/clock"
	"github.com/XiaoYouChR/Kelpie/internal/disk"
	"github.com/XiaoYouChR/Kelpie/internal/piece"
	"github.com/XiaoYouChR/Kelpie/internal/transport"
	"github.com/XiaoYouChR/Kelpie/internal/wire"
)

var start = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

const (
	step = 100 * time.Millisecond
	// stepPause is the real time each fake step leaves the goroutines, so
	// fake time does not run far ahead of real work.
	stepPause   = 2 * time.Millisecond
	waitTimeout = 90 * time.Second
	peerPort    = 4662
)

// recorder is the gateway's view of one engine.
type recorder struct {
	mu        sync.Mutex
	first     map[RunID]Progress
	progress  map[RunID]Progress
	ended     map[RunID]*Error
	endCounts map[RunID]int
	lateRuns  []RunID
	network   Network
}

func buildRecorder() *recorder {
	return &recorder{
		first:     map[RunID]Progress{},
		progress:  map[RunID]Progress{},
		ended:     map[RunID]*Error{},
		endCounts: map[RunID]int{},
	}
}

func (r *recorder) SetProgress(id RunID, p Progress) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.endCounts[id] > 0 {
		r.lateRuns = append(r.lateRuns, id)
	}
	if _, ok := r.first[id]; !ok {
		r.first[id] = p
	}
	r.progress[id] = p
}

func (r *recorder) SendEnded(id RunID, err *Error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.endCounts[id]++
	r.ended[id] = err
}

func (r *recorder) SetNetwork(n Network) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.network = n
}

func (r *recorder) progressByRun(id RunID) (Progress, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.progress[id]
	return p, ok
}

func (r *recorder) firstByRun(id RunID) Progress {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.first[id]
}

func (r *recorder) endedByRun(id RunID) (*Error, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	err, ok := r.ended[id]
	return err, ok
}

func (r *recorder) lastNetwork() Network {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.network
}

// check fails the test if a run ended twice or reported progress after
// ending.
func (r *recorder) check(t *testing.T) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, n := range r.endCounts {
		if n != 1 {
			t.Errorf("run %d ended %d times", id, n)
		}
	}
	if len(r.lateRuns) > 0 {
		t.Errorf("progress after ended for runs %v", r.lateRuns)
	}
}

// world is a fake internet with one shared fake clock.
type world struct {
	t       *testing.T
	network *transport.Network
	clock   *clock.Fake
	caps    capacities
}

func buildWorld(t *testing.T) *world {
	return &world{t: t, network: transport.BuildNetwork(), clock: clock.BuildFake(start), caps: defaultCapacities}
}

// node is one machine: its host, disk and data folder survive its engines.
type node struct {
	w      *world
	ip     netip.Addr
	host   *transport.Host
	disk   *disk.Fake
	folder string
	trace  string
	config Config
	events *recorder
	engine *Engine
}

func (w *world) addNode(ip string) *node {
	addr := netip.MustParseAddr(ip)
	folder := w.t.TempDir()
	n := &node{
		w:      w,
		ip:     addr,
		host:   w.network.AddHost(addr),
		disk:   disk.BuildFake(),
		folder: folder,
		trace:  filepath.Join(folder, "trace.ndjson"),
	}
	n.config = Config{Version: "0.1.0", DataFolder: folder, Port: peerPort, TraceFile: n.trace}
	return n
}

func (n *node) endpoint() netip.AddrPort {
	return netip.AddrPortFrom(n.ip, peerPort)
}

// start builds a new engine on the node and closes it when the test ends.
func (n *node) start() *Engine {
	t := n.w.t
	t.Helper()
	n.events = buildRecorder()
	seed := uint64(n.ip.As4()[3])
	ports := seams{Transport: n.host, Disk: n.disk, Clock: n.w.clock, Rand: rand.New(rand.NewPCG(seed, 1))}
	e, err := build(n.config, ports, n.events, n.w.caps, nil)
	if err != nil {
		t.Fatal(err)
	}
	n.engine = e
	events := n.events
	t.Cleanup(func() {
		if err := e.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
		events.check(t)
	})
	return e
}

func (n *node) close() {
	n.w.t.Helper()
	if err := n.engine.Close(); err != nil {
		n.w.t.Fatal(err)
	}
	n.events.check(n.w.t)
}

// waitFor advances the fake clock in small steps until cond holds.
func (w *world) waitFor(what string, cond func() bool) {
	w.t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for !cond() {
		if time.Now().After(deadline) {
			w.t.Fatalf("timed out waiting for %s at fake %v", what, w.clock.Now().Sub(start))
		}
		w.clock.Advance(step)
		time.Sleep(stepPause)
	}
}

func (w *world) waitEnded(n *node, id RunID) *Error {
	w.t.Helper()
	var err *Error
	w.waitFor(fmt.Sprintf("run %d to end", id), func() bool {
		var ok bool
		err, ok = n.events.endedByRun(id)
		return ok
	})
	return err
}

// testFile is a file's content and its eD2k hash.
type testFile struct {
	name string
	data []byte
	hash wire.Hash
}

func buildTestFile(name string, size int, seed uint64) testFile {
	data := make([]byte, size)
	rand.NewChaCha8([32]byte{byte(seed)}).Read(data)
	var hasher piece.FileHasher
	hasher.Write(data)
	return testFile{name: name, data: data, hash: hasher.FileHash()}
}

func (f testFile) link(sources ...netip.AddrPort) string {
	text := fmt.Sprintf("ed2k://|file|%s|%d|%s|/", f.name, len(f.data), f.hash)
	if len(sources) == 0 {
		return text
	}
	var list []string
	for _, s := range sources {
		list = append(list, s.String())
	}
	return text + "|sources," + strings.Join(list, ",") + "|/"
}

// seed starts a seed run of f on n and waits until its file is checked.
func (n *node) seed(id RunID, f testFile) {
	path := "/share/" + f.name
	n.disk.SetData(path, f.data)
	n.engine.Post(RunCommand{ID: id, Mode: ModeSeed, Link: f.link(), File: path})
	n.w.waitFor("seed to be checked", func() bool {
		p, _ := n.events.progressByRun(id)
		return p.Received == int64(len(f.data))
	})
}

func (n *node) download(id RunID, f testFile, sources ...netip.AddrPort) string {
	path := "/downloads/" + f.name
	n.engine.Post(RunCommand{ID: id, Mode: ModeDownload, Link: f.link(sources...), File: path})
	return path
}

func (n *node) requireData(path string, want []byte) {
	n.w.t.Helper()
	got, ok := n.disk.DataByPath(path)
	if !ok || string(got) != string(want) {
		n.w.t.Fatalf("%s: got %d bytes, want %d matching bytes", path, len(got), len(want))
	}
}

func requireEndedOK(t *testing.T, err *Error) {
	t.Helper()
	if err != nil {
		t.Fatalf("run ended with %v", err)
	}
}

// loadTrace reads the trace file of n.
func (n *node) loadTrace() []map[string]any {
	data, ok := n.disk.DataByPath(n.trace)
	if !ok {
		n.w.t.Fatal("no trace file")
	}
	var lines []map[string]any
	for text := range strings.Lines(string(data)) {
		var line map[string]any
		if err := json.Unmarshal([]byte(text), &line); err != nil {
			n.w.t.Fatalf("trace line %q: %v", text, err)
		}
		lines = append(lines, line)
	}
	return lines
}

func matchTrace(lines []map[string]any, event, source string) bool {
	for _, line := range lines {
		if line["event"] == event && (source == "" || line["source"] == source) {
			return true
		}
	}
	return false
}

func runTwoEngineDownload(t *testing.T, w *world, size int) {
	a, b := w.addNode("198.51.100.1"), w.addNode("198.51.100.2")
	a.start()
	b.start()
	f := buildTestFile("one.bin", size, 1)
	a.seed(1, f)
	path := b.download(7, f, a.endpoint())
	requireEndedOK(t, w.waitEnded(b, 7))
	b.requireData(path, f.data)
	if p, _ := b.events.progressByRun(7); p.Received != int64(size) {
		t.Errorf("last progress received %d, want %d", p.Received, size)
	}
	w.waitFor("seeder to count the upload", func() bool {
		p, _ := a.events.progressByRun(1)
		return p.Uploaded >= int64(size)
	})
	trace := b.loadTrace()
	for _, event := range []string{"found", "connected", "slot", "received"} {
		if !matchTrace(trace, event, a.endpoint().String()) {
			t.Errorf("trace has no %q event for the seeder", event)
		}
	}
}

func TestDownloadFromSeeder(t *testing.T) {
	w := buildWorld(t)
	runTwoEngineDownload(t, w, int(piece.PartSize)+300_000)
}

// TestChannelsOfOne runs the two-engine scenario with every channel the hub
// uses at capacity one: a send that could block the hub deadlocks here.
func TestChannelsOfOne(t *testing.T) {
	w := buildWorld(t)
	w.caps = capacities{inbox: 1, writer: 1, disk: 1, trace: 1}
	runTwoEngineDownload(t, w, 2_000_000)
}

func TestDownloadWithKadOwningUDP(t *testing.T) {
	w := buildWorld(t)
	a, b := w.addNode("198.51.100.1"), w.addNode("198.51.100.2")
	a.config.EnableKad, b.config.EnableKad = true, true
	a.start()
	b.start()
	f := buildTestFile("kad.bin", 700_000, 2)
	a.seed(1, f)
	path := b.download(2, f, a.endpoint())
	requireEndedOK(t, w.waitEnded(b, 2))
	b.requireData(path, f.data)
}

func TestTransferBusy(t *testing.T) {
	w := buildWorld(t)
	b := w.addNode("198.51.100.2")
	b.start()
	f := buildTestFile("busy.bin", 1000, 3)
	b.download(1, f)
	b.engine.Post(RunCommand{ID: 2, Mode: ModeDownload, Link: f.link(), File: "/elsewhere/busy.bin"})
	err := w.waitEnded(b, 2)
	if err == nil || err.Code != CodeTransferBusy {
		t.Fatalf("second run ended with %v, want TRANSFER_BUSY", err)
	}
	if _, ok := b.events.endedByRun(1); ok {
		t.Fatal("the first run ended")
	}
	b.engine.Post(StopCommand{ID: 1})
	requireEndedOK(t, w.waitEnded(b, 1))
}

func TestAdmissionErrors(t *testing.T) {
	w := buildWorld(t)
	b := w.addNode("198.51.100.2")
	b.start()
	f := buildTestFile("taken.bin", 1000, 4)

	b.engine.Post(RunCommand{ID: 1, Mode: ModeDownload, Link: "ed2k://|file|x|", File: "/x"})
	if err := w.waitEnded(b, 1); err == nil || err.Code != CodeInvalidLink {
		t.Fatalf("got %v, want INVALID_LINK", err)
	}

	b.disk.SetData("/downloads/taken.bin", []byte("someone else's"))
	b.download(2, f)
	if err := w.waitEnded(b, 2); err == nil || err.Code != CodeOutputExists {
		t.Fatalf("got %v, want OUTPUT_EXISTS", err)
	}

	b.disk.SetData("/downloads/taken.bin", nil)
	b.download(3, f)
	w.waitFor("placeholder takeover", func() bool {
		_, ok := b.events.progressByRun(3)
		return ok
	})
	b.engine.Post(StopCommand{ID: 3})
	requireEndedOK(t, w.waitEnded(b, 3))

	b.disk.SetData("/share/taken.bin", f.data[:500])
	b.engine.Post(RunCommand{ID: 4, Mode: ModeSeed, Link: f.link(), File: "/share/taken.bin"})
	if err := w.waitEnded(b, 4); err == nil || err.Code != CodeFileError {
		t.Fatalf("seed of a partial file: got %v, want FILE_ERROR", err)
	}

	wrong := append([]byte(nil), f.data...)
	wrong[0] ^= 1
	b.disk.SetData("/share/wrong.bin", wrong)
	b.engine.Post(RunCommand{ID: 5, Mode: ModeSeed, Link: f.link(), File: "/share/wrong.bin"})
	if err := w.waitEnded(b, 5); err == nil || err.Code != CodeFileError {
		t.Fatalf("seed of a different file: got %v, want FILE_ERROR", err)
	}
}

func TestDiskFull(t *testing.T) {
	w := buildWorld(t)
	a, b := w.addNode("198.51.100.1"), w.addNode("198.51.100.2")
	a.start()
	b.start()
	f := buildTestFile("full.bin", 600_000, 5)
	a.seed(1, f)
	b.disk.AddFault("/downloads/full.bin", disk.OpWrite, syscall.ENOSPC, 1)
	b.download(2, f, a.endpoint())
	if err := w.waitEnded(b, 2); err == nil || err.Code != CodeDiskFull {
		t.Fatalf("got %v, want DISK_FULL", err)
	}
}

func TestCompleteDownloadIsSyncedBeforeItEnds(t *testing.T) {
	w := buildWorld(t)
	a, b := w.addNode("198.51.100.1"), w.addNode("198.51.100.2")
	a.start()
	b.start()
	f := buildTestFile("sync.bin", 600_000, 8)
	a.seed(1, f)
	b.disk.AddFault("/downloads/sync.bin", disk.OpSync, syscall.EIO, 1)
	b.download(2, f, a.endpoint())
	if err := w.waitEnded(b, 2); err == nil || err.Code != CodeFileError {
		t.Fatalf("got %v, want FILE_ERROR from the failed sync", err)
	}
}

func TestSeederForgetsTheEndpointOfAGoneDownloader(t *testing.T) {
	w := buildWorld(t)
	a, b := w.addNode("198.51.100.1"), w.addNode("198.51.100.2")
	a.start()
	b.start()
	f := buildTestFile("gone.bin", 600_000, 9)
	a.seed(1, f)
	b.download(2, f, a.endpoint())
	requireEndedOK(t, w.waitEnded(b, 2))
	b.close()
	settle := w.clock.Now().Add(5 * time.Second)
	w.waitFor("seeder ticks", func() bool { return !w.clock.Now().Before(settle) })
	a.close()
	// The hub has stopped, so its map is safe to read.
	if n := len(a.engine.uploadEndpoints); n != 0 {
		t.Fatalf("seeder keeps %d upload endpoints", n)
	}
}

func TestDownloadFromTwoSeedersViaServer(t *testing.T) {
	w := buildWorld(t)
	srv := w.startFakeServer("198.51.100.100")
	a1, a2, b := w.addNode("198.51.100.1"), w.addNode("198.51.100.3"), w.addNode("198.51.100.2")
	for _, n := range []*node{a1, a2, b} {
		n.setServer(srv)
		n.start()
	}
	f := buildTestFile("two.bin", int(piece.PartSize)+500_000, 6)
	a1.seed(1, f)
	a2.seed(1, f)
	for _, n := range []*node{a1, a2, b} {
		w.waitFor("server login", func() bool { return n.events.lastNetwork().IsServerConnected })
	}
	// The server offers each seed on its next tick.
	settle := w.clock.Now().Add(10 * time.Second)
	w.waitFor("both seeds offered", func() bool { return !w.clock.Now().Before(settle) })
	path := b.download(2, f)
	requireEndedOK(t, w.waitEnded(b, 2))
	b.requireData(path, f.data)
	if n := b.events.lastNetwork(); !n.IsHighID {
		t.Errorf("network %+v, want HighID", n)
	}
	trace := b.loadTrace()
	for _, seeder := range []*node{a1, a2} {
		if !matchTrace(trace, "slot", seeder.endpoint().String()) {
			t.Errorf("no slot from %v", seeder.endpoint())
		}
	}
}

func TestCorruptSeederIsBanned(t *testing.T) {
	w := buildWorld(t)
	bad, good, b := w.addNode("198.51.100.1"), w.addNode("198.51.100.3"), w.addNode("198.51.100.2")
	bad.start()
	good.start()
	b.start()
	f := buildTestFile("corrupt.bin", 900_000, 7)
	bad.seed(1, f)
	good.seed(1, f)
	file, err := bad.disk.Open("/share/corrupt.bin", disk.Create)
	if err != nil {
		t.Fatal(err)
	}
	file.WriteAt([]byte("garbage"), 400_000)
	file.Close()

	good.host.SetUnreachable(true)
	path := b.download(2, f, bad.endpoint(), good.endpoint())
	w.waitFor("the corrupt seeder to be banned", func() bool {
		return matchTrace(b.loadTrace(), "closed", bad.endpoint().String()) && hasBan(b.loadTrace(), bad.endpoint().String())
	})
	good.host.SetUnreachable(false)
	// The good seeder failed once and is retried after DeadSourceList's 45
	// minutes; skip ahead a minute at a time.
	deadline := time.Now().Add(waitTimeout)
	for {
		if _, ok := b.events.endedByRun(2); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("download never completed from the good seeder")
		}
		w.clock.Advance(time.Minute)
		for range 20 {
			w.clock.Advance(step)
			time.Sleep(stepPause)
		}
	}
	requireEndedOK(t, w.waitEnded(b, 2))
	b.requireData(path, f.data)
	if !matchTrace(b.loadTrace(), "slot", good.endpoint().String()) {
		t.Fatal("the good seeder never gave a slot")
	}
}

func hasBan(lines []map[string]any, source string) bool {
	for _, line := range lines {
		if line["event"] == "closed" && line["source"] == source && line["reason"] == "banned" {
			return true
		}
	}
	return false
}

func TestStopAndResumeAcrossRestart(t *testing.T) {
	w := buildWorld(t)
	a, b := w.addNode("198.51.100.1"), w.addNode("198.51.100.2")
	a.start()
	b.config.DownloadLimit = 1 << 20
	b.start()
	f := buildTestFile("resume.bin", int(piece.PartSize)+400_000, 8)
	a.seed(1, f)
	path := b.download(2, f, a.endpoint())
	w.waitFor("a third of the file", func() bool {
		p, _ := b.events.progressByRun(2)
		return p.Received >= int64(len(f.data))/3
	})
	b.engine.Post(StopCommand{ID: 2})
	requireEndedOK(t, w.waitEnded(b, 2))
	stopped, _ := b.events.progressByRun(2)
	b.close()

	b.config.DownloadLimit = 0
	b.start()
	b.download(3, f, a.endpoint())
	w.waitFor("the resumed run's first progress", func() bool {
		_, ok := b.events.progressByRun(3)
		return ok
	})
	t.Logf("stopped at %d of %d bytes", stopped.Received, len(f.data))
	if first := b.events.firstByRun(3); first.Received != stopped.Received || first.Received == 0 {
		t.Fatalf("resumed at %d bytes, stopped at %d", first.Received, stopped.Received)
	}
	requireEndedOK(t, w.waitEnded(b, 3))
	b.requireData(path, f.data)
}

func TestRateLimitCapsDownload(t *testing.T) {
	const limit = 200_000
	w := buildWorld(t)
	a, b := w.addNode("198.51.100.1"), w.addNode("198.51.100.2")
	a.start()
	b.start()
	f := buildTestFile("slow.bin", 1_500_000, 9)
	a.seed(1, f)
	b.engine.Post(Settings{DownloadLimit: limit})
	began := w.clock.Now()
	b.download(2, f, a.endpoint())
	requireEndedOK(t, w.waitEnded(b, 2))
	elapsed := w.clock.Now().Sub(began).Seconds()
	t.Logf("%d bytes in %.1f fake seconds", len(f.data), elapsed)
	// The limiter may let a quarter second of rate through at once.
	if rate := float64(len(f.data)) / (elapsed + 0.25); rate > limit {
		t.Fatalf("observed %.0f B/s over %.1f s, limit %d", rate, elapsed, limit)
	}
	if elapsed > 3*float64(len(f.data))/limit {
		t.Fatalf("took %.1f s, far slower than the limit allows", elapsed)
	}
}

// goed2kLink is the Transfer saved in the goed2k fixture, for goed2kPath.
const (
	goed2kLink = "ed2k://|file|ubuntu.iso|25000000|2D2A61A79C0E0B4B4B7E6F7A4B9F1C55|/"
	goed2kPath = "/Users/alice/Downloads/ubuntu 24.04 中文.iso"
)

func (n *node) setGoed2kState() {
	n.w.t.Helper()
	fixture, err := os.ReadFile("../store/testdata/goed2k-v3.json")
	if err != nil {
		n.w.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(n.folder, "state.json"), fixture, 0o644); err != nil {
		n.w.t.Fatal(err)
	}
}

func TestGoed2kStateResumes(t *testing.T) {
	w := buildWorld(t)
	b := w.addNode("198.51.100.2")
	b.setGoed2kState()
	e := b.start()
	if got := e.self.UserHash.String(); got != "FD3887E9230E53F744E5CA8FAF1A6F31" {
		t.Fatalf("user hash %s, want the goed2k one", got)
	}
	b.disk.SetData(goed2kPath, nil)
	b.engine.Post(RunCommand{ID: 1, Mode: ModeDownload, Link: goed2kLink, File: goed2kPath})
	w.waitFor("first progress", func() bool {
		_, ok := b.events.progressByRun(1)
		return ok
	})
	if got, want := b.events.firstByRun(1).Received, piece.PartSize+4*piece.BlockSize; got != want {
		t.Fatalf("resumed at %d bytes, want %d", got, want)
	}
	b.close()
	var saved struct {
		Version    int    `json:"version"`
		UserHash   string `json:"userHash"`
		PrivateKey []byte `json:"privateKey"`
		Credits    []any  `json:"credits"`
	}
	raw, err := os.ReadFile(filepath.Join(b.folder, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &saved); err != nil {
		t.Fatal(err)
	}
	if saved.Version != 4 || saved.UserHash != "FD3887E9230E53F744E5CA8FAF1A6F31" || len(saved.PrivateKey) == 0 || len(saved.Credits) != 2 {
		t.Fatalf("saved state %+v", saved)
	}
}

// TestStateOfAnotherPathIsNotResumed: resume data belongs to the file it
// was written for; a run to another path starts over (docs/protocol.md).
func TestStateOfAnotherPathIsNotResumed(t *testing.T) {
	w := buildWorld(t)
	b := w.addNode("198.51.100.2")
	b.setGoed2kState()
	b.start()
	const path = "/Users/alice/Downloads/elsewhere.iso"
	b.disk.SetData(path, nil)
	b.engine.Post(RunCommand{ID: 1, Mode: ModeDownload, Link: goed2kLink, File: path})
	w.waitFor("first progress", func() bool {
		_, ok := b.events.progressByRun(1)
		return ok
	})
	if got := b.events.firstByRun(1).Received; got != 0 {
		t.Fatalf("started at %d bytes, want 0", got)
	}
}

func TestCloseEndsOpenRuns(t *testing.T) {
	w := buildWorld(t)
	b := w.addNode("198.51.100.2")
	b.start()
	f := buildTestFile("open.bin", 1000, 10)
	b.download(1, f)
	w.waitFor("admission", func() bool {
		_, ok := b.events.progressByRun(1)
		return ok
	})
	b.close()
	if err, ok := b.events.endedByRun(1); !ok || err != nil {
		t.Fatalf("ended %v, %v; want ended without error", ok, err)
	}
}

func TestStartFailsOnCorruptState(t *testing.T) {
	w := buildWorld(t)
	b := w.addNode("198.51.100.2")
	if err := os.WriteFile(filepath.Join(b.folder, "state.json"), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	ports := seams{Transport: b.host, Disk: b.disk, Clock: w.clock, Rand: rand.New(rand.NewPCG(1, 1))}
	_, err := build(b.config, ports, buildRecorder(), defaultCapacities, nil)
	if e, ok := err.(*Error); !ok || e.Code != CodeStartFailed {
		t.Fatalf("got %v, want START_FAILED", err)
	}
}
