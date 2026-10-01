package gateway

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/engine"
	"github.com/XiaoYouChR/Kelpie/internal/wire"
)

const hello = `{"type":"hello","protocol":1,"dataFolder":"/data","settings":{},"rateLimits":{}}` + "\n"

var emptyHash, _ = wire.ParseHash("31D6CFE0D16AE931B73C59D7E0C089C0")

type fakeEngine struct {
	mu       sync.Mutex
	commands []engine.Command
	closes   int
	onPost   func(engine.Command)
	onClose  func()
}

func (f *fakeEngine) Post(command engine.Command) {
	f.mu.Lock()
	f.commands = append(f.commands, command)
	f.mu.Unlock()
	if f.onPost != nil {
		f.onPost(command)
	}
}

func (f *fakeEngine) Close() error {
	f.mu.Lock()
	f.closes++
	f.mu.Unlock()
	if f.onClose != nil {
		f.onClose()
	}
	return nil
}

func (f *fakeEngine) postedCommands() []engine.Command {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]engine.Command(nil), f.commands...)
}

// startFake returns a start function handing out eng, and a channel that
// receives the events it was started with.
func startFake(eng *fakeEngine) (func(engine.Config, engine.Events) (Engine, error), chan engine.Events) {
	events := make(chan engine.Events, 1)
	return func(_ engine.Config, e engine.Events) (Engine, error) {
		events <- e
		return eng, nil
	}, events
}

func parseLines(t *testing.T, text []byte) []map[string]any {
	t.Helper()
	var messages []map[string]any
	for _, line := range bytes.Split(bytes.TrimSpace(text), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var message map[string]any
		if err := json.Unmarshal(line, &message); err != nil {
			t.Fatalf("line %q: %v", line, err)
		}
		messages = append(messages, message)
	}
	return messages
}

func loadGolden(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestSessionTranscript(t *testing.T) {
	var events engine.Events
	eng := &fakeEngine{}
	eng.onPost = func(command engine.Command) {
		switch c := command.(type) {
		case engine.RunCommand:
			if c.Link == "not a link" {
				events.SendEnded(c.ID, &engine.Error{Code: engine.CodeInvalidLink, Message: "not an eD2k file link"})
				return
			}
			events.SetProgress(c.ID, engine.Progress{Hash: emptyHash, Size: 2048, Received: 1024, DownloadRate: 512, Peers: 12, ActivePeers: 3})
		case engine.StopCommand:
			events.SendEnded(c.ID, nil)
		}
	}
	var config engine.Config
	start := func(c engine.Config, e engine.Events) (Engine, error) {
		config, events = c, e
		e.SetNetwork(engine.Network{IsServerConnected: true, IsKadFirewalled: true, KadNodes: 812, IsBehindCarrierNat: true})
		return eng, nil
	}
	var out bytes.Buffer

	if err := Run(bytes.NewReader(loadGolden(t, "session.in.ndjson")), &out, "v0.1.0", start); err != nil {
		t.Fatal(err)
	}

	if got, want := parseLines(t, out.Bytes()), parseLines(t, loadGolden(t, "session.out.ndjson")); !reflect.DeepEqual(got, want) {
		t.Errorf("output\n got %v\nwant %v", got, want)
	}
	wantConfig := engine.Config{
		Version: "v0.1.0", DataFolder: "/data/kelpie", Port: 4662, EnableKad: true, EnableUPnP: true,
		ServerLists: []string{"/data/server.met"}, NodeLists: []string{"/data/nodes.dat"},
		RateLimits: engine.RateLimitsCommand{Upload: 102400},
	}
	if !reflect.DeepEqual(config, wantConfig) {
		t.Errorf("config %+v, want %+v", config, wantConfig)
	}
	wantCommands := []engine.Command{
		engine.RunCommand{ID: 1, Mode: engine.ModeDownload, Link: "ed2k://|file|empty.bin|0|31D6CFE0D16AE931B73C59D7E0C089C0|/", File: "/downloads/empty.bin"},
		engine.RunCommand{ID: 2, Mode: engine.ModeSeed, Link: "not a link", File: "/downloads/other.bin"},
		engine.RateLimitsCommand{Download: 1048576},
		engine.RemoveCommand{Hash: emptyHash},
		engine.StopCommand{ID: 1},
	}
	if got := eng.postedCommands(); !reflect.DeepEqual(got, wantCommands) {
		t.Errorf("commands %#v, want %#v", got, wantCommands)
	}
	if eng.closes != 1 {
		t.Errorf("Close called %d times, want 1", eng.closes)
	}
}

func TestFailedTranscript(t *testing.T) {
	start := func(engine.Config, engine.Events) (Engine, error) {
		return nil, errors.New("listen tcp :4662: address already in use")
	}
	var out bytes.Buffer

	if err := Run(bytes.NewReader(loadGolden(t, "failed.in.ndjson")), &out, "v0.1.0", start); err == nil {
		t.Fatal("Run returned nil after a failed start")
	}

	if got, want := parseLines(t, out.Bytes()), parseLines(t, loadGolden(t, "failed.out.ndjson")); !reflect.DeepEqual(got, want) {
		t.Errorf("output\n got %v\nwant %v", got, want)
	}
}

func TestStartFailureKeepsEngineErrorCode(t *testing.T) {
	start := func(engine.Config, engine.Events) (Engine, error) {
		return nil, &engine.Error{Code: engine.CodeFileError, Message: "data folder is read-only"}
	}
	var out bytes.Buffer

	err := Run(strings.NewReader(hello), &out, "v1", start)

	var engineErr *engine.Error
	if !errors.As(err, &engineErr) || engineErr.Code != engine.CodeFileError {
		t.Errorf("Run error %v, want FILE_ERROR", err)
	}
	want := []map[string]any{{"type": "failed", "error": map[string]any{"code": "FILE_ERROR", "message": "data folder is read-only"}}}
	if got := parseLines(t, out.Bytes()); !reflect.DeepEqual(got, want) {
		t.Errorf("output %v, want %v", got, want)
	}
}

func TestInvalidHelloFailsWithoutStarting(t *testing.T) {
	for _, first := range []string{
		`{"type":"run","run":1,"mode":"download","link":"x","file":"/f"}`,
		`{"type":"hello"`,
		`{"type":"hello","dataFolder":""}`,
		`{"type":"hello","dataFolder":"/d","rateLimits":{"download":-1}}`,
	} {
		isStarted := false
		start := func(engine.Config, engine.Events) (Engine, error) {
			isStarted = true
			return &fakeEngine{}, nil
		}
		var out bytes.Buffer

		if err := Run(strings.NewReader(first+"\n"), &out, "v1", start); err == nil {
			t.Errorf("%s: Run returned nil", first)
		}

		if isStarted {
			t.Errorf("%s: engine started", first)
		}
		got := parseLines(t, out.Bytes())
		if len(got) != 1 || got[0]["type"] != "failed" || got[0]["error"].(map[string]any)["code"] != "START_FAILED" {
			t.Errorf("%s: output %v, want one failed START_FAILED", first, got)
		}
	}
}

func TestEOFBeforeHelloReturnsError(t *testing.T) {
	var out bytes.Buffer
	start := func(engine.Config, engine.Events) (Engine, error) {
		t.Fatal("engine started")
		return nil, nil
	}

	if err := Run(strings.NewReader(""), &out, "v1", start); err == nil {
		t.Error("Run returned nil")
	}
}

func TestCommandDecoding(t *testing.T) {
	lines := []string{
		`not json`,
		`{"type":"unknown","run":1}`,
		`{"type":"run","run":0,"mode":"download","link":"x","file":"/f"}`,
		`{"type":"run","run":-1,"mode":"download","link":"x","file":"/f"}`,
		`{"type":"run","run":1.5,"mode":"download","link":"x","file":"/f"}`,
		`{"type":"run","run":3,"mode":"upload","link":"x","file":"/f"}`,
		`{"type":"run","run":3,"mode":"seed","link":"x","file":""}`,
		`{"type":"stop","run":0}`,
		`{"type":"remove","hash":"31D6"}`,
		`{"type":"remove","hash":"ZZD6CFE0D16AE931B73C59D7E0C089C0"}`,
		`{"type":"setRateLimits","download":-5,"upload":0}`,
		``,
		`{"type":"run","run":7,"mode":"seed","link":"garbage link","file":"/f","extra":true}`,
		`{"type":"stop","run":9}`,
		`{"type":"remove","hash":"31d6cfe0d16ae931b73c59d7e0c089c0"}`,
		`{"type":"setRateLimits","upload":100}`,
	}
	eng := &fakeEngine{}
	start, _ := startFake(eng)
	in := hello + strings.Join(lines, "\n") // the last line has no newline before EOF

	if err := Run(strings.NewReader(in), io.Discard, "v1", start); err != nil {
		t.Fatal(err)
	}

	want := []engine.Command{
		engine.RunCommand{ID: 7, Mode: engine.ModeSeed, Link: "garbage link", File: "/f"},
		engine.StopCommand{ID: 9},
		engine.RemoveCommand{Hash: emptyHash},
		engine.RateLimitsCommand{Upload: 100},
	}
	if got := eng.postedCommands(); !reflect.DeepEqual(got, want) {
		t.Errorf("commands %#v, want %#v", got, want)
	}
}

// gatedWriter blocks its first Write until release is closed, standing in for
// a consumer that stops reading stdout.
type gatedWriter struct {
	mu      sync.Mutex
	lines   bytes.Buffer
	writes  int
	entered chan struct{}
	release chan struct{}
}

func (w *gatedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	w.writes++
	isFirst := w.writes == 1
	w.lines.Write(p)
	w.mu.Unlock()
	if isFirst {
		close(w.entered)
		<-w.release
	}
	return len(p), nil
}

func (w *gatedWriter) text() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]byte(nil), w.lines.Bytes()...)
}

func runWithin(t *testing.T, call func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		call()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("event call blocked")
	}
}

func TestSlowConsumerCoalescesProgress(t *testing.T) {
	inReader, inWriter := io.Pipe()
	out := &gatedWriter{entered: make(chan struct{}), release: make(chan struct{})}
	eng := &fakeEngine{}
	start, eventsReady := startFake(eng)
	runErr := make(chan error, 1)
	go func() { runErr <- Run(inReader, out, "v1", start) }()
	inWriter.Write([]byte(hello))
	events := <-eventsReady

	// The ready line is the first write, so it is the one held by the gate.
	<-out.entered
	runWithin(t, func() {
		for received := int64(1); received <= 3; received++ {
			events.SetProgress(1, engine.Progress{Hash: emptyHash, Received: received})
		}
		events.SetProgress(2, engine.Progress{Hash: emptyHash, Received: 10})
		events.SetNetwork(engine.Network{KadNodes: 1})
		events.SetNetwork(engine.Network{KadNodes: 2})
		events.SendEnded(1, nil)
		events.SetProgress(1, engine.Progress{Hash: emptyHash, Received: 4})
		events.SendEnded(1, nil)
	})
	close(out.release)
	inWriter.Close()
	if err := <-runErr; err != nil {
		t.Fatal(err)
	}

	got := parseLines(t, out.text())
	want := []map[string]any{
		{"type": "ready", "version": "v1", "protocol": 1.0},
		{"type": "network", "isServerConnected": false, "isHighId": false, "isKadFirewalled": false, "kadNodes": 2.0, "isBehindCarrierNat": false},
		buildProgressMessage(1, 3),
		buildProgressMessage(2, 10),
		{"type": "ended", "run": 1.0, "error": nil},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("output\n got %v\nwant %v", got, want)
	}
}

func buildProgressMessage(run, received float64) map[string]any {
	return map[string]any{
		"type": "progress", "run": run, "hash": "31D6CFE0D16AE931B73C59D7E0C089C0", "size": 0.0,
		"received": received, "downloadRate": 0.0, "uploadRate": 0.0, "uploaded": 0.0,
		"peers": 0.0, "activePeers": 0.0,
	}
}

func TestProgressIsWrittenWithoutDelay(t *testing.T) {
	inReader, inWriter := io.Pipe()
	outReader, outWriter := io.Pipe()
	eng := &fakeEngine{}
	start, eventsReady := startFake(eng)
	runErr := make(chan error, 1)
	go func() { runErr <- Run(inReader, outWriter, "v1", start) }()
	inWriter.Write([]byte(hello))
	events := <-eventsReady
	lines := bufio.NewScanner(outReader)
	lines.Scan() // ready

	for received := float64(1); received <= 3; received++ {
		events.SetProgress(5, engine.Progress{Hash: emptyHash, Received: int64(received)})
		if !lines.Scan() {
			t.Fatal("no progress line")
		}
		if got := parseLines(t, lines.Bytes()); !reflect.DeepEqual(got[0], buildProgressMessage(5, received)) {
			t.Errorf("line %v, want received %v", got[0], received)
		}
	}
	events.SendEnded(5, nil)
	events.SetProgress(5, engine.Progress{Hash: emptyHash, Received: 99})
	lines.Scan()
	if got := parseLines(t, lines.Bytes()); got[0]["type"] != "ended" {
		t.Errorf("line %v, want ended", got[0])
	}

	inWriter.Close()
	go func() { outWriter.CloseWithError(<-runErr) }()
	for lines.Scan() {
		t.Errorf("output after ended: %s", lines.Bytes())
	}
	if err := lines.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestEOFClosesEngineThenFlushes(t *testing.T) {
	var events engine.Events
	eng := &fakeEngine{}
	eng.onClose = func() {
		events.SetProgress(4, engine.Progress{Hash: emptyHash, Received: 7})
		events.SendEnded(4, nil)
		events.SetNetwork(engine.Network{KadNodes: 9})
	}
	start := func(c engine.Config, e engine.Events) (Engine, error) {
		events = e
		return eng, nil
	}
	var out bytes.Buffer
	in := hello + `{"type":"run","run":4,"mode":"download","link":"l","file":"/f"}` + "\n"

	if err := Run(strings.NewReader(in), &out, "v1", start); err != nil {
		t.Fatal(err)
	}

	if eng.closes != 1 {
		t.Errorf("Close called %d times, want 1", eng.closes)
	}
	// Each outbox call wakes the writer, so the network line may be written
	// before, between or after the run's lines; only progress before ended
	// is promised.
	var got []map[string]any
	var network map[string]any
	for _, message := range parseLines(t, out.Bytes()) {
		if message["type"] == "network" {
			network = message
		} else {
			got = append(got, message)
		}
	}
	want := []map[string]any{
		{"type": "ready", "version": "v1", "protocol": 1.0},
		buildProgressMessage(4, 7),
		{"type": "ended", "run": 4.0, "error": nil},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("output\n got %v\nwant %v", got, want)
	}
	wantNetwork := map[string]any{"type": "network", "isServerConnected": false, "isHighId": false, "isKadFirewalled": false, "kadNodes": 9.0, "isBehindCarrierNat": false}
	if !reflect.DeepEqual(network, wantNetwork) {
		t.Errorf("network %v, want %v", network, wantNetwork)
	}
}

type brokenWriter struct{ writes int }

func (w *brokenWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.writes == 1 {
		return len(p), nil
	}
	return 0, errors.New("broken pipe")
}

func TestWriteErrorDoesNotBlockEngine(t *testing.T) {
	inReader, inWriter := io.Pipe()
	eng := &fakeEngine{}
	start, eventsReady := startFake(eng)
	runErr := make(chan error, 1)
	go func() { runErr <- Run(inReader, &brokenWriter{}, "v1", start) }()
	inWriter.Write([]byte(hello))
	events := <-eventsReady

	runWithin(t, func() {
		for id := engine.RunID(1); id <= 100; id++ {
			events.SetProgress(id, engine.Progress{})
			events.SendEnded(id, nil)
		}
	})
	inWriter.Close()

	if err := <-runErr; err == nil {
		t.Error("Run returned nil after a write error")
	}
	if eng.closes != 1 {
		t.Errorf("Close called %d times, want 1", eng.closes)
	}
}
