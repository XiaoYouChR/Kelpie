package engine

import (
	"context"
	"encoding/binary"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/fakeserver"
	"github.com/XiaoYouChR/Kelpie/internal/server"
	"github.com/XiaoYouChR/Kelpie/internal/store"
	"github.com/XiaoYouChR/Kelpie/internal/wire"
)

// startFakeServer runs an eD2k server on its own host until the test ends.
func (w *world) startFakeServer(ip string) *fakeserver.Server {
	return w.startFakeServerWith(fakeserver.Config{Addr: netip.AddrPortFrom(netip.MustParseAddr(ip), 4661)})
}

// startFakeServerWith fills in the host, clock and name of config.
func (w *world) startFakeServerWith(config fakeserver.Config) *fakeserver.Server {
	w.t.Helper()
	config.Transport = w.network.AddHost(config.Addr.Addr())
	config.Clock = w.clock
	config.Name = "test"
	srv, err := fakeserver.Create(config)
	if err != nil {
		w.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.Run(ctx)
	}()
	w.t.Cleanup(func() {
		cancel()
		<-done
	})
	return srv
}

func (n *node) setServer(srv *fakeserver.Server) {
	path := filepath.Join(n.folder, "server.met")
	if err := os.WriteFile(path, fakeserver.BuildMet(srv), 0o644); err != nil {
		n.w.t.Fatal(err)
	}
	n.config.ServerLists = []string{path}
}

// A server that lists an obfuscation port is logged in to there, through
// the Diffie-Hellman handshake, before any plain attempt.
func TestServerLoginObfuscated(t *testing.T) {
	w := buildWorld(t)
	srv := w.startFakeServerWith(fakeserver.Config{Addr: netip.MustParseAddrPort("198.51.100.100:4661"), ObfuscationPort: 4665})
	a := w.addNode("198.51.100.1")
	log := &lockedBuffer{}
	a.config.PacketLog = log
	a.setServer(srv)
	a.start()
	w.waitFor("server login", func() bool { return a.events.lastNetwork().IsServerConnected })
	text := log.String()
	if !strings.Contains(text, "open 198.51.100.100:4665 obfuscated=true") || strings.Contains(text, "open 198.51.100.100:4661") {
		t.Fatalf("login not obfuscated:\n%s", text)
	}
	if !strings.Contains(text, "in  198.51.100.100:4661 server.IDChange") {
		t.Fatalf("no IDChange over the obfuscated connection:\n%s", text)
	}
}

// A server.met entry with only a host name is reached through a lookup.
func TestServerByHostName(t *testing.T) {
	w := buildWorld(t)
	srv := w.startFakeServer("198.51.100.100")
	w.network.SetName("server.test", srv.Addr().Addr())
	a := w.addNode("198.51.100.1")
	met := binary.LittleEndian.AppendUint32([]byte{0x0E}, 1)
	met = wire.BuildAddrPort(met, netip.AddrPortFrom(netip.IPv4Unspecified(), srv.Addr().Port()))
	met = wire.BuildTags(met, []wire.Tag{{Type: wire.TagString, ID: 0x85, String: "server.test"}})
	path := filepath.Join(a.folder, "server.met")
	if err := os.WriteFile(path, met, 0o644); err != nil {
		t.Fatal(err)
	}
	a.config.ServerLists = []string{path}
	a.start()
	w.waitFor("server login", func() bool { return a.events.lastNetwork().IsServerConnected })
}

// What the status ping taught about a server is saved and put back on the
// listed server at the next start, as aMule keeps it in its server.met.
func TestServerStatsSurviveRestart(t *testing.T) {
	w := buildWorld(t)
	srv := w.startFakeServer("198.51.100.100")
	a := w.addNode("198.51.100.1")
	a.setServer(srv)
	a.start()
	w.waitFor("server login", func() bool { return a.events.lastNetwork().IsServerConnected })
	settle := w.clock.Now().Add(10 * time.Second)
	w.waitFor("status ping", func() bool { return !w.clock.Now().Before(settle) })
	a.close()
	first, err := store.Load(a.folder)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Servers) != 1 || first.Servers[0].Endpoint != srv.Addr() || first.Servers[0].PingedAt.IsZero() || first.Servers[0].Users == 0 {
		t.Fatalf("saved servers = %+v", first.Servers)
	}
	a.start()
	a.close()
	second, err := store.Load(a.folder)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(second.Servers, first.Servers) {
		t.Fatalf("after restart %+v, want %+v", second.Servers, first.Servers)
	}
}

func TestUpdateLearnedKeepsListedNames(t *testing.T) {
	at := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	entries := []server.Entry{
		{Endpoint: netip.MustParseAddrPort("198.51.100.7:4661"), Name: "listed", Preference: server.PreferenceHigh},
		{Endpoint: netip.AddrPortFrom(netip.Addr{}, 4661), Host: "dyn.example"},
		{Endpoint: netip.MustParseAddrPort("198.51.100.8:4661")},
	}
	saved := []store.Server{
		{Endpoint: netip.MustParseAddrPort("198.51.100.7:4661"), Failures: 3, UDPFlags: 0x21, PingedAt: at},
		{Host: "dyn.example", Port: 4661, Users: 70},
		{Host: "dyn.example", Port: 4242, Users: 99},
		{Endpoint: netip.MustParseAddrPort("198.51.100.9:4661"), Users: 5},
	}
	got := updateLearned(entries, saved)
	want := []server.Entry{
		{Endpoint: netip.MustParseAddrPort("198.51.100.7:4661"), Name: "listed", Preference: server.PreferenceHigh, Failures: 3, UDPFlags: 0x21, PingedAt: at},
		{Endpoint: netip.AddrPortFrom(netip.Addr{}, 4661), Host: "dyn.example", Users: 70},
		{Endpoint: netip.MustParseAddrPort("198.51.100.8:4661")},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %+v\nwant %+v", got, want)
	}
}

// A LowID seeder reaches the downloader through a server callback; the
// server passes on the downloader's crypt options and user hash, so the
// callback connection is obfuscated.
func TestCallbackIsObfuscated(t *testing.T) {
	w := buildWorld(t)
	srv := w.startFakeServer("198.51.100.100")
	a, b := w.addNode("198.51.100.1"), w.addNode("198.51.100.2")
	a.host.SetLowID(true)
	log := &lockedBuffer{}
	a.config.PacketLog = log
	for _, n := range []*node{a, b} {
		n.setServer(srv)
		n.start()
	}
	f := buildTestFile("callback.bin", 500_000, 21)
	a.seed(1, f)
	for _, n := range []*node{a, b} {
		w.waitFor("server login", func() bool { return n.events.lastNetwork().IsServerConnected })
	}
	if a.events.lastNetwork().IsHighID || !b.events.lastNetwork().IsHighID {
		t.Fatalf("a %+v, b %+v: want a LowID, b HighID", a.events.lastNetwork(), b.events.lastNetwork())
	}
	settle := w.clock.Now().Add(10 * time.Second)
	w.waitFor("seed offered", func() bool { return !w.clock.Now().Before(settle) })
	path := b.download(2, f)
	requireEndedOK(t, w.waitEnded(b, 2))
	b.requireData(path, f.data)
	if text := log.String(); !strings.Contains(text, "open "+b.endpoint().String()+" obfuscated=true") {
		t.Fatalf("callback connection not obfuscated:\n%s", text)
	}
}

func TestHasOtherUser(t *testing.T) {
	endpoint := netip.MustParseAddrPort("198.51.100.5:4662")
	known, other := wire.Hash{1}, wire.Hash{2}
	e := &Engine{uploadEndpoints: map[uploadKey]uploadTarget{
		{known, endpoint.Addr()}: {endpoint: endpoint},
	}}
	if e.hasOtherUser(endpoint, known) {
		t.Error("the known user counts as another")
	}
	if !e.hasOtherUser(endpoint, other) {
		t.Error("a different user at a known endpoint not noticed")
	}
	if e.hasOtherUser(netip.MustParseAddrPort("198.51.100.6:4662"), other) {
		t.Error("an unknown endpoint has another user")
	}
}

// A server that takes obfuscated UDP is pinged obfuscated, and the UDP key
// its answer brings obfuscates the global source request, whose answer
// names the source.
//
// A is logged in to S1, which answers faster than S2; C shares the file on
// S2 only.
func TestGlobalSourceRequestIsObfuscated(t *testing.T) {
	w := buildWorld(t)
	s1 := w.startFakeServerWith(fakeserver.Config{Addr: netip.MustParseAddrPort("198.51.100.100:4661"), ObfuscationPort: 4665})
	s2 := w.startFakeServerWith(fakeserver.Config{Addr: netip.MustParseAddrPort("198.51.100.101:4661"), UDPKey: 0x0BADF00D, Delay: 2 * time.Second})
	a, c := w.addNode("198.51.100.1"), w.addNode("198.51.100.3")
	log := &lockedBuffer{}
	a.config.PacketLog = log
	path := filepath.Join(a.folder, "server.met")
	if err := os.WriteFile(path, fakeserver.BuildMet(s1, s2), 0o644); err != nil {
		t.Fatal(err)
	}
	a.config.ServerLists = []string{path}
	c.setServer(s2)
	a.start()
	c.start()
	f := buildTestFile("global.bin", 500_000, 15)
	c.seed(1, f)

	toS2 := "udp out 198.51.100.101:4673 obfuscated"
	w.waitFor("A's obfuscated ping answered by S2", func() bool {
		return strings.Contains(log.String(), "udp in  198.51.100.101:4673 obfuscated")
	})
	a.download(2, f)
	w.waitFor("A to find C through S2", func() bool {
		return matchTrace(a.loadTrace(), "found", c.endpoint().String())
	})
	text := log.String()
	if strings.Count(text, toS2) < 2 || strings.Contains(text, "udp out 198.51.100.101:4665") {
		t.Fatalf("UDP to S2 not obfuscated:\n%s", text)
	}
	if !a.events.lastNetwork().IsServerConnected || !strings.Contains(text, "in  198.51.100.100:4661 server.IDChange") {
		t.Fatalf("A not on S1:\n%s", text)
	}
}
