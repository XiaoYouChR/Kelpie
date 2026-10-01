package server

import (
	"fmt"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/wire"
	packet "github.com/XiaoYouChR/Kelpie/internal/wire/server"
)

var (
	start    = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	userHash = wire.Hash{1, 2, 3}
	config   = Config{UserHash: userHash, Port: 4662, Version: "v1.2.3"}
	highID   = wire.ToClientID(netip.MustParseAddr("9.8.7.6"))
)

func ep(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

// first is the server loggedIn connects to.
var first = ep("1.0.0.1:4661")

func fileHash(i int) wire.Hash {
	var h wire.Hash
	h[0], h[1] = byte(i), byte(i>>8)
	h[15] = 0xAA
	return h
}

func downloads(n int) []Wanted {
	var w []Wanted
	for i := range n {
		w = append(w, Wanted{File: fileHash(i), Size: 1 << 20, Name: fmt.Sprintf("f%d", i)})
	}
	return w
}

// loggedIn returns a server connected to the first entry with clientID.
func loggedIn(t *testing.T, entries []Entry, clientID, flags uint32, wanted []Wanted) (*Server, Output) {
	t.Helper()
	s := BuildServer(config, entries)
	out := s.OnTick(start, wanted)
	if dialed(out)[0] != entries[0].Endpoint {
		t.Fatalf("connect = %v, want %v first", dialed(out), entries[0].Endpoint)
	}
	s.OnConnected(entries[0].Endpoint, start)
	out = s.OnPacket(entries[0].Endpoint, packet.IDChange{ClientID: clientID, Flags: flags}, start)
	if !s.IsServerConnected() {
		t.Fatal("not connected after IDChange")
	}
	return s, out
}

// dialed is the servers out connects to, obfuscated or not.
func dialed(out Output) []netip.AddrPort {
	var servers []netip.AddrPort
	for _, d := range out.Connect {
		servers = append(servers, d.Server)
	}
	return servers
}

func sent[T wire.Packet](out Output) []T {
	var got []T
	for _, p := range out.Send {
		if v, ok := p.(T); ok {
			got = append(got, v)
		}
	}
	return got
}

func TestChoiceAndRotation(t *testing.T) {
	entries := []Entry{
		{Endpoint: ep("1.0.0.1:4661"), Users: 100},
		{Endpoint: ep("1.0.0.2:4661"), Users: 10, Preference: PreferenceHigh},
		{Endpoint: ep("1.0.0.3:4661"), Users: 1000, Failures: 2},
		{Endpoint: ep("1.0.0.4:4661"), Users: 5000, Preference: PreferenceLow},
		{Endpoint: ep("1.0.0.5:4661"), Users: 9000, Failures: maxFailures},
		{Endpoint: ep("1.0.0.1:4661"), Users: 99999, Preference: PreferenceHigh},
	}
	s := BuildServer(config, entries)
	now := start
	var order, pending []netip.AddrPort
	out := s.OnTick(now, nil)
	for len(dialed(out)) > 0 || len(pending) > 0 {
		order = append(order, dialed(out)...)
		pending = append(pending, dialed(out)...)
		if len(pending) > maxAttempts {
			t.Fatalf("%d attempts in flight", len(pending))
		}
		if again := s.OnTick(now, nil); len(dialed(again)) > 0 {
			t.Fatalf("tick connects %v while %v are pending", dialed(again), pending)
		}
		out = s.OnConnectFailed(pending[0], now)
		pending = pending[1:]
	}
	want := []netip.AddrPort{ep("1.0.0.2:4661"), ep("1.0.0.1:4661"), ep("1.0.0.3:4661"), ep("1.0.0.4:4661")}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("pass order = %v, want %v", order, want)
	}
	for ; now.Before(start.Add(passRetryTime)); now = now.Add(time.Second) {
		if out := s.OnTick(now, nil); len(dialed(out)) > 0 {
			t.Fatalf("retried at %v, before CS_RETRYCONNECTTIME", now.Sub(start))
		}
	}
	// Every server failed once, so the order is the same again.
	if out := s.OnTick(now.Add(time.Second), nil); !reflect.DeepEqual(dialed(out), want[:2]) {
		t.Fatalf("new pass connects %v", dialed(out))
	}
}

// TestFirstLoginWins follows aMule: two servers are tried at once, the
// first to give an id is kept and the other is closed without counting
// a failure against it.
func TestFirstLoginWins(t *testing.T) {
	a, b := ep("1.0.0.1:4661"), ep("1.0.0.2:4661")
	s := BuildServer(config, []Entry{{Endpoint: a, Users: 10}, {Endpoint: b}})
	if out := s.OnTick(start, nil); !reflect.DeepEqual(dialed(out), []netip.AddrPort{a, b}) {
		t.Fatalf("connect = %v", dialed(out))
	}
	if out := s.OnConnected(b, start); out.To != b || len(sent[packet.Login](out)) != 1 {
		t.Fatalf("login to b = %+v", out)
	}
	if out := s.OnConnected(a, start); out.To != a || len(sent[packet.Login](out)) != 1 {
		t.Fatalf("login to a = %+v", out)
	}
	out := s.OnPacket(a, packet.ServerMessage{Text: "from a"}, start)
	if !reflect.DeepEqual(out.Events, []Event{MessageReceived{Text: "from a"}}) {
		t.Fatalf("message while logging in = %+v", out.Events)
	}
	out = s.OnPacket(b, packet.IDChange{ClientID: highID}, start)
	if !reflect.DeepEqual(out.Close, []netip.AddrPort{a}) || out.To != b {
		t.Fatalf("login output = %+v", out)
	}
	if !s.IsServerConnected() || s.current.Endpoint != b {
		t.Fatal("not logged in to b")
	}
	if out := s.OnDisconnected(a, start); len(dialed(out)) > 0 || s.servers[0].Failures != 0 {
		t.Fatalf("closed loser reported: %+v failures=%d", out, s.servers[0].Failures)
	}
	if out := s.OnPacket(a, packet.IDChange{ClientID: 1234}, start); len(out.Events) > 0 || s.ClientID() != highID {
		t.Fatalf("packet from the closed loser used: %+v", out)
	}
	if out := s.OnTick(start.Add(time.Hour), nil); len(dialed(out)) > 0 || len(out.Close) > 0 {
		t.Fatalf("attempt left after login: %+v", out)
	}
}

func TestFailedAttemptCountsAgainstItsServer(t *testing.T) {
	a, b := ep("1.0.0.1:4661"), ep("1.0.0.2:4661")
	s := BuildServer(config, []Entry{{Endpoint: a, Users: 10}, {Endpoint: b}})
	s.OnTick(start, nil)
	s.OnConnected(a, start)
	if out := s.OnDisconnected(a, start); len(dialed(out)) > 0 {
		t.Fatalf("reconnected while b is pending: %v", dialed(out))
	}
	if s.servers[0].Failures != 1 || s.servers[1].Failures != 0 {
		t.Fatalf("failures = %d, %d", s.servers[0].Failures, s.servers[1].Failures)
	}
}

func TestServerIsGivenUpAfterMaxFailures(t *testing.T) {
	s := BuildServer(config, []Entry{{Endpoint: first}})
	now := start
	attempts := 0
	for range 1000 {
		if out := s.OnTick(now, nil); len(dialed(out)) > 0 {
			attempts++
			s.OnConnectFailed(first, now)
		}
		now = now.Add(5 * time.Second)
	}
	if attempts != maxFailures {
		t.Fatalf("%d attempts, want %d", attempts, maxFailures)
	}
}

func TestLoginTimesOut(t *testing.T) {
	a, b, c := ep("1.0.0.1:4661"), ep("1.0.0.2:4661"), ep("1.0.0.3:4661")
	s := BuildServer(config, []Entry{{Endpoint: a, Users: 2}, {Endpoint: b, Users: 1}, {Endpoint: c}})
	s.OnTick(start, nil)
	s.OnConnected(a, start.Add(time.Second))
	if out := s.OnTick(start.Add(connectTimeout), nil); len(out.Close) > 0 || len(dialed(out)) > 0 {
		t.Fatalf("gave up too early: %+v", out)
	}
	out := s.OnTick(start.Add(connectTimeout+time.Second), nil)
	if !reflect.DeepEqual(out.Close, []netip.AddrPort{a, b}) || !reflect.DeepEqual(dialed(out), []netip.AddrPort{c}) {
		t.Fatalf("timeout output = %+v", out)
	}
}

func TestLogin(t *testing.T) {
	s := BuildServer(config, []Entry{{Endpoint: first}})
	s.OnTick(start, nil)
	out := s.OnConnected(first, start)
	want := packet.Login{
		UserHash: userHash, Port: 4662, Name: "Kelpie", Version: 0x3C,
		Flags: packet.CapZlib | packet.CapNewTags | packet.CapUnicode | packet.CapLargeFiles |
			packet.CapSupportCrypt | packet.CapRequestCrypt,
		EmuleVersion: compatibleClient<<24 | 1<<17 | 2<<10 | 3<<7,
	}
	if len(out.Send) != 1 || !reflect.DeepEqual(out.Send[0], want) {
		t.Fatalf("login = %+v, want %+v", out.Send, want)
	}
	if s.IsServerConnected() {
		t.Fatal("connected before IDChange")
	}
}

func TestIDChangeGivesLowIDOrHighID(t *testing.T) {
	entries := []Entry{{Endpoint: ep("1.0.0.1:4661")}}
	s, out := loggedIn(t, entries, 1234, 0, nil)
	if s.IsHighID() || s.ClientID() != 1234 {
		t.Fatalf("LowID: isHighID=%v id=%d", s.IsHighID(), s.ClientID())
	}
	if !reflect.DeepEqual(out.Events, []Event{IDChanged{Server: entries[0].Endpoint, ClientID: 1234}}) {
		t.Fatalf("events = %+v", out.Events)
	}
	s, _ = loggedIn(t, entries, highID, 0, nil)
	if !s.IsHighID() {
		t.Fatal("HighID not reported")
	}
	s.OnDisconnected(first, start)
	if s.IsServerConnected() || s.IsHighID() || s.ClientID() != 0 {
		t.Fatal("still connected after disconnect")
	}
}

func TestReconnectMovesToAnotherServer(t *testing.T) {
	entries := []Entry{{Endpoint: ep("1.0.0.1:4661"), Users: 10}, {Endpoint: ep("1.0.0.2:4661")}}
	s, _ := loggedIn(t, entries, highID, 0, nil)
	if out := s.OnDisconnected(first, start.Add(time.Hour)); !reflect.DeepEqual(dialed(out), []netip.AddrPort{ep("1.0.0.2:4661")}) {
		t.Fatalf("reconnect = %v", dialed(out))
	}
}

func TestServerMessagesAndStatus(t *testing.T) {
	s, _ := loggedIn(t, []Entry{{Endpoint: ep("1.0.0.1:4661")}}, highID, 0, nil)
	out := s.OnPacket(first, packet.ServerMessage{Text: "welcome"}, start)
	if !reflect.DeepEqual(out.Events, []Event{MessageReceived{Text: "welcome"}}) {
		t.Fatalf("events = %+v", out.Events)
	}
	s.OnPacket(first, packet.ServerStatus{Users: 7, Files: 8}, start)
	s.OnPacket(first, packet.ServerIdent{Name: "renamed"}, start)
	if c := s.current; c.Users != 7 || c.Files != 8 || c.Name != "renamed" {
		t.Fatalf("entry = %+v", c.Entry)
	}
}

// TestSourceRequestPacing runs a day of one-second ticks and checks every
// OP_GETSOURCES against eMule's limits.
func TestSourceRequestPacing(t *testing.T) {
	wanted := downloads(40)
	wanted = append(wanted, Wanted{File: fileHash(99), Size: 1 << 20, IsComplete: true, IsShared: true})
	s, out := loggedIn(t, []Entry{{Endpoint: ep("1.0.0.1:4661")}}, highID, 0, wanted)

	askedAt := map[wire.Hash]time.Time{}
	var frames []time.Time
	check := func(now time.Time, out Output) {
		requests := sent[packet.GetSources](out)
		if len(requests) == 0 {
			return
		}
		if len(requests) > sourceFilesPerFrame {
			t.Fatalf("%d requests in one frame", len(requests))
		}
		if n := len(frames); n > 0 && now.Sub(frames[n-1]) < sourceFrameTime {
			t.Fatalf("frames %v apart", now.Sub(frames[n-1]))
		}
		frames = append(frames, now)
		for _, r := range requests {
			if r.Hash == fileHash(99) {
				t.Fatal("asked sources for a complete file")
			}
			if at, ok := askedAt[r.Hash]; ok && now.Sub(at) < sourceReaskTime {
				t.Fatalf("file reasked after %v", now.Sub(at))
			}
			askedAt[r.Hash] = now
		}
	}
	check(start, out)
	if len(frames) != 1 {
		t.Fatal("no source request right after login")
	}
	now := start
	for range 24 * 3600 {
		now = now.Add(time.Second)
		check(now, s.OnTick(now, wanted))
	}
	if len(askedAt) != 40 {
		t.Fatalf("%d files asked, want 40", len(askedAt))
	}
	// 15 files per 300 s means 40 files take 3 frames, so each is asked
	// every 15 minutes at best.
	if len(frames) < 24*3600/int(sourceFrameTime.Seconds())-1 {
		t.Fatalf("only %d frames in a day", len(frames))
	}
}

func TestLargeFileSourcesNeedServerSupport(t *testing.T) {
	large := []Wanted{{File: fileHash(1), Size: 5 << 30}}
	_, out := loggedIn(t, []Entry{{Endpoint: ep("1.0.0.1:4661")}}, highID, 0, large)
	if len(sent[packet.GetSources](out)) != 0 {
		t.Fatal("large file asked on a server without large file support")
	}
	_, out = loggedIn(t, []Entry{{Endpoint: ep("1.0.0.1:4661")}}, highID, packet.FlagLargeFiles, large)
	if got := sent[packet.GetSources](out); len(got) != 1 || got[0].Size != 5<<30 {
		t.Fatalf("got %+v", got)
	}
}

// OP_GETSOURCES gets plain OP_FOUNDSOURCES even after a login that
// supports obfuscation; only OP_GETSOURCES_OBFU brings the user hashes that
// obfuscated connections need.
func TestObfuscationServerGetsObfuRequest(t *testing.T) {
	wanted := downloads(1)
	_, out := loggedIn(t, []Entry{{Endpoint: ep("1.0.0.1:4661")}}, highID, packet.FlagTCPObfuscation, wanted)
	if got := sent[packet.GetSourcesObfu](out); len(got) != 1 || got[0].Hash != wanted[0].File || len(sent[packet.GetSources](out)) != 0 {
		t.Fatalf("sent %+v", out.Send)
	}
	_, out = loggedIn(t, []Entry{{Endpoint: ep("1.0.0.1:4661")}}, highID, 0, wanted)
	if len(sent[packet.GetSources](out)) != 1 || len(sent[packet.GetSourcesObfu](out)) != 0 {
		t.Fatalf("sent %+v", out.Send)
	}
}

func TestFoundSources(t *testing.T) {
	server := ep("1.0.0.1:4661")
	v6 := netip.MustParseAddr("2001:db8::1")
	found := packet.FoundSources{Hash: fileHash(0), Sources: []packet.Source{
		{ClientID: wire.ToClientID(netip.MustParseAddr("5.6.7.8")), Port: 4662},
		{ClientID: 77, Port: 4662},
		{ClientID: wire.IPv6Sentinel, Port: 4663, IPv6: v6},
		{ClientID: highID, Port: 4662},
		{ClientID: 0, Port: 4662},
	}}
	s, _ := loggedIn(t, []Entry{{Endpoint: server}}, highID, 0, downloads(1))
	out := s.OnPacket(first, found, start)
	want := SourcesFound{File: fileHash(0), Sources: []Source{
		{Endpoint: ep("5.6.7.8:4662"), ClientID: found.Sources[0].ClientID, Server: server},
		{ClientID: 77, IsLowID: true, Server: server},
		{Endpoint: netip.AddrPortFrom(v6, 4663), ClientID: wire.IPv6Sentinel, Server: server},
	}}
	if !reflect.DeepEqual(out.Events, []Event{want}) {
		t.Fatalf("events = %+v\nwant %+v", out.Events, want)
	}

	obfu := packet.FoundSourcesObfu{Hash: fileHash(0), Sources: []packet.Source{{ClientID: 77, Port: 4662, CryptOptions: 0x80, UserHash: userHash}}}
	if out := s.OnPacket(first, obfu, start); len(out.Events) != 1 || out.Events[0].(SourcesFound).Sources[0].UserHash != userHash ||
		out.Events[0].(SourcesFound).Sources[0].CanObfuscate {
		t.Fatalf("obfuscated variant: %+v", out.Events)
	}
	obfu.Sources[0].CryptOptions = 0x81
	if out := s.OnPacket(first, obfu, start); !out.Events[0].(SourcesFound).Sources[0].CanObfuscate {
		t.Fatalf("supports bit lost: %+v", out.Events)
	}
	if out := s.OnPacket(first, packet.FoundSources{Hash: fileHash(5), Sources: found.Sources}, start); len(out.Events) != 0 {
		t.Fatal("sources for a file nobody wants")
	}

	s, _ = loggedIn(t, []Entry{{Endpoint: server}}, 1234, 0, downloads(1))
	out = s.OnPacket(first, found, start)
	for _, src := range out.Events[0].(SourcesFound).Sources {
		if src.IsLowID {
			t.Fatal("LowID source kept while we are LowID")
		}
	}
}

func TestCallbacks(t *testing.T) {
	server := ep("1.0.0.1:4661")
	lowSource := Source{ClientID: 77, IsLowID: true, Server: server}
	s, _ := loggedIn(t, []Entry{{Endpoint: server}}, highID, 0, nil)

	out, ok := s.RequestCallback(lowSource, start)
	if !ok || !reflect.DeepEqual(out.Send, []wire.Packet{packet.CallbackRequest{ClientID: 77}}) {
		t.Fatalf("callback = %+v %v", out, ok)
	}
	elsewhere := lowSource
	elsewhere.Server = ep("1.0.0.2:4661")
	if _, ok := s.RequestCallback(elsewhere, start); ok {
		t.Fatal("callback through a server we are not on")
	}
	if _, ok := s.RequestCallback(Source{Endpoint: ep("5.6.7.8:4662"), ClientID: 1 << 30, Server: server}, start); ok {
		t.Fatal("callback for a HighID source")
	}

	out = s.OnPacket(first, packet.CallbackRequested{Addr: ep("5.6.7.8:4662")}, start)
	if !reflect.DeepEqual(out.ConnectPeers, []Callback{{Endpoint: ep("5.6.7.8:4662")}}) {
		t.Fatalf("connect peers = %+v", out.ConnectPeers)
	}
	user := wire.Hash{1, 2, 3}
	out = s.OnPacket(first, packet.CallbackRequested{Addr: ep("5.6.7.8:4662"), CryptOptions: 0x83, UserHash: user}, start)
	if !reflect.DeepEqual(out.ConnectPeers, []Callback{{Endpoint: ep("5.6.7.8:4662"), UserHash: user, CanObfuscate: true}}) {
		t.Fatalf("obfuscated callback = %+v", out.ConnectPeers)
	}
	out = s.OnPacket(first, packet.CallbackRequested{Addr: ep("5.6.7.8:4662"), CryptOptions: 0x80, UserHash: user}, start)
	if len(out.ConnectPeers) != 1 || out.ConnectPeers[0].CanObfuscate {
		t.Fatalf("callback without crypt support = %+v", out.ConnectPeers)
	}
	out = s.OnPacket(first, packet.CallbackRequestedIPv6{Addr: ep("[2001:db8::1]:4662")}, start)
	if len(out.ConnectPeers) != 1 {
		t.Fatalf("IPv6 callback = %v", out.ConnectPeers)
	}
	if out := s.OnPacket(first, packet.CallbackFailed{}, start); !reflect.DeepEqual(out.Events, []Event{CallbackFailed{}}) {
		t.Fatalf("events = %+v", out.Events)
	}

	low, _ := loggedIn(t, []Entry{{Endpoint: server}}, 1234, 0, nil)
	if _, ok := low.RequestCallback(lowSource, start); ok {
		t.Fatal("LowID to LowID callback")
	}
}

func TestOfferFilesMarkers(t *testing.T) {
	shared := []Wanted{
		{File: fileHash(1), Size: 100, Name: "done.iso", IsComplete: true, IsShared: true},
		{File: fileHash(2), Size: 200, Name: "part.iso", IsShared: true},
		{File: fileHash(3), Size: 300, Name: "hidden.iso"},
		{File: fileHash(4), Size: 5 << 30, Name: "large.iso", IsComplete: true, IsShared: true},
	}
	entries := []Entry{{Endpoint: ep("1.0.0.1:4661")}}
	idPort := func(o packet.OfferFiles) [][2]uint32 {
		var got [][2]uint32
		for _, f := range o.Files {
			got = append(got, [2]uint32{f.ClientID, uint32(f.Port)})
		}
		return got
	}

	_, out := loggedIn(t, entries, highID, packet.FlagCompression|packet.FlagLargeFiles, shared)
	offers := sent[packet.OfferFiles](out)
	if len(offers) != 1 || len(offers[0].Files) != 3 {
		t.Fatalf("offers = %+v", offers)
	}
	want := [][2]uint32{{packet.CompleteID, uint32(packet.CompletePort)}, {packet.IncompleteID, uint32(packet.IncompletePort)}, {packet.CompleteID, uint32(packet.CompletePort)}}
	if got := idPort(offers[0]); !reflect.DeepEqual(got, want) {
		t.Fatalf("markers = %x", got)
	}
	wantTags := []wire.Tag{
		{Type: wire.TagString, ID: packet.FileName, String: "large.iso"},
		{Type: wire.TagUint32, ID: packet.FileSize, Uint: (5 << 30) & 0xFFFFFFFF},
		{Type: wire.TagUint32, ID: packet.FileSizeHi, Uint: 1},
	}
	if !reflect.DeepEqual(offers[0].Files[2].Tags, wantTags) {
		t.Fatalf("tags = %+v", offers[0].Files[2].Tags)
	}

	_, out = loggedIn(t, entries, highID, 0, shared)
	offers = sent[packet.OfferFiles](out)
	if got := idPort(offers[0]); !reflect.DeepEqual(got, [][2]uint32{{highID, 4662}, {highID, 4662}}) {
		t.Fatalf("HighID without compression = %v", got)
	}
	_, out = loggedIn(t, entries, 1234, 0, shared)
	offers = sent[packet.OfferFiles](out)
	if got := idPort(offers[0]); !reflect.DeepEqual(got, [][2]uint32{{0, 0}, {0, 0}}) {
		t.Fatalf("LowID without compression = %v", got)
	}
}

func TestOfferFilesCadence(t *testing.T) {
	var shared []Wanted
	for i := range 450 {
		shared = append(shared, Wanted{File: fileHash(i), Size: 100, Name: "f", IsComplete: true, IsShared: true})
	}
	s, out := loggedIn(t, []Entry{{Endpoint: ep("1.0.0.1:4661")}}, highID, packet.FlagCompression, shared)
	counts := []int{len(sent[packet.OfferFiles](out)[0].Files)}
	last := start
	for now := start.Add(time.Second); now.Before(start.Add(10 * time.Minute)); now = now.Add(time.Second) {
		offers := sent[packet.OfferFiles](s.OnTick(now, shared))
		if len(offers) == 0 {
			continue
		}
		if now.Sub(last) < offerTime {
			t.Fatalf("offers %v apart", now.Sub(last))
		}
		last = now
		counts = append(counts, len(offers[0].Files))
	}
	if !reflect.DeepEqual(counts, []int{200, 200, 50}) {
		t.Fatalf("offer sizes = %v", counts)
	}

	shared[0].IsComplete = false
	now := last.Add(offerTime)
	offers := sent[packet.OfferFiles](s.OnTick(now, shared))
	if len(offers) != 1 || len(offers[0].Files) != 1 || offers[0].Files[0].ClientID != packet.IncompleteID {
		t.Fatalf("changed file not offered again: %+v", offers)
	}
}

func TestOfferFilesRespectsSoftLimit(t *testing.T) {
	var shared []Wanted
	for i := range 50 {
		shared = append(shared, Wanted{File: fileHash(i), Size: 100, IsComplete: true, IsShared: true})
	}
	_, out := loggedIn(t, []Entry{{Endpoint: ep("1.0.0.1:4661"), SoftFiles: 20}}, highID, 0, shared)
	if n := len(sent[packet.OfferFiles](out)[0].Files); n != 20 {
		t.Fatalf("offered %d files, soft limit 20", n)
	}
}

func TestKeepAlive(t *testing.T) {
	s, _ := loggedIn(t, []Entry{{Endpoint: ep("1.0.0.1:4661")}}, highID, 0, nil)
	if out := s.OnTick(start.Add(keepAliveTime-time.Second), nil); len(out.Send) != 0 {
		t.Fatalf("early keep-alive: %+v", out.Send)
	}
	out := s.OnTick(start.Add(keepAliveTime), nil)
	if !reflect.DeepEqual(out.Send, []wire.Packet{packet.OfferFiles{}}) {
		t.Fatalf("keep-alive = %+v", out.Send)
	}
	if out := s.OnTick(start.Add(keepAliveTime+time.Minute), nil); len(out.Send) != 0 {
		t.Fatal("keep-alive repeated at once")
	}
}

// TestObfuscatedPassFirst follows aMule's TryAnotherConnectionrequest: the
// first pass tries only servers that obfuscate, each on its obfuscation
// port when it has one, and a plain pass over every server follows at once.
func TestObfuscatedPassFirst(t *testing.T) {
	a, b, c := ep("1.0.0.1:4661"), ep("1.0.0.2:4661"), ep("1.0.0.3:4661")
	s := BuildServer(config, []Entry{
		{Endpoint: a, Users: 30, TCPObfuscationPort: 4665, UDPFlags: packet.UDPFlagTCPObfuscation},
		{Endpoint: b, Users: 20, UDPFlags: packet.UDPFlagUDPObfuscation},
		{Endpoint: c, Users: 10},
	})
	out := s.OnTick(start, nil)
	if want := []Dial{{Server: a, ObfuscationPort: 4665}, {Server: b}}; !reflect.DeepEqual(out.Connect, want) {
		t.Fatalf("obfuscated pass = %+v, want %+v", out.Connect, want)
	}
	if out := s.OnConnectFailed(a, start); len(out.Connect) > 0 {
		t.Fatalf("plain pass began while b is pending: %+v", out.Connect)
	}
	// a and b failed once, so c comes first.
	out = s.OnConnectFailed(b, start)
	if want := []Dial{{Server: c}, {Server: a}}; !reflect.DeepEqual(out.Connect, want) {
		t.Fatalf("plain pass = %+v, want %+v", out.Connect, want)
	}
	if out := s.OnConnectFailed(c, start); !reflect.DeepEqual(out.Connect, []Dial{{Server: b}}) {
		t.Fatalf("plain pass continues with %+v", out.Connect)
	}
	s.OnConnectFailed(a, start)
	if out := s.OnConnectFailed(b, start); len(out.Connect) > 0 {
		t.Fatalf("connected again before CS_RETRYCONNECTTIME: %+v", out.Connect)
	}
	out = s.OnTick(start.Add(passRetryTime+time.Second), nil)
	if want := []Dial{{Server: a, ObfuscationPort: 4665}, {Server: b}}; !reflect.DeepEqual(out.Connect, want) {
		t.Fatalf("next pass = %+v, want obfuscated again", out.Connect)
	}
}

// A server's OP_IDCHANGE tells its obfuscation port and flag; the next
// connection to it is obfuscated.
func TestObfuscationPortFromLogin(t *testing.T) {
	s, _ := loggedIn(t, []Entry{{Endpoint: first}}, highID, 0, nil)
	s.OnPacket(first, packet.IDChange{ClientID: highID, Flags: packet.FlagTCPObfuscation, ObfuscationPort: 4665}, start)
	s.OnDisconnected(first, start)
	out := s.OnTick(start.Add(passRetryTime+time.Second), nil)
	if want := []Dial{{Server: first, ObfuscationPort: 4665}}; !reflect.DeepEqual(out.Connect, want) {
		t.Fatalf("reconnect = %+v, want %+v", out.Connect, want)
	}
}
