package server

import (
	"fmt"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/wire"
	serverwire "github.com/XiaoYouChR/Kelpie/internal/wire/server"
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

// noIP is our public IP while unknown.
var noIP netip.Addr

// loggedIn returns a server connected to the first entry with clientID.
func loggedIn(t *testing.T, entries []Entry, clientID, flags uint32, wanted []Wanted) (*Server, kinds) {
	t.Helper()
	s := BuildServer(config, entries)
	out := byKind(s.OnTick(start, wanted, noIP))
	if dialed(out)[0] != entries[0].Endpoint {
		t.Fatalf("connect = %v, want %v first", dialed(out), entries[0].Endpoint)
	}
	s.OnConnected(entries[0].Endpoint)
	out = byKind(s.OnPacket(entries[0].Endpoint, serverwire.IDChange{ClientID: clientID, Flags: flags}, start))
	if _, id := s.Login(); id == 0 {
		t.Fatal("not connected after IDChange")
	}
	return s, out
}

// kinds is an Output grouped by action type, each group in order. To is
// where every Send goes; the test fails on sends to two servers.
type kinds struct {
	Close    []netip.AddrPort
	Dial     []Dial
	To       netip.AddrPort
	Send     []wire.Packet
	Datagram []Datagram
	Callback []Callback
	Resolve  []string
	Events   []Action
}

func byKind(out []Action) kinds {
	var k kinds
	for _, a := range out {
		switch a := a.(type) {
		case Close:
			k.Close = append(k.Close, a.Server)
		case Dial:
			k.Dial = append(k.Dial, a)
		case Send:
			if k.To.IsValid() && k.To != a.To {
				panic(fmt.Sprintf("sends to %v and %v", k.To, a.To))
			}
			k.To = a.To
			k.Send = append(k.Send, a.Packet)
		case Datagram:
			k.Datagram = append(k.Datagram, a)
		case Callback:
			k.Callback = append(k.Callback, a)
		case Resolve:
			k.Resolve = append(k.Resolve, a.Host)
		default:
			k.Events = append(k.Events, a)
		}
	}
	return k
}

// dialed is the servers out connects to, obfuscated or not.
func dialed(out kinds) []netip.AddrPort {
	var servers []netip.AddrPort
	for _, d := range out.Dial {
		servers = append(servers, d.Server)
	}
	return servers
}

func sent[T wire.Packet](out kinds) []T {
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
	out := byKind(s.OnTick(now, nil, noIP))
	for len(dialed(out)) > 0 || len(pending) > 0 {
		order = append(order, dialed(out)...)
		pending = append(pending, dialed(out)...)
		if len(pending) > maxAttempts {
			t.Fatalf("%d attempts in flight", len(pending))
		}
		if again := byKind(s.OnTick(now, nil, noIP)); len(dialed(again)) > 0 {
			t.Fatalf("tick connects %v while %v are pending", dialed(again), pending)
		}
		out = byKind(s.OnDisconnected(pending[0], now))
		pending = pending[1:]
	}
	want := []netip.AddrPort{ep("1.0.0.2:4661"), ep("1.0.0.1:4661"), ep("1.0.0.3:4661"), ep("1.0.0.4:4661")}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("pass order = %v, want %v", order, want)
	}
	for ; now.Before(start.Add(passRetryTime)); now = now.Add(time.Second) {
		if out := byKind(s.OnTick(now, nil, noIP)); len(dialed(out)) > 0 {
			t.Fatalf("retried at %v, before CS_RETRYCONNECTTIME", now.Sub(start))
		}
	}
	// Every server failed once, so the order is the same again.
	if out := byKind(s.OnTick(now.Add(time.Second), nil, noIP)); !reflect.DeepEqual(dialed(out), want[:2]) {
		t.Fatalf("new pass connects %v", dialed(out))
	}
}

// TestFirstLoginWins follows aMule: two servers are tried at once, the
// first to give an id is kept and the other is closed without counting
// a failure against it.
func TestFirstLoginWins(t *testing.T) {
	a, b := ep("1.0.0.1:4661"), ep("1.0.0.2:4661")
	s := BuildServer(config, []Entry{{Endpoint: a, Users: 10}, {Endpoint: b}})
	if out := byKind(s.OnTick(start, nil, noIP)); !reflect.DeepEqual(dialed(out), []netip.AddrPort{a, b}) {
		t.Fatalf("connect = %v", dialed(out))
	}
	if out := byKind(s.OnConnected(b)); out.To != b || len(sent[serverwire.Login](out)) != 1 {
		t.Fatalf("login to b = %+v", out)
	}
	if out := byKind(s.OnConnected(a)); out.To != a || len(sent[serverwire.Login](out)) != 1 {
		t.Fatalf("login to a = %+v", out)
	}
	out := byKind(s.OnPacket(a, serverwire.ServerMessage{Text: "from a"}, start))
	if !reflect.DeepEqual(out.Events, []Action{MessageReceived{Text: "from a"}}) {
		t.Fatalf("message while logging in = %+v", out.Events)
	}
	out = byKind(s.OnPacket(b, serverwire.IDChange{ClientID: highID}, start))
	if !reflect.DeepEqual(out.Close, []netip.AddrPort{a}) || !reflect.DeepEqual(out.Events, []Action{IDChanged{ClientID: highID}}) {
		t.Fatalf("login output = %+v", out)
	}
	if server, clientID := s.Login(); clientID == 0 || server != b {
		t.Fatal("not logged in to b")
	}
	if out := byKind(s.OnDisconnected(a, start)); len(dialed(out)) > 0 || s.servers[0].Failures != 0 {
		t.Fatalf("closed loser reported: %+v failures=%d", out, s.servers[0].Failures)
	}
	out = byKind(s.OnPacket(a, serverwire.IDChange{ClientID: 1234}, start))
	if _, id := s.Login(); len(out.Events) > 0 || id != highID {
		t.Fatalf("packet from the closed loser used: %+v", out)
	}
	if out := byKind(s.OnTick(start.Add(time.Hour), nil, noIP)); len(dialed(out)) > 0 || len(out.Close) > 0 {
		t.Fatalf("attempt left after login: %+v", out)
	}
}

func TestFailedAttemptCountsAgainstItsServer(t *testing.T) {
	a, b := ep("1.0.0.1:4661"), ep("1.0.0.2:4661")
	s := BuildServer(config, []Entry{{Endpoint: a, Users: 10}, {Endpoint: b}})
	byKind(s.OnTick(start, nil, noIP))
	byKind(s.OnConnected(a))
	if out := byKind(s.OnDisconnected(a, start)); len(dialed(out)) > 0 {
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
		if out := byKind(s.OnTick(now, nil, noIP)); len(dialed(out)) > 0 {
			attempts++
			byKind(s.OnDisconnected(first, now))
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
	byKind(s.OnTick(start, nil, noIP))
	byKind(s.OnConnected(a))
	if out := byKind(s.OnTick(start.Add(connectTimeout), nil, noIP)); len(out.Close) > 0 || len(dialed(out)) > 0 {
		t.Fatalf("gave up too early: %+v", out)
	}
	out := byKind(s.OnTick(start.Add(connectTimeout+time.Second), nil, noIP))
	if !reflect.DeepEqual(out.Close, []netip.AddrPort{a, b}) || !reflect.DeepEqual(dialed(out), []netip.AddrPort{c}) {
		t.Fatalf("timeout output = %+v", out)
	}
}

func TestLogin(t *testing.T) {
	s := BuildServer(config, []Entry{{Endpoint: first}})
	byKind(s.OnTick(start, nil, noIP))
	out := byKind(s.OnConnected(first))
	want := serverwire.Login{
		UserHash: userHash, Port: 4662, Name: "Kelpie", Version: 0x3C,
		Flags: serverwire.CapZlib | serverwire.CapNewTags | serverwire.CapUnicode | serverwire.CapLargeFiles |
			serverwire.CapSupportCrypt | serverwire.CapRequestCrypt,
		EmuleVersion: 0x4B<<24 | 1<<17 | 2<<10 | 3<<7,
	}
	if len(out.Send) != 1 || !reflect.DeepEqual(out.Send[0], want) {
		t.Fatalf("login = %+v, want %+v", out.Send, want)
	}
	if _, id := s.Login(); id != 0 {
		t.Fatal("connected before IDChange")
	}
}

func TestIDChangeGivesLowIDOrHighID(t *testing.T) {
	entries := []Entry{{Endpoint: ep("1.0.0.1:4661")}}
	s, out := loggedIn(t, entries, 1234, 0, nil)
	if server, clientID := s.Login(); clientID != 1234 || server != entries[0].Endpoint {
		t.Fatalf("LowID: id=%d server=%s", clientID, server)
	}
	if !reflect.DeepEqual(out.Events, []Action{IDChanged{ClientID: 1234}}) {
		t.Fatalf("events = %+v", out.Events)
	}
	s, _ = loggedIn(t, entries, highID, 0, nil)
	if _, id := s.Login(); id != highID {
		t.Fatal("HighID not reported")
	}
	byKind(s.OnDisconnected(first, start))
	if server, clientID := s.Login(); clientID != 0 || server.IsValid() {
		t.Fatal("still connected after disconnect")
	}
}

func TestReconnectMovesToAnotherServer(t *testing.T) {
	entries := []Entry{{Endpoint: ep("1.0.0.1:4661"), Users: 10}, {Endpoint: ep("1.0.0.2:4661")}}
	s, _ := loggedIn(t, entries, highID, 0, nil)
	if out := byKind(s.OnDisconnected(first, start.Add(time.Hour))); !reflect.DeepEqual(dialed(out), []netip.AddrPort{ep("1.0.0.2:4661")}) {
		t.Fatalf("reconnect = %v", dialed(out))
	}
}

func TestServerMessagesAndStatus(t *testing.T) {
	s, _ := loggedIn(t, []Entry{{Endpoint: ep("1.0.0.1:4661")}}, highID, 0, nil)
	out := byKind(s.OnPacket(first, serverwire.ServerMessage{Text: "welcome"}, start))
	if !reflect.DeepEqual(out.Events, []Action{MessageReceived{Text: "welcome"}}) {
		t.Fatalf("events = %+v", out.Events)
	}
	byKind(s.OnPacket(first, serverwire.ServerStatus{Users: 7, Files: 8}, start))
	if c := s.current; c.Users != 7 || c.Files != 8 {
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
	check := func(now time.Time, out kinds) {
		requests := sent[serverwire.GetSources](out)
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
		check(now, byKind(s.OnTick(now, wanted, noIP)))
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
	if len(sent[serverwire.GetSources](out)) != 0 {
		t.Fatal("large file asked on a server without large file support")
	}
	_, out = loggedIn(t, []Entry{{Endpoint: ep("1.0.0.1:4661")}}, highID, serverwire.FlagLargeFiles, large)
	if got := sent[serverwire.GetSources](out); len(got) != 1 || got[0].Size != 5<<30 {
		t.Fatalf("got %+v", got)
	}
}

func TestFileWithEnoughSourcesIsNotAsked(t *testing.T) {
	wanted := []Wanted{
		{File: fileHash(1), Size: 100, Sources: maxSourcesSoft - 1},
		{File: fileHash(2), Size: 100, Sources: maxSourcesSoft},
	}
	_, out := loggedIn(t, []Entry{{Endpoint: ep("1.0.0.1:4661")}}, highID, 0, wanted)
	if got := sent[serverwire.GetSources](out); len(got) != 1 || got[0].Hash != fileHash(1) {
		t.Fatalf("got %+v, want only the file short of sources", got)
	}
}

// OP_GETSOURCES gets plain OP_FOUNDSOURCES even after a login that
// supports obfuscation; only OP_GETSOURCES_OBFU brings the user hashes that
// obfuscated connections need.
func TestObfuscationServerGetsObfuRequest(t *testing.T) {
	wanted := downloads(1)
	_, out := loggedIn(t, []Entry{{Endpoint: ep("1.0.0.1:4661")}}, highID, serverwire.FlagTCPObfuscation, wanted)
	if got := sent[serverwire.GetSources](out); len(got) != 1 || got[0].Hash != wanted[0].File || !got[0].IsObfu {
		t.Fatalf("sent %+v", out.Send)
	}
	_, out = loggedIn(t, []Entry{{Endpoint: ep("1.0.0.1:4661")}}, highID, 0, wanted)
	if got := sent[serverwire.GetSources](out); len(got) != 1 || got[0].IsObfu {
		t.Fatalf("sent %+v", out.Send)
	}
}

func TestFoundSources(t *testing.T) {
	server := ep("1.0.0.1:4661")
	v6 := netip.MustParseAddr("2001:db8::1")
	found := serverwire.FoundSources{Hash: fileHash(0), Sources: []serverwire.Source{
		{ClientID: wire.ToClientID(netip.MustParseAddr("5.6.7.8")), Port: 4662},
		{ClientID: 77, Port: 4662},
		{ClientID: wire.IPv6Sentinel, Port: 4663, IPv6: v6},
		{ClientID: highID, Port: 4662},
		{ClientID: 0, Port: 4662},
	}}
	s, _ := loggedIn(t, []Entry{{Endpoint: server}}, highID, 0, downloads(1))
	out := byKind(s.OnPacket(first, found, start))
	want := SourcesFound{File: fileHash(0), Sources: []Source{
		{Endpoint: ep("5.6.7.8:4662"), ClientID: found.Sources[0].ClientID, Server: server},
		{ClientID: 77, IsLowID: true, Server: server},
		{Endpoint: netip.AddrPortFrom(v6, 4663), ClientID: wire.IPv6Sentinel, Server: server},
	}}
	if !reflect.DeepEqual(out.Events, []Action{want}) {
		t.Fatalf("events = %+v\nwant %+v", out.Events, want)
	}

	obfu := serverwire.FoundSources{Hash: fileHash(0), Sources: []serverwire.Source{{ClientID: 77, Port: 4662, CryptOptions: 0x80, UserHash: userHash}}, IsObfu: true}
	if out := byKind(s.OnPacket(first, obfu, start)); len(out.Events) != 1 || out.Events[0].(SourcesFound).Sources[0].UserHash != userHash ||
		out.Events[0].(SourcesFound).Sources[0].CanObfuscate {
		t.Fatalf("obfuscated variant: %+v", out.Events)
	}
	obfu.Sources[0].CryptOptions = 0x81
	if out := byKind(s.OnPacket(first, obfu, start)); !out.Events[0].(SourcesFound).Sources[0].CanObfuscate {
		t.Fatalf("supports bit lost: %+v", out.Events)
	}
	if out := byKind(s.OnPacket(first, serverwire.FoundSources{Hash: fileHash(5), Sources: found.Sources}, start)); len(out.Events) != 0 {
		t.Fatal("sources for a file nobody wants")
	}

	s, _ = loggedIn(t, []Entry{{Endpoint: server}}, 1234, 0, downloads(1))
	out = byKind(s.OnPacket(first, found, start))
	for _, src := range out.Events[0].(SourcesFound).Sources {
		if src.IsLowID {
			t.Fatal("LowID source kept while we are LowID")
		}
	}
}

func TestCallbacks(t *testing.T) {
	server := ep("1.0.0.1:4661")
	s, _ := loggedIn(t, []Entry{{Endpoint: server}}, highID, 0, nil)

	out := byKind(s.RequestCallback(77, start))
	if out.To != server || !reflect.DeepEqual(out.Send, []wire.Packet{serverwire.CallbackRequest{ClientID: 77}}) {
		t.Fatalf("callback = %+v", out)
	}

	out = byKind(s.OnPacket(first, serverwire.CallbackRequested{Addr: ep("5.6.7.8:4662")}, start))
	if !reflect.DeepEqual(out.Callback, []Callback{{Endpoint: ep("5.6.7.8:4662")}}) {
		t.Fatalf("connect peers = %+v", out.Callback)
	}
	user := wire.Hash{1, 2, 3}
	out = byKind(s.OnPacket(first, serverwire.CallbackRequested{Addr: ep("5.6.7.8:4662"), CryptOptions: 0x83, UserHash: user}, start))
	if !reflect.DeepEqual(out.Callback, []Callback{{Endpoint: ep("5.6.7.8:4662"), UserHash: user, CanObfuscate: true}}) {
		t.Fatalf("obfuscated callback = %+v", out.Callback)
	}
	out = byKind(s.OnPacket(first, serverwire.CallbackRequested{Addr: ep("5.6.7.8:4662"), CryptOptions: 0x80, UserHash: user}, start))
	if len(out.Callback) != 1 || out.Callback[0].CanObfuscate {
		t.Fatalf("callback without crypt support = %+v", out.Callback)
	}
	out = byKind(s.OnPacket(first, serverwire.CallbackRequestedIPv6{Addr: ep("[2001:db8::1]:4662")}, start))
	if len(out.Callback) != 1 {
		t.Fatalf("IPv6 callback = %v", out.Callback)
	}

	low, _ := loggedIn(t, []Entry{{Endpoint: server}}, 1234, 0, nil)
	if out := low.RequestCallback(77, start); len(out) > 0 {
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
	idPort := func(o serverwire.OfferFiles) [][2]uint32 {
		var got [][2]uint32
		for _, f := range o.Files {
			got = append(got, [2]uint32{f.ClientID, uint32(f.Port)})
		}
		return got
	}

	_, out := loggedIn(t, entries, highID, serverwire.FlagCompression|serverwire.FlagLargeFiles, shared)
	offers := sent[serverwire.OfferFiles](out)
	if len(offers) != 1 || len(offers[0].Files) != 3 {
		t.Fatalf("offers = %+v", offers)
	}
	want := [][2]uint32{{serverwire.CompleteID, uint32(serverwire.CompletePort)}, {serverwire.IncompleteID, uint32(serverwire.IncompletePort)}, {serverwire.CompleteID, uint32(serverwire.CompletePort)}}
	if got := idPort(offers[0]); !reflect.DeepEqual(got, want) {
		t.Fatalf("markers = %x", got)
	}
	wantTags := []wire.Tag{
		{Type: wire.TagString, ID: serverwire.FileName, String: "large.iso"},
		{Type: wire.TagUint32, ID: serverwire.FileSize, Uint: (5 << 30) & 0xFFFFFFFF},
		{Type: wire.TagUint32, ID: serverwire.FileSizeHi, Uint: 1},
	}
	if !reflect.DeepEqual(offers[0].Files[2].Tags, wantTags) {
		t.Fatalf("tags = %+v", offers[0].Files[2].Tags)
	}

	_, out = loggedIn(t, entries, highID, 0, shared)
	offers = sent[serverwire.OfferFiles](out)
	if got := idPort(offers[0]); !reflect.DeepEqual(got, [][2]uint32{{highID, 4662}, {highID, 4662}}) {
		t.Fatalf("HighID without compression = %v", got)
	}
	_, out = loggedIn(t, entries, 1234, 0, shared)
	offers = sent[serverwire.OfferFiles](out)
	if got := idPort(offers[0]); !reflect.DeepEqual(got, [][2]uint32{{0, 0}, {0, 0}}) {
		t.Fatalf("LowID without compression = %v", got)
	}
}

func TestOfferFilesCadence(t *testing.T) {
	var shared []Wanted
	for i := range 450 {
		shared = append(shared, Wanted{File: fileHash(i), Size: 100, Name: "f", IsComplete: true, IsShared: true})
	}
	s, out := loggedIn(t, []Entry{{Endpoint: ep("1.0.0.1:4661")}}, highID, serverwire.FlagCompression, shared)
	counts := []int{len(sent[serverwire.OfferFiles](out)[0].Files)}
	last := start
	for now := start.Add(time.Second); now.Before(start.Add(10 * time.Minute)); now = now.Add(time.Second) {
		offers := sent[serverwire.OfferFiles](byKind(s.OnTick(now, shared, noIP)))
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
	offers := sent[serverwire.OfferFiles](byKind(s.OnTick(now, shared, noIP)))
	if len(offers) != 1 || len(offers[0].Files) != 1 || offers[0].Files[0].ClientID != serverwire.IncompleteID {
		t.Fatalf("changed file not offered again: %+v", offers)
	}
}

func TestOfferFilesRespectsSoftLimit(t *testing.T) {
	var shared []Wanted
	for i := range 50 {
		shared = append(shared, Wanted{File: fileHash(i), Size: 100, IsComplete: true, IsShared: true})
	}
	_, out := loggedIn(t, []Entry{{Endpoint: ep("1.0.0.1:4661"), SoftFiles: 20}}, highID, 0, shared)
	if n := len(sent[serverwire.OfferFiles](out)[0].Files); n != 20 {
		t.Fatalf("offered %d files, soft limit 20", n)
	}
}

func TestKeepAlive(t *testing.T) {
	s, _ := loggedIn(t, []Entry{{Endpoint: ep("1.0.0.1:4661")}}, highID, 0, nil)
	if out := byKind(s.OnTick(start.Add(keepAliveTime-time.Second), nil, noIP)); len(out.Send) != 0 {
		t.Fatalf("early keep-alive: %+v", out.Send)
	}
	out := byKind(s.OnTick(start.Add(keepAliveTime), nil, noIP))
	if !reflect.DeepEqual(out.Send, []wire.Packet{serverwire.OfferFiles{}}) {
		t.Fatalf("keep-alive = %+v", out.Send)
	}
	if out := byKind(s.OnTick(start.Add(keepAliveTime+time.Minute), nil, noIP)); len(out.Send) != 0 {
		t.Fatal("keep-alive repeated at once")
	}
}

// TestObfuscatedPassFirst follows aMule's TryAnotherConnectionrequest: the
// first pass tries only servers that obfuscate, each on its obfuscation
// port when it has one, and a plain pass over every server follows at once.
func TestObfuscatedPassFirst(t *testing.T) {
	a, b, c := ep("1.0.0.1:4661"), ep("1.0.0.2:4661"), ep("1.0.0.3:4661")
	s := BuildServer(config, []Entry{
		{Endpoint: a, Users: 30, TCPObfuscationPort: 4665, UDPFlags: serverwire.UDPFlagTCPObfuscation},
		{Endpoint: b, Users: 20, UDPFlags: serverwire.UDPFlagUDPObfuscation},
		{Endpoint: c, Users: 10},
	})
	out := byKind(s.OnTick(start, nil, noIP))
	if want := []Dial{{Server: a, ObfuscationPort: 4665}, {Server: b}}; !reflect.DeepEqual(out.Dial, want) {
		t.Fatalf("obfuscated pass = %+v, want %+v", out.Dial, want)
	}
	if out := byKind(s.OnDisconnected(a, start)); len(out.Dial) > 0 {
		t.Fatalf("plain pass began while b is pending: %+v", out.Dial)
	}
	// a and b failed once, so c comes first.
	out = byKind(s.OnDisconnected(b, start))
	if want := []Dial{{Server: c}, {Server: a}}; !reflect.DeepEqual(out.Dial, want) {
		t.Fatalf("plain pass = %+v, want %+v", out.Dial, want)
	}
	if out := byKind(s.OnDisconnected(c, start)); !reflect.DeepEqual(out.Dial, []Dial{{Server: b}}) {
		t.Fatalf("plain pass continues with %+v", out.Dial)
	}
	byKind(s.OnDisconnected(a, start))
	if out := byKind(s.OnDisconnected(b, start)); len(out.Dial) > 0 {
		t.Fatalf("connected again before CS_RETRYCONNECTTIME: %+v", out.Dial)
	}
	out = byKind(s.OnTick(start.Add(passRetryTime+time.Second), nil, noIP))
	if want := []Dial{{Server: a, ObfuscationPort: 4665}, {Server: b}}; !reflect.DeepEqual(out.Dial, want) {
		t.Fatalf("next pass = %+v, want obfuscated again", out.Dial)
	}
}

// An obfuscated attempt that times out is closed before the plain pass
// dials the same server again, in the same tick.
func TestTimedOutAttemptClosesBeforeRedial(t *testing.T) {
	a := Entry{Endpoint: first, TCPObfuscationPort: 4665, UDPFlags: serverwire.UDPFlagTCPObfuscation}
	s := BuildServer(config, []Entry{a})
	byKind(s.OnTick(start, nil, noIP))
	out := s.OnTick(start.Add(connectTimeout+time.Second), nil, noIP)
	if want := []Action{Close{first}, Dial{Server: first}}; !reflect.DeepEqual(out, want) {
		t.Fatalf("timeout = %+v, want %+v", out, want)
	}
}

// A server's OP_IDCHANGE tells its obfuscation port and flag; the next
// connection to it is obfuscated.
func TestObfuscationPortFromLogin(t *testing.T) {
	s, _ := loggedIn(t, []Entry{{Endpoint: first}}, highID, 0, nil)
	byKind(s.OnPacket(first, serverwire.IDChange{ClientID: highID, Flags: serverwire.FlagTCPObfuscation, ObfuscationPort: 4665}, start))
	byKind(s.OnDisconnected(first, start))
	out := byKind(s.OnTick(start.Add(passRetryTime+time.Second), nil, noIP))
	if want := []Dial{{Server: first, ObfuscationPort: 4665}}; !reflect.DeepEqual(out.Dial, want) {
		t.Fatalf("reconnect = %+v, want %+v", out.Dial, want)
	}
}

// A server listed by host name is looked up first, connected once it has
// an address, and looked up again every DNS_SOLVE_TIME while not in use.
func TestHostNameServer(t *testing.T) {
	dyn := Entry{Endpoint: netip.AddrPortFrom(netip.Addr{}, 4661), Host: "dyn.example"}
	s := BuildServer(config, []Entry{dyn, dyn})
	out := byKind(s.OnTick(start, nil, noIP))
	if !reflect.DeepEqual(out.Resolve, []string{"dyn.example"}) || len(out.Dial) > 0 {
		t.Fatalf("first tick = %+v", out)
	}
	if out := byKind(s.OnTick(start.Add(time.Second), nil, noIP)); len(out.Resolve) > 0 {
		t.Fatalf("looked up again while waiting: %v", out.Resolve)
	}
	resolved := ep("1.0.0.9:4661")
	out = byKind(s.OnResolved("dyn.example", resolved.Addr(), start))
	if !reflect.DeepEqual(dialed(out), []netip.AddrPort{resolved}) {
		t.Fatalf("connect after lookup = %+v", out.Dial)
	}
	byKind(s.OnConnected(resolved))
	byKind(s.OnPacket(resolved, serverwire.IDChange{ClientID: highID}, start))
	later := start.Add(dnsSolveTime + time.Minute)
	if out := byKind(s.OnTick(later, nil, noIP)); len(out.Resolve) > 0 {
		t.Fatalf("looked up the connected server: %v", out.Resolve)
	}
	byKind(s.OnDisconnected(resolved, later))
	if out := byKind(s.OnTick(later, nil, noIP)); !reflect.DeepEqual(out.Resolve, []string{"dyn.example"}) {
		t.Fatalf("no new lookup once free: %+v", out)
	}
	byKind(s.OnResolved("dyn.example", netip.Addr{}, later))
	if s.servers[0].Endpoint != resolved {
		t.Fatalf("failed lookup dropped the address: %v", s.servers[0].Endpoint)
	}
	later = later.Add(dnsSolveTime + time.Minute)
	if out := byKind(s.OnTick(later, nil, noIP)); len(out.Dial) > 0 {
		t.Fatalf("connected while looking up: %+v", out.Dial)
	}
	out = byKind(s.OnResolved("dyn.example", netip.MustParseAddr("1.0.0.10"), later))
	if !reflect.DeepEqual(dialed(out), []netip.AddrPort{ep("1.0.0.10:4661")}) {
		t.Fatalf("connect after new address = %+v", out.Dial)
	}
}
