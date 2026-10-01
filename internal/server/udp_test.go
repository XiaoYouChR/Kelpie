package server

import (
	"math/rand/v2"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/wire"
	packet "github.com/XiaoYouChR/Kelpie/internal/wire/server"
)

const getSources2 = packet.UDPFlagGetSources | packet.UDPFlagGetSources2

func searches(out Output) []Datagram {
	var got []Datagram
	for _, d := range out.SendUDP {
		if _, ok := d.Packet.(packet.GlobGetSources2); ok {
			got = append(got, d)
		}
	}
	return got
}

func pings(out Output) []Datagram {
	var got []Datagram
	for _, d := range out.SendUDP {
		if _, ok := d.Packet.(packet.GlobServStatReq); ok {
			got = append(got, d)
		}
	}
	return got
}

func TestUDPSearchBatchingAndRotation(t *testing.T) {
	entries := []Entry{
		{Endpoint: ep("1.0.0.1:4661"), Users: 100, UDPFlags: getSources2},
		{Endpoint: ep("1.0.0.2:4661"), UDPFlags: getSources2},
		{Endpoint: ep("1.0.0.3:4661")},
		{Endpoint: ep("1.0.0.4:4661"), UDPFlags: getSources2, Failures: 1},
		{Endpoint: ep("1.0.0.5:4661"), UDPFlags: getSources2},
	}
	wanted := downloads(50)
	s, _ := loggedIn(t, entries, highID, 0, wanted)

	type sentTo struct {
		at    time.Time
		to    netip.AddrPort
		files []packet.GetSources
	}
	var log []sentTo
	now := start
	for range 3600 {
		for _, d := range searches(s.OnTick(now, wanted)) {
			log = append(log, sentTo{now, d.To, d.Packet.(packet.GlobGetSources2).Files})
		}
		now = now.Add(time.Second)
	}

	for i := 1; i < len(log); i++ {
		if gap := log[i].at.Sub(log[i-1].at); gap < udpSearchSpeed {
			t.Fatalf("UDP searches %v apart", gap)
		}
	}
	for _, l := range log {
		size := len(l.files) * bytesPerFile
		if size-bytesPerFile >= maxUDPPacketData {
			t.Fatalf("packet of %d bytes", size)
		}
	}
	// The connected server and the one without known UDP flags are not
	// asked; the one that failed over TCP is. Each series asks 35 files,
	// rotated, and a server is asked again only UDPSERVERREASKTIME later.
	var series []sentTo
	for i, l := range log {
		if i > 0 && l.to == log[i-1].to && l.at.Sub(log[i-1].at) < udpSearchTime {
			last := &series[len(series)-1]
			last.files = append(last.files, l.files...)
			continue
		}
		series = append(series, l)
	}
	var order []netip.AddrPort
	lastAsked := map[netip.AddrPort]time.Time{}
	for _, l := range series {
		order = append(order, l.to)
		if len(l.files) != maxRequestsPerServer {
			t.Fatalf("%d files asked of %v", len(l.files), l.to)
		}
		if at, ok := lastAsked[l.to]; ok && l.at.Sub(at) <= udpSearchTime {
			t.Fatalf("%v asked again %v later", l.to, l.at.Sub(at))
		}
		lastAsked[l.to] = l.at
	}
	want := []netip.AddrPort{ep("1.0.0.2:4665"), ep("1.0.0.4:4665"), ep("1.0.0.5:4665")}
	if !reflect.DeepEqual(order[:3], want) || !reflect.DeepEqual(order[3:6], want) {
		t.Fatalf("asked %v", order)
	}
	if series[0].files[0].Hash != fileHash(0) || series[1].files[0].Hash != fileHash(35) {
		t.Fatal("file list did not rotate between servers")
	}
	if len(log[0].files) != 26 || len(log[1].files) != 9 {
		t.Fatalf("first server packets = %d + %d files", len(log[0].files), len(log[1].files))
	}
}

// A server whose OP_GLOBGETSOURCES2 support is learnt from its status answer
// is asked at once, not after the servers asked before it wait out
// UDPSERVERREASKTIME.
func TestUDPSearchAsksLateServerAtOnce(t *testing.T) {
	entries := []Entry{
		{Endpoint: ep("1.0.0.1:4661")},
		{Endpoint: ep("1.0.0.2:4661"), UDPFlags: getSources2},
		{Endpoint: ep("1.0.0.3:4661")},
	}
	wanted := downloads(1)
	s, _ := loggedIn(t, entries, highID, 0, wanted)
	var asked []netip.AddrPort
	now := start
	for range 60 {
		out := s.OnTick(now, wanted)
		for _, d := range pings(out) {
			if d.To == ep("1.0.0.3:4665") {
				s.OnUDPPacket(d.To, packet.GlobServStatRes{Challenge: d.Packet.(packet.GlobServStatReq).Challenge, UDPFlags: getSources2}, now)
			}
		}
		for _, d := range searches(out) {
			asked = append(asked, d.To)
		}
		now = now.Add(time.Second)
	}
	if !reflect.DeepEqual(asked, []netip.AddrPort{ep("1.0.0.2:4665"), ep("1.0.0.3:4665")}) {
		t.Fatalf("asked %v in the first minute", asked)
	}
}

func TestUDPSearchSkipsLargeFilesWithoutSupport(t *testing.T) {
	entries := []Entry{
		{Endpoint: ep("1.0.0.1:4661")},
		{Endpoint: ep("1.0.0.2:4661"), UDPFlags: getSources2},
		{Endpoint: ep("1.0.0.3:4661"), UDPFlags: getSources2 | packet.UDPFlagLargeFiles},
	}
	wanted := []Wanted{{File: fileHash(1), Size: 100}, {File: fileHash(2), Size: 5 << 30}}
	s, _ := loggedIn(t, entries, highID, 0, wanted)
	got := map[netip.AddrPort]int{}
	for now := start; now.Before(start.Add(10 * time.Second)); now = now.Add(time.Second) {
		for _, d := range searches(s.OnTick(now, wanted)) {
			got[d.To] = len(d.Packet.(packet.GlobGetSources2).Files)
		}
	}
	if !reflect.DeepEqual(got, map[netip.AddrPort]int{ep("1.0.0.2:4665"): 1, ep("1.0.0.3:4665"): 2}) {
		t.Fatalf("files per server = %v", got)
	}
}

func TestUDPSearchNeedsServerConnection(t *testing.T) {
	entries := []Entry{{Endpoint: ep("1.0.0.1:4661")}, {Endpoint: ep("1.0.0.2:4661"), UDPFlags: getSources2}}
	s := BuildServer(config, entries)
	for now := start; now.Before(start.Add(time.Minute)); now = now.Add(time.Second) {
		if out := s.OnTick(now, downloads(3)); len(out.SendUDP) > 0 {
			t.Fatal("UDP traffic without a server connection")
		}
	}
}

func TestStatusPings(t *testing.T) {
	entries := []Entry{
		{Endpoint: ep("1.0.0.1:4661")},
		{Endpoint: ep("1.0.0.2:4661")},
		{Endpoint: ep("1.0.0.3:4661")},
	}
	wanted := downloads(1)
	s, _ := loggedIn(t, entries, highID, 0, wanted)

	var at []time.Time
	var reqs []Datagram
	now := start
	for range 60 {
		for _, d := range pings(s.OnTick(now, wanted)) {
			at, reqs = append(at, now), append(reqs, d)
		}
		now = now.Add(time.Second)
	}
	if len(reqs) != 3 {
		t.Fatalf("%d pings in a minute, want each of 3 servers once", len(reqs))
	}
	for i := 1; i < len(at); i++ {
		if at[i].Sub(at[i-1]) <= udpStatTime {
			t.Fatalf("pings %v apart", at[i].Sub(at[i-1]))
		}
	}

	// Server 2 answers and turns out to take OP_GLOBGETSOURCES2; server 3
	// stays silent.
	challenge := reqs[1].Packet.(packet.GlobServStatReq).Challenge
	if reqs[1].To != ep("1.0.0.2:4665") {
		t.Fatalf("second ping to %v", reqs[1].To)
	}
	s.OnUDPPacket(ep("1.0.0.2:4665"), packet.GlobServStatRes{Challenge: challenge + 1, UDPFlags: getSources2}, now)
	if s.servers[1].UDPFlags != 0 {
		t.Fatal("accepted a wrong challenge")
	}
	s.OnUDPPacket(ep("1.0.0.2:4665"), packet.GlobServStatRes{Challenge: challenge, Users: 42, UDPFlags: getSources2}, now)
	if l := s.servers[1]; l.Users != 42 || l.Failures != 0 || l.UDPFlags != getSources2 {
		t.Fatalf("server after answer = %+v", l.Entry)
	}
	var searched []netip.AddrPort
	for range 5 {
		for _, d := range searches(s.OnTick(now, wanted)) {
			searched = append(searched, d.To)
		}
		now = now.Add(time.Second)
	}
	if !reflect.DeepEqual(searched, []netip.AddrPort{ep("1.0.0.2:4665")}) {
		t.Fatalf("searched %v", searched)
	}

	// After UDPSERVSTATREASKTIME the silent server is dead and no longer pinged.
	s.OnUDPPacket(ep("1.0.0.1:4665"), packet.GlobServStatRes{Challenge: reqs[0].Packet.(packet.GlobServStatReq).Challenge}, now)
	now = start.Add(udpStatReaskTime + time.Minute)
	var later []netip.AddrPort
	for range 120 {
		for _, d := range pings(s.OnTick(now, wanted)) {
			later = append(later, d.To)
		}
		now = now.Add(time.Second)
	}
	if !reflect.DeepEqual(later, []netip.AddrPort{ep("1.0.0.1:4665"), ep("1.0.0.2:4665")}) {
		t.Fatalf("later pings %v", later)
	}
}

func TestGlobFoundSources(t *testing.T) {
	entries := []Entry{{Endpoint: ep("1.0.0.1:4661")}, {Endpoint: ep("1.0.0.2:4661"), UDPFlags: getSources2}}
	s, _ := loggedIn(t, entries, highID, 0, downloads(2))
	high := wire.ToClientID(netip.MustParseAddr("5.6.7.8"))
	res := packet.GlobFoundSources{Files: []packet.FoundSources{
		{Hash: fileHash(0), Sources: []packet.Source{{ClientID: high, Port: 4662}, {ClientID: 77, Port: 4662}}},
		{Hash: fileHash(9), Sources: []packet.Source{{ClientID: high, Port: 4662}}},
		{Hash: fileHash(1), Sources: []packet.Source{{ClientID: 78, Port: 4662}}},
	}}
	out := s.OnUDPPacket(ep("1.0.0.2:4665"), res, start)
	want := []Event{SourcesFound{File: fileHash(0), IsGlobal: true, Sources: []Source{
		{Endpoint: ep("5.6.7.8:4662"), ClientID: high, Server: ep("1.0.0.2:4661")},
	}}}
	if !reflect.DeepEqual(out.Events, want) {
		t.Fatalf("events = %+v", out.Events)
	}
	if out := s.OnUDPPacket(ep("9.9.9.9:4665"), res, start); len(out.Events) != 0 {
		t.Fatal("accepted sources from an unknown sender")
	}
}

// A server that takes OP_GLOBGETSOURCES but not OP_GLOBGETSOURCES2 is
// asked by hash alone, 31 files a packet and 35 a series, as aMule does.
func TestUDPSearchVersionOne(t *testing.T) {
	entries := []Entry{
		{Endpoint: ep("1.0.0.1:4661")},
		{Endpoint: ep("1.0.0.2:4661"), UDPFlags: packet.UDPFlagGetSources},
	}
	wanted := append(downloads(40), Wanted{File: fileHash(99), Size: 5 << 30})
	s, _ := loggedIn(t, entries, highID, 0, wanted)
	var counts []int
	asked := map[wire.Hash]bool{}
	for now := start; now.Before(start.Add(10 * time.Second)); now = now.Add(time.Second) {
		for _, d := range s.OnTick(now, wanted).SendUDP {
			if g, ok := d.Packet.(packet.GlobGetSources); ok && d.To == ep("1.0.0.2:4665") {
				counts = append(counts, len(g.Files))
				for _, h := range g.Files {
					asked[h] = true
				}
			}
		}
	}
	if !reflect.DeepEqual(counts, []int{maxFilesPerUDPPacket, maxRequestsPerServer - maxFilesPerUDPPacket}) {
		t.Fatalf("packets of %v files", counts)
	}
	if asked[fileHash(99)] {
		t.Fatal("asked about a large file without large-file support")
	}
}

// sentTo collects what n ticks a second apart send to the server at ip.
func sentTo(s *Server, ip string, from time.Time, n int) ([]Datagram, time.Time) {
	var got []Datagram
	now := from
	for range n {
		for _, d := range s.OnTick(now, downloads(1)).SendUDP {
			if d.To.Addr() == netip.MustParseAddr(ip) {
				got = append(got, d)
			}
		}
		now = now.Add(time.Second)
	}
	return got, now
}

// With our public IP known, a server is pinged obfuscated at its port plus
// 12; the answer, opened with the challenge, brings the server's UDP key,
// which then obfuscates source requests to its UDP obfuscation port until
// our public IP changes; then the server is pinged again 20 min after the
// last ping.
func TestObfuscatedStatusPing(t *testing.T) {
	entries := []Entry{{Endpoint: ep("1.0.0.1:4661")}, {Endpoint: ep("1.0.0.2:4661")}}
	s, _ := loggedIn(t, entries, highID, 0, downloads(1))
	s.config.Random = rand.New(rand.NewPCG(1, 2))
	s.SetPublicIP(wire.ToAddr(highID))

	sent, now := sentTo(s, "1.0.0.2", start, 10)
	if len(sent) != 1 || sent[0].To != ep("1.0.0.2:4673") || sent[0].Key != 0 {
		t.Fatalf("sent %+v, want one ping to port + 12", sent)
	}
	ping, ok := sent[0].Packet.(packet.ObfuscatedPing)
	if !ok || ping.Challenge == 0 || len(ping.Padding) >= 16 {
		t.Fatalf("ping %+v", sent[0].Packet)
	}
	if key := s.UDPKeyByAddr(ep("1.0.0.2:4673")); key != ping.Challenge {
		t.Fatalf("key for the answer %#x, want the challenge %#x", key, ping.Challenge)
	}
	flags := getSources2 | packet.UDPFlagUDPObfuscation
	s.OnUDPPacket(ep("1.0.0.2:4673"), packet.GlobServStatRes{Challenge: ping.Challenge, UDPFlags: flags, UDPObfuscationPort: 4670, UDPKey: 0xBEEF}, now)
	if l := s.servers[1]; l.UDPFlags != flags || l.Failures != 0 || l.isCryptPinging {
		t.Fatalf("server after answer %+v", l.Entry)
	}
	for _, from := range []string{"1.0.0.2:4670", "1.0.0.2:4665"} {
		if key := s.UDPKeyByAddr(ep(from)); key != 0xBEEF {
			t.Fatalf("key for %s %#x", from, key)
		}
	}

	sent, now = sentTo(s, "1.0.0.2", now, 3)
	if len(sent) != 1 || sent[0].To != ep("1.0.0.2:4670") || sent[0].Key != 0xBEEF {
		t.Fatalf("source request %+v, want it obfuscated", sent)
	}

	s.SetPublicIP(netip.MustParseAddr("9.8.7.5"))
	if key := s.UDPKeyByAddr(ep("1.0.0.2:4670")); key != 0 {
		t.Fatalf("key %#x for another public IP", key)
	}
	if sent, _ = sentTo(s, "1.0.0.2", start.Add(udpStatMinReaskTime-time.Minute), 55); len(sent) != 0 {
		t.Fatalf("sent %+v before 20 min", sent)
	}
	if sent, _ = sentTo(s, "1.0.0.2", start.Add(udpStatMinReaskTime), 15); len(sent) != 1 || sent[0].To != ep("1.0.0.2:4673") {
		t.Fatalf("sent %+v 20 min after the ping, want a new ping", sent)
	}
}

// An obfuscated ping left unanswered for 20 s is followed by a plain one,
// and only that one counts as a failure.
func TestObfuscatedPingFallsBackToPlain(t *testing.T) {
	entries := []Entry{{Endpoint: ep("1.0.0.1:4661")}, {Endpoint: ep("1.0.0.2:4661")}}
	s, _ := loggedIn(t, entries, highID, 0, downloads(1))
	s.config.Random = rand.New(rand.NewPCG(1, 2))
	s.SetPublicIP(wire.ToAddr(highID))

	sent, now := sentTo(s, "1.0.0.2", start, 60)
	if len(sent) != 2 || sent[0].To != ep("1.0.0.2:4673") || sent[1].To != ep("1.0.0.2:4665") || sent[1].Key != 0 {
		t.Fatalf("sent %+v, want an obfuscated ping, then a plain one", sent)
	}
	req, ok := sent[1].Packet.(packet.GlobServStatReq)
	if !ok || s.servers[1].Failures != 1 || s.UDPKeyByAddr(ep("1.0.0.2:4665")) != 0 {
		t.Fatalf("plain ping %+v, failures %d", sent[1].Packet, s.servers[1].Failures)
	}
	s.OnUDPPacket(ep("1.0.0.2:4665"), packet.GlobServStatRes{Challenge: req.Challenge, UDPFlags: getSources2}, now)
	if l := s.servers[1]; l.UDPFlags != getSources2 || l.Failures != 0 {
		t.Fatalf("server after answer %+v", l.Entry)
	}
}
