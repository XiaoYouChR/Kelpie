package server

import (
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
	perServer := map[netip.AddrPort][]wire.Hash{}
	for _, l := range log {
		size := 0
		for _, f := range l.files {
			size += bytesPerFile
			perServer[l.to] = append(perServer[l.to], f.Hash)
		}
		if size-bytesPerFile >= maxUDPPacketData {
			t.Fatalf("packet of %d bytes", size)
		}
	}
	// The connected server, the one without known UDP flags and the failed
	// one are not asked; each of the others gets 35 files, rotated.
	if len(perServer) != 2 {
		t.Fatalf("asked servers %v", perServer)
	}
	first, second := perServer[ep("1.0.0.2:4665")], perServer[ep("1.0.0.5:4665")]
	if len(first) != maxRequestsPerServer || len(second) != maxRequestsPerServer {
		t.Fatalf("files per server = %d, %d", len(first), len(second))
	}
	if first[0] != fileHash(0) || second[0] != fileHash(35) {
		t.Fatal("file list did not rotate between servers")
	}
	if len(log[0].files) != 26 || len(log[1].files) != 9 {
		t.Fatalf("first server packets = %d + %d files", len(log[0].files), len(log[1].files))
	}
	if len(log) != 4 {
		t.Fatalf("%d packets in the first hour, want one round of 4", len(log))
	}

	// The next round waits UDPSERVERREASKTIME after the last one ended.
	ended := log[len(log)-1].at
	for now = start.Add(time.Hour); now.Sub(ended) <= udpSearchTime; now = now.Add(time.Second) {
		if len(searches(s.OnTick(now, wanted))) > 0 {
			t.Fatalf("new round %v after the last", now.Sub(ended))
		}
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
