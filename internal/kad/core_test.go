package kad

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"testing"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/obfuscation"
	"github.com/XiaoYouChR/Kelpie/internal/wire"
	kadwire "github.com/XiaoYouChR/Kelpie/internal/wire/kad"
)

var (
	selfID   = mustHash("23A8CEFF57A7A32D562D649ED7893796")
	userHash = mustHash("31D6CFE0D16AE931B73C59D7E0C089C0")
	fileHash = mustHash("C3D1E0F5A1B2C3D4E5F60718293A4B5C")
)

// harness drives one core with a fake clock and scripted peers. Peers in
// answering reply to routing queries and hellos the way a live node would.
type harness struct {
	t         *testing.T
	c         *core
	now       time.Time
	answering map[netip.AddrPort]Node
	sent      []datagram
	found     []SourcesFound
	requests  []Request
}

func buildHarness(t *testing.T) *harness {
	c := buildCore(coreConfig{ID: selfID, UserHash: userHash, TCPPort: 4662, UDPPort: 4672, Rand: rand.New(rand.NewPCG(1, 1))}, start)
	return &harness{t: t, c: c, now: start, answering: map[netip.AddrPort]Node{}}
}

func (h *harness) record(out output) {
	h.sent = append(h.sent, out.datagrams...)
	h.found = append(h.found, out.found...)
	h.requests = append(h.requests, out.requests...)
	for _, d := range out.datagrams {
		peer, ok := h.answering[d.to]
		if !ok {
			continue
		}
		switch p := d.packet.(type) {
		case kadwire.Req:
			h.record(h.c.onPacket(peer.Addr, kadwire.Res{Target: p.Target}, keys{}, h.now))
		case kadwire.HelloReq:
			h.record(h.c.onPacket(peer.Addr, kadwire.HelloRes{ID: peer.ID, TCPPort: peer.TCPPort, Version: peer.Version}, keys{}, h.now))
		case kadwire.BootstrapReq:
			h.record(h.c.onPacket(peer.Addr, kadwire.BootstrapRes{ID: peer.ID, TCPPort: peer.TCPPort, Version: peer.Version}, keys{}, h.now))
		}
	}
}

func (h *harness) tick(d time.Duration) {
	h.now = h.now.Add(d)
	h.record(h.c.onTick(h.now))
}

func (h *harness) receive(from netip.AddrPort, p wire.Packet) {
	h.record(h.c.onPacket(from, p, keys{}, h.now))
}

// clearSent forgets what was sent so far.
func (h *harness) clearSent() { h.sent, h.found, h.requests = nil, nil, nil }

type sent[T wire.Packet] struct {
	to     netip.AddrPort
	packet T
}

func packetsOf[T wire.Packet](h *harness) []sent[T] {
	var out []sent[T]
	for _, d := range h.sent {
		if p, ok := d.packet.(T); ok {
			out = append(out, sent[T]{d.to, p})
		}
	}
	return out
}

// buildNear makes a node whose ID shares the first bytes of target, so it
// is within SEARCHTOLERANCE of it.
func buildNear(target wire.Hash, n int) Node {
	id := target
	id[15] ^= byte(n + 1)
	id[14] ^= byte(n * 7)
	return Node{ID: id, Addr: netip.MustParseAddrPort(fmt.Sprintf("10.1.%d.%d:4672", n/250, n%250+1)), TCPPort: 4662, Version: 9}
}

// connect gives the core verified, answering contacts near target.
func (h *harness) connect(target wire.Hash, count int) []Node {
	var nodes []Node
	for i := range count {
		n := buildNear(target, i)
		h.c.table.add(n, true, h.now)
		h.answering[n.Addr] = n
		nodes = append(nodes, n)
	}
	return nodes
}

func TestBootstrapThenSelfLookup(t *testing.T) {
	h := buildHarness(t)
	seed := buildNear(fileHash, 0)
	h.c.addNodes([]Node{seed}, h.now)
	h.tick(time.Second)
	if got := packetsOf[kadwire.BootstrapReq](h); len(got) != 1 || got[0].to != seed.Addr {
		t.Fatalf("bootstrap requests %v, want one to the seed", got)
	}
	if h.c.status().Nodes != 0 {
		t.Fatal("connected before any answer")
	}
	learned := buildNear(fileHash, 1)
	h.receive(seed.Addr, kadwire.BootstrapRes{ID: seed.ID, TCPPort: seed.TCPPort, Version: seed.Version, Contacts: []kadwire.Contact{
		{ID: learned.ID, Addr: learned.Addr.Addr(), UDPPort: learned.Addr.Port(), TCPPort: learned.TCPPort, Version: learned.Version},
	}})
	if got := h.c.status(); got.Nodes != 1 || !got.IsFirewalled {
		t.Fatalf("status %+v, want one node and firewalled until checked", got)
	}
	h.clearSent()
	h.tick(time.Second)
	var reqs []sent[kadwire.Req]
	for _, r := range packetsOf[kadwire.Req](h) {
		if r.packet.Target == selfID {
			reqs = append(reqs, r)
		}
	}
	if len(reqs) != 2 {
		t.Fatalf("self lookup sent %d requests, want one to each known contact", len(reqs))
	}
	for _, r := range reqs {
		if r.packet.SearchType != kadwire.FindNode {
			t.Fatalf("self lookup request %+v", r.packet)
		}
	}
	if len(packetsOf[kadwire.BootstrapReq](h)) != 0 {
		t.Fatal("still bootstrapping while connected")
	}
}

func TestBootstrapPacesSeeds(t *testing.T) {
	h := buildHarness(t)
	h.c.addNodes([]Node{buildNear(fileHash, 0), buildNear(fileHash, 1), buildNear(fileHash, 2)}, h.now)
	for range 4 {
		h.tick(time.Second)
	}
	if got := len(packetsOf[kadwire.BootstrapReq](h)); got != 2 {
		t.Fatalf("%d bootstrap requests in 4 s, want one every 2 s", got)
	}
}

func TestUnrequestedResponsesAreIgnored(t *testing.T) {
	h := buildHarness(t)
	stranger := buildNear(fileHash, 0)
	pushed := buildNear(fileHash, 1)
	contacts := []kadwire.Contact{{ID: pushed.ID, Addr: pushed.Addr.Addr(), UDPPort: pushed.Addr.Port(), Version: 9}}
	h.receive(stranger.Addr, kadwire.Res{Target: fileHash, Contacts: contacts})
	h.receive(stranger.Addr, kadwire.BootstrapRes{ID: stranger.ID, Contacts: contacts})
	h.receive(stranger.Addr, kadwire.HelloRes{ID: stranger.ID, Version: 9})
	h.receive(stranger.Addr, kadwire.SearchRes{Target: fileHash, Results: []kadwire.Entry{buildOpenEntry(pushed.ID, "1.2.3.4", 4662)}})
	if len(h.c.table.byID) != 0 || len(h.found) != 0 {
		t.Fatalf("unrequested responses changed state: %d contacts, %d found", len(h.c.table.byID), len(h.found))
	}
}

func TestAnswersOtherNodes(t *testing.T) {
	h := buildHarness(t)
	nodes := h.connect(fileHash, 5)
	heard := buildNear(fileHash, 9)
	h.c.table.add(heard, false, h.now)
	asker := netip.MustParseAddrPort("10.9.9.9:5000")

	h.receive(asker, kadwire.Req{SearchType: kadwire.FindValue, Target: fileHash, Receiver: fileHash})
	if len(h.sent) != 0 {
		t.Fatal("answered a request meant for another ID")
	}
	h.receive(asker, kadwire.Req{SearchType: kadwire.FindValue, Target: fileHash, Receiver: selfID})
	res := packetsOf[kadwire.Res](h)
	if len(res) != 1 || res[0].to != asker || len(res[0].packet.Contacts) != 2 {
		t.Fatalf("routing answer %+v, want two contacts", res)
	}
	for _, ct := range res[0].packet.Contacts {
		if ct.ID == heard.ID {
			t.Fatal("answered with an unverified contact")
		}
	}

	h.clearSent()
	h.receive(asker, kadwire.BootstrapReq{})
	boot := packetsOf[kadwire.BootstrapRes](h)
	if len(boot) != 1 || boot[0].packet.ID != selfID || boot[0].packet.TCPPort != 4662 || len(boot[0].packet.Contacts) != len(nodes) {
		t.Fatalf("bootstrap answer %+v", boot)
	}

	h.clearSent()
	newcomer := buildNear(fileHash, 20)
	h.receive(newcomer.Addr, kadwire.HelloReq{ID: newcomer.ID, TCPPort: 4662, Version: 9})
	hello := packetsOf[kadwire.HelloRes](h)
	if len(hello) != 1 || hello[0].packet.ID != selfID || hello[0].packet.Version != kadwire.Version {
		t.Fatalf("hello answer %+v", hello)
	}
	if c := h.c.table.byID[newcomer.ID]; c == nil || c.isVerified {
		t.Fatal("want the greeting node added, unverified")
	}

	h.clearSent()
	h.receive(asker, kadwire.Ping{})
	if pong := packetsOf[kadwire.Pong](h); len(pong) != 1 || pong[0].packet.UDPPort != 5000 {
		t.Fatalf("pong %+v", pong)
	}
}

func buildOpenEntry(id wire.Hash, ip string, port uint16) kadwire.Entry {
	return kadwire.Entry{ID: id, Tags: []wire.Tag{
		{Type: wire.TagUint8, ID: kadwire.TagSourceType, Uint: 1},
		{Type: wire.TagUint32, ID: kadwire.TagSourceIP, Uint: uint64(kadwire.ToUint32(netip.MustParseAddr(ip)))},
		{Type: wire.TagUint16, ID: kadwire.TagSourcePort, Uint: uint64(port)},
		{Type: wire.TagUint16, ID: kadwire.TagSourceUPort, Uint: 4672},
		{Type: wire.TagUint8, ID: kadwire.TagEncryption, Uint: 3},
	}}
}

// buddyHashText is how eMule writes TAG_BUDDYHASH: the hex of the ID's Kad
// wire bytes.
func buddyHashText(id wire.Hash) string {
	var raw wire.Hash
	copy(raw[:], kadwire.BuildID(nil, id))
	return raw.String()
}

func buildFirewalledEntry(id, buddyID wire.Hash, buddy netip.AddrPort) kadwire.Entry {
	return kadwire.Entry{ID: id, Tags: []wire.Tag{
		{Type: wire.TagUint8, ID: kadwire.TagSourceType, Uint: 3},
		{Type: wire.TagUint32, ID: kadwire.TagSourceIP, Uint: uint64(kadwire.ToUint32(netip.MustParseAddr("5.6.7.8")))},
		{Type: wire.TagUint16, ID: kadwire.TagSourcePort, Uint: 4662},
		{Type: wire.TagUint32, ID: kadwire.TagServerIP, Uint: uint64(wire.ToClientID(buddy.Addr()))},
		{Type: wire.TagUint16, ID: kadwire.TagServerPort, Uint: uint64(buddy.Port())},
		{Type: wire.TagString, ID: kadwire.TagBuddyHash, String: buddyHashText(buddyID)},
	}}
}

// runSearch connects the core, wants fileHash, and plays the lookup until
// the first source request goes out; it returns that request.
func runSearch(t *testing.T, h *harness) sent[kadwire.SearchSourcesReq] {
	h.connect(fileHash, 6)
	h.c.setWanted(Wanted{Find: []Search{{Hash: fileHash, Size: 1000}}}, h.now)
	h.tick(time.Second)
	reqs := packetsOf[kadwire.Req](h)
	asked := 0
	for _, r := range reqs {
		if r.packet.Target == fileHash {
			asked++
			if r.packet.SearchType != kadwire.FindValue {
				t.Fatalf("source lookup asks with type %d", r.packet.SearchType)
			}
		}
	}
	if asked != alphaQuery {
		t.Fatalf("source lookup started with %d requests, want %d", asked, alphaQuery)
	}
	for range 5 {
		h.tick(time.Second)
		if got := packetsOf[kadwire.SearchSourcesReq](h); len(got) > 0 {
			if got[0].packet.Target != fileHash || got[0].packet.Size != 1000 {
				t.Fatalf("source request %+v", got[0].packet)
			}
			return got[0]
		}
	}
	t.Fatal("no source request after the lookup went quiet")
	return sent[kadwire.SearchSourcesReq]{}
}

func TestSourceSearchReportsSources(t *testing.T) {
	h := buildHarness(t)
	req := runSearch(t, h)
	for ip := range h.c.firewall.asked {
		h.c.onFirewallAck(ip)
	}
	open := mustHash("A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1")
	firewalled := mustHash("B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2")
	buddyID := mustHash("0011223344556677889900AABBCCDDEE")
	buddy := netip.MustParseAddrPort("9.8.7.6:4672")
	direct := buildOpenEntry(mustHash("C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3"), "1.1.1.1", 4662)
	direct.Tags[0].Uint = 6
	noPort := buildOpenEntry(mustHash("D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4"), "1.1.1.2", 0)
	h.receive(req.to, kadwire.SearchRes{Source: fileHash, Target: fileHash, Results: []kadwire.Entry{
		buildOpenEntry(open, "1.2.3.4", 4662),
		buildFirewalledEntry(firewalled, buddyID, buddy),
		direct,
		noPort,
		buildOpenEntry(userHash, "1.2.3.9", 4662),
		buildOpenEntry(open, "1.2.3.4", 4662),
	}})
	want := []Source{
		{Type: SourceOpen, UserHash: open, Addr: netip.MustParseAddrPort("1.2.3.4:4662"), UDPPort: 4672, CryptOptions: 3},
		{Type: SourceFirewalled, UserHash: firewalled, Addr: netip.MustParseAddrPort("5.6.7.8:4662"), Buddy: buddy, BuddyID: buddyID},
	}
	if len(h.found) != 1 || h.found[0].Hash != fileHash || fmt.Sprint(h.found[0].Sources) != fmt.Sprint(want) {
		t.Fatalf("found %+v\nwant %+v", h.found, want)
	}
	h.clearSent()
	h.receive(req.to, kadwire.SearchRes{Target: fileHash, Results: []kadwire.Entry{buildOpenEntry(open, "1.2.3.4", 4662)}})
	if len(h.found) != 0 {
		t.Fatal("reported a source twice in one search")
	}
}

func TestFirewalledSourcesNeedUsOpen(t *testing.T) {
	e := buildFirewalledEntry(mustHash("B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2"), mustHash("0011223344556677889900AABBCCDDEE"), netip.MustParseAddrPort("9.8.7.6:4672"))
	if _, ok := toSource(e, true); ok {
		t.Fatal("kept a firewalled source while firewalled")
	}
	if _, ok := toSource(e, false); !ok {
		t.Fatal("dropped a firewalled source while open")
	}
}

func TestRequestCallbackReachesBuddy(t *testing.T) {
	h := buildHarness(t)
	buddyID := mustHash("0011223344556677889900AABBCCDDEE")
	buddy := netip.MustParseAddrPort("9.8.7.6:4672")
	out := h.c.requestCallback(Callback{Buddy: buddy, BuddyID: buddyID, Hash: fileHash})
	if len(out.datagrams) != 1 || out.datagrams[0].to != buddy {
		t.Fatalf("callback datagrams %+v", out.datagrams)
	}
	got := wire.BuildPacketDatagram(nil, out.datagrams[0].packet)
	want := []byte{wire.ProtocolKad, 0x52}
	buddyWire := mustHash(buddyHashText(buddyID))
	want = append(want, buddyWire[:]...)
	want = kadwire.BuildID(want, fileHash)
	want = binary.LittleEndian.AppendUint16(want, 4662)
	if !bytes.Equal(got, want) {
		t.Fatalf("callback\n got %x\nwant %x", got, want)
	}
}

func TestSourceSearchReaskBacksOff(t *testing.T) {
	h := buildHarness(t)
	h.connect(fileHash, 6)
	h.c.setWanted(Wanted{Find: []Search{{Hash: fileHash, Size: 1000}}}, h.now)
	var starts []time.Duration
	isRunning := false
	for range 7 * 60 {
		h.tick(time.Minute)
		l := h.c.lookupByTarget(sourceSearch, fileHash)
		if l != nil && !isRunning {
			starts = append(starts, h.now.Sub(start))
		}
		isRunning = l != nil
	}
	want := []time.Duration{time.Minute, 61 * time.Minute, 181 * time.Minute, 361 * time.Minute}
	if fmt.Sprint(starts) != fmt.Sprint(want) {
		t.Fatalf("searches started at %v, want %v", starts, want)
	}
}

func TestSetWantedCancelsDroppedSearch(t *testing.T) {
	h := buildHarness(t)
	req := runSearch(t, h)
	h.c.setWanted(Wanted{}, h.now)
	h.clearSent()
	h.receive(req.to, kadwire.SearchRes{Target: fileHash, Results: []kadwire.Entry{buildOpenEntry(mustHash("A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1"), "1.2.3.4", 4662)}})
	if len(h.found) != 0 || h.c.lookupByTarget(sourceSearch, fileHash) != nil {
		t.Fatal("search kept running after the file was no longer wanted")
	}
}

func TestFirewallCheckGatesPublishing(t *testing.T) {
	h := buildHarness(t)
	h.connect(fileHash, 6)
	h.c.setWanted(Wanted{Publish: []Publish{{Hash: fileHash, Size: 5000}}}, h.now)
	for range 60 {
		h.tick(time.Second)
	}
	fwReqs := packetsOf[kadwire.FirewalledReq](h)
	if len(fwReqs) != firewallChecks {
		t.Fatalf("%d firewall checks out, want %d", len(fwReqs), firewallChecks)
	}
	if r := fwReqs[0].packet; r.TCPPort != 4662 || r.ID != userHash {
		t.Fatalf("firewall request %+v", r)
	}
	if !h.c.status().IsFirewalled || len(packetsOf[kadwire.PublishSourcesReq](h)) != 0 {
		t.Fatal("published before the firewall check passed")
	}

	stranger := netip.MustParseAddrPort("10.200.0.1:4672")
	h.receive(stranger, wire.Unknown{Proto: wire.ProtocolKad, Op: 0x59})
	h.c.onFirewallAck(stranger.Addr())
	h.receive(fwReqs[0].to, wire.Unknown{Proto: wire.ProtocolKad, Op: 0x59})
	h.receive(fwReqs[0].to, wire.Unknown{Proto: wire.ProtocolKad, Op: 0x59})
	if !h.c.status().IsFirewalled {
		t.Fatal("open after acks from one asked node and a stranger")
	}
	h.c.onFirewallAck(fwReqs[1].to.Addr())
	if h.c.status().IsFirewalled {
		t.Fatal("still firewalled after two acks")
	}

	h.clearSent()
	for range 10 {
		h.tick(time.Second)
	}
	pubs := packetsOf[kadwire.PublishSourcesReq](h)
	if len(pubs) == 0 {
		t.Fatal("no publish after the firewall check passed")
	}
	p := pubs[0].packet
	if p.FileID != fileHash || p.Source.ID != userHash {
		t.Fatalf("publish %+v", p)
	}
	wantTags := map[byte]uint64{kadwire.TagSourceType: 1, kadwire.TagSourcePort: 4662, kadwire.TagFileSize: 5000}
	for id, v := range wantTags {
		if tag, ok := p.Source.TagByID(id); !ok || tag.Uint != v {
			t.Fatalf("publish tag %#x = %+v, want %d", id, tag, v)
		}
	}
	if _, ok := p.Source.TagByID(kadwire.TagSourceUPort); ok {
		t.Fatal("published our UDP port before a UDP test chose it over the NAT's")
	}
	l := h.c.lookupByTarget(sourcePublish, fileHash)
	for _, pub := range pubs {
		h.receive(pub.to, kadwire.PublishRes{FileID: fileHash, Load: 1})
	}
	if l.answers != len(pubs) {
		t.Fatalf("%d publish acknowledgements counted, want %d", l.answers, len(pubs))
	}
}

func TestIndexStoresAndServesSources(t *testing.T) {
	h := buildHarness(t)
	near := selfID
	near[15] ^= 1
	publisher := netip.MustParseAddrPort("10.7.0.1:4672")
	source := kadwire.Entry{ID: userHash, Tags: []wire.Tag{
		{Type: wire.TagUint8, ID: kadwire.TagSourceType, Uint: 1},
		{Type: wire.TagUint16, ID: kadwire.TagSourcePort, Uint: 4662},
	}}
	h.receive(publisher, kadwire.PublishSourcesReq{FileID: fileHash, Source: source})
	if len(h.sent) != 0 {
		t.Fatal("stored a source for a file far from our ID")
	}
	h.receive(publisher, kadwire.PublishSourcesReq{FileID: near, Source: source})
	if res := packetsOf[kadwire.PublishRes](h); len(res) != 1 || res[0].packet.FileID != near {
		t.Fatalf("publish answer %+v", res)
	}

	h.clearSent()
	searcher := netip.MustParseAddrPort("10.7.0.2:4672")
	h.receive(searcher, kadwire.SearchSourcesReq{Target: near, Size: 1})
	res := packetsOf[kadwire.SearchRes](h)
	if len(res) != 1 || len(res[0].packet.Results) != 1 {
		t.Fatalf("search answer %+v", res)
	}
	s, ok := toSource(res[0].packet.Results[0], false)
	want := Source{Type: SourceOpen, UserHash: userHash, Addr: netip.MustParseAddrPort("10.7.0.1:4662"), UDPPort: 4672}
	if !ok || s != want {
		t.Fatalf("served source %+v, want %+v", s, want)
	}

	h.clearSent()
	h.tick(republishSources)
	h.receive(searcher, kadwire.SearchSourcesReq{Target: near, Size: 1})
	if len(packetsOf[kadwire.SearchRes](h)) != 0 {
		t.Fatal("served an expired source")
	}
}

// TestObfuscationFollowsAMule: requests to Kad 6+ contacts go out keyed
// by their node ID, answers with the key the request carried, and a plain
// request gets a plain answer.
func TestObfuscationFollowsAMule(t *testing.T) {
	h := buildHarness(t)
	old := buildNear(fileHash, 1)
	old.Version = 5
	h.c.table.add(old, true, h.now)
	modern := h.connect(fileHash, 1)[0]
	delete(h.answering, modern.Addr)

	h.c.startLookup(nodeLookup, fileHash, 0, h.now)
	h.record(h.c.out)
	h.c.out = output{}
	if len(h.sent) != 2 {
		t.Fatalf("lookup sent %d requests, want 2", len(h.sent))
	}
	for _, d := range h.sent {
		want := wire.Hash{}
		if d.to == modern.Addr {
			want = modern.ID
		}
		if d.nodeID != want {
			t.Fatalf("request to %v keyed by %v, want %v", d.to, d.nodeID, want)
		}
	}

	h.clearSent()
	h.receive(modern.Addr, kadwire.Ping{})
	if len(h.sent) != 1 || h.sent[0].receiverKey != 0 || h.sent[0].nodeID != (wire.Hash{}) {
		t.Fatalf("answer to a plain ping %+v, want plain", h.sent)
	}
	h.clearSent()
	h.record(h.c.onPacket(modern.Addr, kadwire.Ping{}, keys{sender: 0x1234}, h.now))
	if len(h.sent) != 1 || h.sent[0].receiverKey != 0x1234 || h.sent[0].nodeID != (wire.Hash{}) ||
		h.sent[0].senderKey != obfuscation.BuildKadVerifyKey(h.c.udpKey, modern.Addr.Addr()) {
		t.Fatalf("answer to an obfuscated ping %+v, want it keyed by the ping's sender key", h.sent)
	}
	if h.c.table.byAddr[modern.Addr].udpKey != 0x1234 {
		t.Fatal("contact did not keep its sender key")
	}

	d := h.sent[0]
	data := h.c.buildDatagram(d)
	p, k, isKad := buildCore(coreConfig{ID: modern.ID, Rand: h.c.rng}, h.now).parseDatagram(Datagram{Addr: netip.AddrPortFrom(netip.MustParseAddr("10.0.0.1"), 4672), Data: data})
	if isKad || p != nil || k != (keys{}) {
		t.Fatal("a receiver key datagram decoded with someone else's verify key")
	}
}

func miscOptionsOf(h kadwire.Hello) (byte, bool) {
	for _, t := range h.Tags {
		if t.ID == kadwire.TagKadMiscOptions {
			return byte(t.Uint), true
		}
	}
	return 0, false
}

// TestHelloKeysAndMiscOptions follows AddContact2 and SendMyDetails: a
// hello carrying our verify key proves its sender's IP, a UDP firewalled
// sender stays out of the table, and only version 8 nodes hear our
// firewall state.
func TestHelloKeysAndMiscOptions(t *testing.T) {
	h := buildHarness(t)
	known := buildNear(fileHash, 1)
	h.c.onPacket(known.Addr, kadwire.HelloReq{ID: known.ID, TCPPort: 4662, Version: 8}, keys{sender: 0x77, receiver: obfuscation.BuildKadVerifyKey(h.c.udpKey, known.Addr.Addr())}, h.now)
	if c := h.c.table.byID[known.ID]; c == nil || !c.isVerified {
		t.Fatal("a hello with our verify key did not verify its sender")
	}
	stranger := buildNear(fileHash, 2)
	h.c.onPacket(stranger.Addr, kadwire.HelloReq{ID: stranger.ID, TCPPort: 4662, Version: 8}, keys{sender: 0x77, receiver: 0x1234}, h.now)
	if c := h.c.table.byID[stranger.ID]; c == nil || c.isVerified {
		t.Fatal("want a hello with a wrong receiver key added unverified")
	}

	h.clearSent()
	nat := buildNear(fileHash, 3)
	udpFirewalled := wire.Tag{Type: wire.TagUint8, ID: kadwire.TagKadMiscOptions, Uint: uint64(kadwire.MiscUDPFirewalled | kadwire.MiscTCPFirewalled)}
	h.receive(nat.Addr, kadwire.HelloReq{ID: nat.ID, TCPPort: 4662, Version: 8, Tags: []wire.Tag{udpFirewalled}})
	if h.c.table.byID[nat.ID] != nil {
		t.Fatal("added a UDP firewalled node")
	}
	res := packetsOf[kadwire.HelloRes](h)
	if len(res) != 1 {
		t.Fatalf("hello answers %+v, want one", res)
	}
	if misc, ok := miscOptionsOf(kadwire.Hello(res[0].packet)); !ok || misc != kadwire.MiscTCPFirewalled {
		t.Fatalf("misc options %#x %v, want TCP firewalled before any check", misc, ok)
	}

	h.clearSent()
	legacy := buildNear(fileHash, 4)
	h.receive(legacy.Addr, kadwire.HelloReq{ID: legacy.ID, TCPPort: 4662, Version: 7})
	if res := packetsOf[kadwire.HelloRes](h); len(res) != 1 || len(res[0].packet.Tags) != 0 {
		t.Fatalf("answer to a version 7 hello %+v, want no tags", res)
	}
}

// TestHelloResAck is the three-way hello of Kad version 8: a node we added
// on its word is asked for a HelloResAck, which verifies it only when it
// carries our verify key; we answer such a request when the asker is a
// version 8 node that gave us its key.
func TestHelloResAck(t *testing.T) {
	h := buildHarness(t)
	n := buildNear(fileHash, 1)
	n.Version = 8
	verifyKey := obfuscation.BuildKadVerifyKey(h.c.udpKey, n.Addr.Addr())
	h.c.onPacket(n.Addr, kadwire.HelloResAck{ID: n.ID}, keys{receiver: verifyKey}, h.now)
	h.receive(n.Addr, kadwire.HelloReq{ID: n.ID, TCPPort: 4662, Version: 8})
	if h.c.table.byID[n.ID].isVerified {
		t.Fatal("an unasked ACK verified a node")
	}
	res := packetsOf[kadwire.HelloRes](h)
	if misc, _ := miscOptionsOf(kadwire.Hello(res[0].packet)); misc&kadwire.MiscRequestsAck == 0 {
		t.Fatalf("hello answer %+v does not ask for an ACK", res)
	}
	h.c.onPacket(n.Addr, kadwire.HelloResAck{ID: n.ID}, keys{receiver: 0x1234}, h.now)
	if h.c.table.byID[n.ID].isVerified {
		t.Fatal("an ACK without our verify key verified a node")
	}
	h.receive(n.Addr, kadwire.HelloReq{ID: n.ID, TCPPort: 4662, Version: 8})
	h.c.onPacket(n.Addr, kadwire.HelloResAck{ID: n.ID}, keys{receiver: verifyKey}, h.now)
	if !h.c.table.byID[n.ID].isVerified {
		t.Fatal("the ACK did not verify the node")
	}

	askAck := []wire.Tag{{Type: wire.TagUint8, ID: kadwire.TagKadMiscOptions, Uint: uint64(kadwire.MiscRequestsAck)}}
	for _, tc := range []struct {
		version   byte
		senderKey uint32
		isAcked   bool
	}{{8, 0x55, true}, {7, 0x55, false}, {8, 0, false}} {
		h.clearSent()
		h.c.rpcs.add(&rpc{kind: rpcHello, node: n, sent: h.now})
		h.record(h.c.onPacket(n.Addr, kadwire.HelloRes{ID: n.ID, TCPPort: 4662, Version: tc.version, Tags: askAck}, keys{sender: tc.senderKey}, h.now))
		acks := packetsOf[kadwire.HelloResAck](h)
		if tc.isAcked != (len(acks) == 1) || tc.isAcked && (acks[0].packet.ID != selfID || h.sent[0].receiverKey != tc.senderKey || h.sent[0].nodeID != (wire.Hash{})) {
			t.Fatalf("version %d, sender key %#x: sent %+v", tc.version, tc.senderKey, h.sent)
		}
	}
}
