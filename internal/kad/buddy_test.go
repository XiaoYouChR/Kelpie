package kad

import (
	"net/netip"
	"testing"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/wire"
	kadwire "github.com/XiaoYouChR/Kelpie/internal/wire/kad"
)

// setUDPVerdict ends the harness's UDP test with the given verdict.
func (h *harness) setUDPVerdict(isFirewalled bool) {
	h.c.udp.finished = udpCheckClients
	h.c.udp.isFirewalled, h.c.udp.isVerified = isFirewalled, true
}

func TestFirewalledNodeFindsBuddy(t *testing.T) {
	h := buildHarness(t)
	h.connect(h.c.buddyTarget(), 4)
	for i := 10; i < 14; i++ {
		n := buildNear(fileHash, i)
		h.c.table.add(n, true, h.now)
		h.answering[n.Addr] = n
	}
	h.c.setWanted(Wanted{Publish: []Publish{{Hash: fileHash, Size: 5000}}}, h.now)
	h.tick(time.Second)
	h.setUDPVerdict(true)
	for range 4 * 60 {
		h.tick(time.Second)
	}
	if len(packetsOf[kadwire.FindBuddyReq](h)) != 0 {
		t.Fatal("looked for a buddy before 5 minutes")
	}
	for range 2 * 60 {
		h.tick(time.Second)
	}
	reqs := packetsOf[kadwire.FindBuddyReq](h)
	if len(reqs) == 0 {
		t.Fatal("no buddy request after 6 minutes")
	}
	if r := reqs[0].packet; r.Target != h.c.buddyTarget() || r.UserHash != userHash || r.TCPPort != 4662 {
		t.Fatalf("buddy request %+v", r)
	}
	if len(packetsOf[kadwire.PublishSourcesReq](h)) != 0 {
		t.Fatal("published while firewalled without a buddy")
	}

	h.clearSent()
	h.receive(netip.MustParseAddrPort("10.99.0.1:4672"), kadwire.FindBuddyRes{Target: h.c.buddyTarget(), UserHash: wire.Hash{9}, TCPPort: 4662})
	if len(h.requests) != 0 {
		t.Fatal("took an answer to a request we did not send")
	}
	h.receive(reqs[0].to, kadwire.FindBuddyRes{Target: h.c.buddyTarget(), UserHash: wire.Hash{9}, TCPPort: 4111, HasOptions: true, Options: 3})
	want := BuddyFound{Addr: netip.AddrPortFrom(reqs[0].to.Addr(), 4111), UserHash: wire.Hash{9}, CryptOptions: 3}
	if len(h.requests) != 1 || h.requests[0] != want {
		t.Fatalf("requests %+v, want %+v", h.requests, want)
	}

	buddy := netip.MustParseAddrPort("10.99.0.2:4672")
	h.c.setBuddy(Buddy{IsConnected: true, Addr: buddy})
	h.clearSent()
	for range 10 {
		h.tick(time.Second)
	}
	pubs := packetsOf[kadwire.PublishSourcesReq](h)
	if len(pubs) == 0 {
		t.Fatal("no publish with a buddy")
	}
	src, ok := toSource(kadwire.Entry{ID: userHash, Tags: append(pubs[0].packet.Source.Tags,
		wire.Tag{Type: wire.TagUint32, ID: kadwire.TagSourceIP, Uint: uint64(kadwire.ToUint32(netip.MustParseAddr("10.5.5.5")))})}, false)
	if !ok || src.Type != SourceFirewalled || src.Buddy != buddy || src.BuddyID != h.c.buddyTarget() {
		t.Fatalf("published source reads back as %+v, %v", src, ok)
	}

	h.clearSent()
	h.c.setBuddy(Buddy{})
	for range 3 * 60 {
		h.tick(time.Second)
	}
	if len(packetsOf[kadwire.FindBuddyReq](h)) == 0 {
		t.Fatal("did not look for a new buddy after losing one")
	}
}

func TestOpenNodeServesAsBuddy(t *testing.T) {
	h := buildHarness(t)
	asker := netip.MustParseAddrPort("10.9.9.9:5000")
	target, user := wire.Hash{0x77}, wire.Hash{0x88}
	req := kadwire.FindBuddyReq{Target: target, UserHash: user, TCPPort: 4111}
	h.receive(asker, req)
	if len(h.sent) != 0 {
		t.Fatal("answered a buddy request while firewalled")
	}

	h.c.firewall.acks = firewallOpenAcks
	h.receive(asker, req)
	if len(h.sent) != 0 {
		t.Fatal("answered a buddy request before a UDP test confirmed us open")
	}
	h.setUDPVerdict(false)
	h.record(h.c.onPacket(asker, req, keys{sender: 0x5555}, h.now))
	res := packetsOf[kadwire.FindBuddyRes](h)
	wantRes := kadwire.FindBuddyRes{Target: target, UserHash: userHash, TCPPort: 4662, HasOptions: true, Options: connectOptions}
	if len(res) != 1 || res[0].to != asker || res[0].packet != wantRes {
		t.Fatalf("buddy answer %+v, want %+v", res, wantRes)
	}
	wantReq := BuddyRequested{Addr: netip.AddrPortFrom(asker.Addr(), 4111), UserHash: user, BuddyID: target}
	if len(h.requests) != 1 || h.requests[0] != wantReq {
		t.Fatalf("requests %+v, want %+v", h.requests, wantReq)
	}

	h.clearSent()
	downloader := netip.MustParseAddrPort("10.8.8.8:4672")
	callback := kadwire.CallbackReq{BuddyID: target, Hash: fileHash, TCPPort: 4663}
	h.receive(downloader, callback)
	if len(h.requests) != 0 {
		t.Fatal("passed a callback on without a buddy link")
	}
	h.c.setBuddy(Buddy{IsConnected: true})
	h.receive(asker, req)
	h.receive(downloader, callback)
	want := CallbackRequested{BuddyID: target, Hash: fileHash, Addr: netip.AddrPortFrom(downloader.Addr(), 4663)}
	if len(packetsOf[kadwire.FindBuddyRes](h)) != 0 || len(h.requests) != 1 || h.requests[0] != want {
		t.Fatalf("with a buddy: sent %+v, requests %+v", h.sent, h.requests)
	}
}

func TestSourceTypesTwoAndSix(t *testing.T) {
	user := wire.Hash{0x66}
	direct := func(options byte) kadwire.Entry {
		return kadwire.Entry{ID: user, Tags: []wire.Tag{
			{Type: wire.TagUint8, ID: kadwire.TagSourceType, Uint: 6},
			{Type: wire.TagUint32, ID: kadwire.TagSourceIP, Uint: uint64(kadwire.ToUint32(netip.MustParseAddr("5.6.7.8")))},
			{Type: wire.TagUint16, ID: kadwire.TagSourcePort, Uint: 4662},
			{Type: wire.TagUint16, ID: kadwire.TagSourceUPort, Uint: 4672},
			{Type: wire.TagUint8, ID: kadwire.TagEncryption, Uint: uint64(options)},
		}}
	}
	s, ok := toSource(direct(0x0B), false)
	want := Source{Type: SourceDirectCallback, UserHash: user, Addr: netip.MustParseAddrPort("5.6.7.8:4662"), UDPPort: 4672, CryptOptions: 0x0B}
	if !ok || s != want {
		t.Fatalf("type 6 source %+v, %v; want %+v", s, ok, want)
	}
	if _, ok := toSource(direct(0x0B), true); ok {
		t.Fatal("kept a direct callback source while firewalled")
	}
	if _, ok := toSource(direct(0x03), false); ok {
		t.Fatal("kept a type 6 source without the direct callback flag")
	}
	two := direct(0x0B)
	two.Tags[0].Uint = 2
	if _, ok := toSource(two, false); ok {
		t.Fatal("kept a type 2 source")
	}
}

func TestFirewalledNodeWithOpenUDPTakesDirectCallbacks(t *testing.T) {
	h := buildHarness(t)
	h.connect(fileHash, 4)
	h.setUDPVerdict(false)
	h.c.setWanted(Wanted{Publish: []Publish{{Hash: fileHash, Size: 5000}}}, h.now)
	for range 60 {
		h.tick(time.Second)
	}
	pubs := packetsOf[kadwire.PublishSourcesReq](h)
	if len(pubs) == 0 || len(packetsOf[kadwire.FindBuddyReq](h)) != 0 {
		t.Fatalf("%d publishes, buddy requests %v", len(pubs), packetsOf[kadwire.FindBuddyReq](h))
	}
	entry := pubs[0].packet.Source
	entry.Tags = append(entry.Tags,
		wire.Tag{Type: wire.TagUint32, ID: kadwire.TagSourceIP, Uint: uint64(kadwire.ToUint32(netip.MustParseAddr("10.5.5.5")))},
		wire.Tag{Type: wire.TagUint16, ID: kadwire.TagSourceUPort, Uint: 4672})
	if src, ok := toSource(entry, false); !ok || src.Type != SourceDirectCallback {
		t.Fatalf("published source reads back as %+v, %v", src, ok)
	}
}
