package kad

import (
	"bytes"
	"compress/zlib"
	"encoding/hex"
	"net/netip"
	"reflect"
	"testing"

	"github.com/XiaoYouChR/Kelpie/internal/wire"
)

var (
	idA = mustHash("23A8CEFF57A7A32D562D649ED7893796")
	idB = mustHash("31D6CFE0D16AE931B73C59D7E0C089C0")
	idC = mustHash("31D6CFE0D14CE931B73C59D7E0C04BC0")
)

func mustHash(s string) wire.Hash {
	h, err := wire.ParseHash(s)
	if err != nil {
		panic(err)
	}
	return h
}

func localContact() Contact {
	return Contact{ID: idB, Addr: netip.MustParseAddr("127.0.0.1"), UDPPort: 4672, TCPPort: 4661, Version: 8}
}

func roundTrip(t *testing.T, p wire.Packet) wire.Packet {
	t.Helper()
	frame, err := wire.ParseDatagram(wire.BuildPacketDatagram(nil, p))
	if err != nil {
		t.Fatal(err)
	}
	if frame.Opcode != p.Opcode() {
		t.Fatalf("%T: opcode %#x, want %#x", p, frame.Opcode, p.Opcode())
	}
	got, err := Parse(frame.Protocol, frame.Opcode, frame.Body)
	if err != nil {
		t.Fatalf("%T: %v", p, err)
	}
	if !reflect.DeepEqual(got, p) {
		t.Fatalf("%T round trip\n got  %+v\n want %+v", p, got, p)
	}
	return got
}

func TestRoundTrip(t *testing.T) {
	sourceTags := []wire.Tag{
		{Type: wire.TagUint8, ID: TagSourceType, Uint: 1},
		{Type: wire.TagUint32, ID: TagSourceIP, Uint: 0x0100007f},
		{Type: wire.TagUint16, ID: TagSourcePort, Uint: 4662},
	}
	packets := []wire.Packet{
		BootstrapReq{},
		BootstrapRes{ID: idA, TCPPort: 4661, Version: Version, Contacts: []Contact{localContact()}},
		HelloReq{ID: idA, TCPPort: 4662, Version: 9, Tags: []wire.Tag{{Type: wire.TagUint16, ID: TagSourceUPort, Uint: 4672}}},
		HelloRes{ID: idA, TCPPort: 4662, Version: 9},
		HelloRes{ID: idA, TCPPort: 4662, Version: 8, Tags: []wire.Tag{{Type: wire.TagUint8, ID: TagKadMiscOptions, Uint: uint64(MiscRequestsAck)}}},
		HelloResAck{ID: idA},
		Req{SearchType: FindNode, Target: idA, Receiver: idB},
		Res{Target: idA, Contacts: []Contact{{ID: idC, Addr: netip.MustParseAddr("127.0.0.1"), UDPPort: 4672, TCPPort: 4661, Version: 8}}},
		SearchKeysReq{Target: idA},
		SearchSourcesReq{Target: idA, StartPos: 7, Size: 12345},
		SearchNotesReq{Target: idA, Size: 99},
		SearchRes{Source: idA, Target: idB, Results: []Entry{{ID: idC, Tags: sourceTags}}},
		PublishKeysReq{KeywordID: idA, Sources: []Entry{{ID: idB, Tags: []wire.Tag{{Type: wire.TagString, ID: 0x01, String: "demo.epub"}}}}},
		PublishSourcesReq{FileID: idA, Source: Entry{ID: idB, Tags: sourceTags}},
		PublishRes{FileID: idA, Load: 1},
		PublishNotesRes{FileID: idA, Load: 1},
		LegacyFirewalledReq{TCPPort: 4662},
		FirewalledReq{TCPPort: 4661, ID: idA, Options: 3},
		FirewalledRes{Addr: netip.MustParseAddr("127.0.0.1")},
		FirewalledUDP{ErrorCode: 1, Port: 4662},
		Ping{},
		Pong{UDPPort: 4672},
		FindBuddyReq{Target: idA, UserHash: idB, TCPPort: 4662},
		FindBuddyRes{Target: idA, UserHash: idB, TCPPort: 4662},
		FindBuddyRes{Target: idA, UserHash: idB, TCPPort: 4662, HasOptions: true, Options: 3},
		CallbackReq{BuddyID: idA, Hash: idB, TCPPort: 4662},
	}
	for _, p := range packets {
		roundTrip(t, p)
	}
}

// TestHelloResAckGolden: aMule's ACK is our ID and a zero tag count
// (KademliaUDPListener.cpp:612).
func TestHelloResAckGolden(t *testing.T) {
	got := HelloResAck{ID: idB}.Build(nil)
	want := "e0cfd63131e96ad1d7593cb7c089c0e0" + "00"
	if hex.EncodeToString(got) != want {
		t.Fatalf("ack = %x\nwant  %s", got, want)
	}
}

// Ported from goed2k protocol/kad/types_test.go.
func TestIDRoundTrip(t *testing.T) {
	r := &wire.Reader{Rest: BuildID(nil, idA)}
	if got := ParseID(r); got != idA {
		t.Fatalf("id = %s", got)
	}
}

func TestIDGolden(t *testing.T) {
	var id wire.Hash
	for i := range id {
		id[i] = byte(i)
	}
	want := "03020100070605040b0a09080f0e0d0c"
	if got := hex.EncodeToString(BuildID(nil, id)); got != want {
		t.Fatalf("id = %s, want %s", got, want)
	}
}

func TestContactGolden(t *testing.T) {
	got := buildContact(nil, localContact())
	want := "e0cfd63131e96ad1d7593cb7c089c0e0" + "0100007f" + "4012" + "3512" + "08"
	if hex.EncodeToString(got) != want {
		t.Fatalf("contact = %x\nwant      %s", got, want)
	}
}

// Ported from goed2k protocol/kad/types_test.go.
func TestSearchEntryExtractsSourceAddrPort(t *testing.T) {
	entry := Entry{Tags: []wire.Tag{
		{ID: TagSourceType, Uint: 1},
		{ID: TagSourceIP, Uint: 0x7f000001},
		{ID: TagSourcePort, Uint: 4662},
	}}
	ap, ok := entry.SourceAddrPort()
	if !ok || ap != netip.MustParseAddrPort("127.0.0.1:4662") {
		t.Fatalf("source = %v %v", ap, ok)
	}
}

// Ported from goed2k protocol/kad/types_test.go.
func TestTagReadsStandardOneByteName(t *testing.T) {
	r := &wire.Reader{Rest: []byte{wire.TagUint32, 1, 0, TagSourceIP, 0x01, 0x00, 0x00, 0x7f}}
	tag := r.Tag()
	if r.Err() != nil || tag.ID != TagSourceIP || tag.Uint != 0x7f000001 {
		t.Fatalf("tag = %+v %v", tag, r.Err())
	}
}

func TestTagsUseClassicNames(t *testing.T) {
	got := buildEntry(nil, Entry{ID: idA, Tags: []wire.Tag{{Type: wire.TagUint16, ID: TagSourcePort, Uint: 4662}}})
	if !bytes.Equal(got[16:], []byte{1, wire.TagUint16, 1, 0, TagSourcePort, 0x36, 0x12}) {
		t.Fatalf("entry tags = %x", got[16:])
	}
}

// Ported from goed2k protocol/kad/packet_combiner_test.go.
func TestCompressedPacketParses(t *testing.T) {
	body := SearchRes{Source: idA, Target: idB}.Build(nil)
	var compressed bytes.Buffer
	zw := zlib.NewWriter(&compressed)
	zw.Write(body)
	zw.Close()
	raw := append([]byte{wire.ProtocolKadPacked, opSearchRes}, compressed.Bytes()...)
	frame, err := wire.ParseDatagram(raw)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(frame.Protocol, frame.Opcode, frame.Body)
	if err != nil {
		t.Fatal(err)
	}
	if res, ok := got.(SearchRes); !ok || res.Source != idA || res.Target != idB {
		t.Fatalf("got %+v", got)
	}
}

func TestParseRejectsImpossibleCounts(t *testing.T) {
	body := append(BuildID(nil, idA), 0x01, 0x00, Version, 0xFF, 0xFF)
	if _, err := Parse(wire.ProtocolKad, opBootstrapRes, body); err == nil {
		t.Fatal("want error")
	}
}

func TestUnknownOpcodesSurvive(t *testing.T) {
	got, err := Parse(wire.ProtocolKad, 0x45, []byte{1, 2})
	if err != nil || !reflect.DeepEqual(got, wire.Unknown{Proto: wire.ProtocolKad, Op: 0x45, Body: []byte{1, 2}}) {
		t.Fatalf("got %+v, %v", got, err)
	}
}
