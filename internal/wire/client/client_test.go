package client

import (
	"bytes"
	"encoding/hex"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/XiaoYouChR/Kelpie/internal/wire"
)

var (
	fileHash = mustHash("31D6CFE0D16AE931B73C59D7E0C089C0")
	userHash = mustHash("23A8CEFF57A7A32D562D649ED7893796")
)

var aichRoot = wire.AICHHash{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}

func mustHash(s string) wire.Hash {
	h, err := wire.ParseHash(s)
	if err != nil {
		panic(err)
	}
	return h
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func parts(bits ...bool) wire.Bitfield { return wire.ToBitfield(bits) }

func roundTrip(t *testing.T, p wire.Packet, parse func(byte, byte, []byte) (wire.Packet, error)) {
	t.Helper()
	frame, n, err := wire.ParseFrame(wire.BuildPacket(nil, p))
	if err != nil || n == 0 {
		t.Fatalf("%T: frame n=%d err=%v", p, n, err)
	}
	got, err := parse(frame.Protocol, frame.Opcode, frame.Body)
	if err != nil {
		t.Fatalf("%T: %v", p, err)
	}
	if !reflect.DeepEqual(got, p) {
		t.Fatalf("%T round trip\n got  %+v\n want %+v", p, got, p)
	}
}

func TestTCPRoundTrip(t *testing.T) {
	hello := Hello{
		UserHash:     userHash,
		ClientID:     0x04030201,
		Port:         4662,
		Server:       netip.MustParseAddrPort("5.6.7.8:4661"),
		Name:         "Kelpie",
		Version:      EDonkeyVersion,
		ModName:      "Kelpie 0.1",
		UDPPort:      4672,
		KadPort:      4673,
		Misc1:        MiscOptions1{IsUnicode: true, UDPVersion: 4, DataCompressionVersion: 1, SecureIdentVersion: 2, SourceExchange1Version: 3, ExtendedRequestsVersion: ExtendedRequestsVersion, HasMultiPacket: true, IsSharedFilesHidden: true},
		Misc2:        MiscOptions2{HasLargeFiles: true, HasExtMultiPacket: true, HasSourceExchange2: true, HasCaptcha: true},
		EmuleVersion: 0x00002000,
		ModMisc:      ModMiscExtendedSources | ModMiscIPv6,
		YourIP:       netip.MustParseAddr("9.9.9.9"),
		IPv6:         netip.MustParseAddr("2a01:4f8::1"),
		Tags:         []wire.Tag{{Type: wire.TagString, Name: "custom", String: "x"}},
	}
	answer := HelloAnswer(hello)
	answer.YourIP = netip.MustParseAddr("2a01:4f8::2")
	packets := []wire.Packet{
		hello,
		answer,
		Hello{UserHash: userHash, ClientID: 7},
		EmuleInfo{Version: 0x40, ProtocolVersion: 1, Tags: []wire.Tag{{Type: wire.TagUint32, ID: InfoSourceExchange, Uint: 3}}},
		EmuleInfoAnswer{Version: 0x40, ProtocolVersion: 1},
		FileRequest{Hash: fileHash},
		FileRequest{Hash: fileHash, HasParts: true, Parts: parts(true, false, true)},
		FileRequest{Hash: fileHash, HasParts: true, Parts: parts(), HasCompleteSources: true, CompleteSources: 9},
		FileNameAnswer{Hash: fileHash, Name: "kelpie.iso"},
		SetRequestFileID{Hash: fileHash},
		FileStatus{Hash: fileHash, Parts: parts(true, true, false, true, false, false, false, false, true)},
		NoFile{Hash: fileHash},
		HashSetRequest{Hash: fileHash},
		HashSetAnswer{Hash: fileHash, Parts: []wire.Hash{userHash, fileHash}},
		StartUploadRequest{Hash: fileHash},
		AcceptUploadRequest{},
		CancelTransfer{},
		OutOfParts{},
		QueueRank{Rank: 70000},
		QueueRanking{Rank: 42},
		RequestParts{Hash: fileHash, Starts: [3]uint32{0, 10, 0}, Ends: [3]uint32{10, 20, 0}},
		RequestParts64{Hash: fileHash, Starts: [3]uint64{1 << 33, 0, 0}, Ends: [3]uint64{1<<33 + 10, 0, 0}},
		SendingPart{Hash: fileHash, Start: 100, End: 103, Data: []byte{1, 2, 3}},
		SendingPart64{Hash: fileHash, Start: 1 << 33, End: 1<<33 + 2, Data: []byte{1, 2}},
		CompressedPart{Hash: fileHash, Start: 100, PackedSize: 50, Data: []byte{9, 9}},
		CompressedPart64{Hash: fileHash, Start: 1 << 33, PackedSize: 50, Data: []byte{9, 9}},
		RequestSources{Hash: fileHash},
		AnswerSources{Hash: fileHash, Sources: []Source{{ClientID: 1, Port: 2, Server: netip.MustParseAddrPort("1.2.3.4:5")}}},
		AnswerSources{Hash: fileHash, HasUserHash: true, Sources: []Source{{ClientID: 1, Port: 2, UserHash: userHash}}},
		RequestSources2{Version: SourceExchange2Version, Hash: fileHash},
		AnswerSources2{Version: 4, Hash: fileHash, Sources: []Source{{ClientID: 0x0100000A, Port: 4662, Server: netip.MustParseAddrPort("1.2.3.4:4661"), UserHash: userHash, CryptOptions: 0x81}}},
		AnswerSources2{Version: 2, Hash: fileHash, Sources: []Source{{ClientID: 3, Port: 4, UserHash: userHash}}},
		AnswerSources2{Version: ExtendedSourcesVersion, Hash: fileHash, Sources: []Source{
			{ClientID: 0x0100000A, Port: 4662, Server: netip.MustParseAddrPort("1.2.3.4:4661"), IPv6: netip.MustParseAddr("2a01:4f8::1"), UserHash: userHash, CryptOptions: 3},
			{ClientID: 5, Port: 6},
		}},
		SecureIdentState{State: SecureIdentNeedsKeyAndSignature, Challenge: 0xDEADBEEF},
		PublicKey{Key: []byte{1, 2, 3}},
		Signature{Signature: []byte{4, 5}},
		Signature{Signature: []byte{4, 5}, IPKind: IPKindRemoteClient},
		MultiPacket{Hash: fileHash, Requests: []wire.Packet{
			FileRequest{Hash: fileHash, HasParts: true, Parts: parts(true), HasCompleteSources: true, CompleteSources: 3},
			SetRequestFileID{Hash: fileHash},
			RequestSources2{Version: SourceExchange2Version, Hash: fileHash},
			RequestSources{Hash: fileHash},
			AICHFileHashRequest{Hash: fileHash},
			wire.Unknown{Proto: wire.ProtocolEMule, Op: 0xFE, Body: []byte{7, 7}},
		}},
		MultiPacketExt{Hash: fileHash, Size: 1 << 33, Requests: []wire.Packet{SetRequestFileID{Hash: fileHash}}},
		MultiPacketAnswer{Hash: fileHash, Answers: []wire.Packet{
			FileNameAnswer{Hash: fileHash, Name: "kelpie.iso"},
			FileStatus{Hash: fileHash, Parts: parts(false, true)},
			AICHFileHashAnswer{Hash: fileHash, Root: aichRoot},
		}},
		AICHFileHashRequest{Hash: fileHash},
		AICHFileHashAnswer{Hash: fileHash, Root: aichRoot},
		AICHRequest{Hash: fileHash, Part: 3, Root: aichRoot},
		AICHAnswer{Hash: fileHash},
		AICHAnswer{Hash: fileHash, HasData: true, Part: 3, Root: aichRoot, Entries: []AICHEntry{{Ident: 2, Hash: aichRoot}, {Ident: 0xFFFF, Hash: aichRoot}}},
		AICHAnswer{Hash: fileHash, HasData: true, Part: 700, Root: aichRoot, HasLongIdents: true, Entries: []AICHEntry{{Ident: 0x10000, Hash: aichRoot}}},
		IPv6Changed{Addr: netip.MustParseAddr("2a01:4f8::1")},
	}
	for _, p := range packets {
		roundTrip(t, p, Parse)
	}
}

func TestUDPRoundTrip(t *testing.T) {
	packets := []wire.Packet{
		ReaskFilePing{Hash: fileHash},
		ReaskFilePing{Hash: fileHash, HasCompleteSources: true, CompleteSources: 4},
		ReaskFilePing{Hash: fileHash, HasParts: true, Parts: parts(), HasCompleteSources: true, CompleteSources: 4},
		ReaskFilePing{Hash: fileHash, HasParts: true, Parts: parts(true, false), HasCompleteSources: true, CompleteSources: 4},
		ReaskAck{Rank: 12},
		ReaskAck{HasParts: true, Parts: parts(), Rank: 12},
		FileNotFound{},
		QueueFull{},
	}
	for _, p := range packets {
		raw := wire.BuildPacketDatagram(nil, p)
		frame, err := wire.ParseDatagram(raw)
		if err != nil {
			t.Fatal(err)
		}
		got, err := ParseUDP(frame.Protocol, frame.Opcode, frame.Body)
		if err != nil {
			t.Fatalf("%T: %v", p, err)
		}
		if !reflect.DeepEqual(got, p) {
			t.Fatalf("%T round trip\n got  %+v\n want %+v", p, got, p)
		}
	}
}

func TestUnknownOpcodesSurvive(t *testing.T) {
	for _, c := range []struct {
		protocol, opcode byte
		parse            func(byte, byte, []byte) (wire.Packet, error)
	}{
		{wire.ProtocolEDonkey, 0x4E, Parse},
		{wire.ProtocolEMule, 0x61, Parse},
		{wire.ProtocolKad, 0x01, Parse},
		{wire.ProtocolEMule, 0x95, ParseUDP},
	} {
		got, err := c.parse(c.protocol, c.opcode, []byte{1, 2})
		want := wire.Unknown{Proto: c.protocol, Op: c.opcode, Body: []byte{1, 2}}
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("%#x/%#x = %+v, %v", c.protocol, c.opcode, got, err)
		}
	}
}

func TestHelloGolden(t *testing.T) {
	hello := Hello{UserHash: userHash, ClientID: 0x04030201, Port: 4662, ModMisc: ModMiscExtendedSources | ModMiscIPv6}
	want := unhex(t, "10"+"23a8ceff57a7a32d562d649ed7893796"+"01020304"+"3612"+
		"01000000"+"030100aa05000000"+"000000000000")
	if got := hello.Build(nil); !bytes.Equal(got, want) {
		t.Fatalf("hello =\n %x\nwant\n %x", got, want)
	}
}

func TestHelloIgnoresTrailingBytes(t *testing.T) {
	body := append(HelloAnswer{UserHash: userHash}.Build(nil), 'K', 'D', 'L', 'M')
	got, err := Parse(wire.ProtocolEDonkey, opHelloAnswer, body)
	if err != nil || got.(HelloAnswer).UserHash != userHash {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestMiscOptionsBits(t *testing.T) {
	m1 := MiscOptions1{AICHVersion: 1, IsUnicode: true, UDPVersion: 4, DataCompressionVersion: 1, SecureIdentVersion: 3, SourceExchange1Version: 3, ExtendedRequestsVersion: 2, AcceptCommentVersion: 1, IsSharedFilesHidden: true, HasMultiPacket: true, HasPreview: true}
	if v := m1.ToUint32(); v != 0x34133217 {
		t.Fatalf("misc1 = %#x", v)
	}
	if ParseMiscOptions1(0x34133217) != m1 {
		t.Fatal("misc1 parse")
	}
	m2 := MiscOptions2{KadVersion: 9, HasLargeFiles: true, HasExtMultiPacket: true, HasSourceExchange2: true, HasCaptcha: true}
	if v := m2.ToUint32(); v != 0x0C39 {
		t.Fatalf("misc2 = %#x", v)
	}
	if ParseMiscOptions2(0x0C39) != m2 {
		t.Fatal("misc2 parse")
	}
}

// emule-qt ipv6-spec §3.3.3 worked example.
func TestExtendedSourceGolden(t *testing.T) {
	record := unhex(t, "0a000001 3612 03 83ba01020304 88bb3512 81ae2a0104f8000000000000000000000001")
	answer := AnswerSources2{Version: ExtendedSourcesVersion, Hash: fileHash, Sources: []Source{{
		ClientID: 0x0100000A,
		Port:     4662,
		Server:   netip.MustParseAddrPort("1.2.3.4:4661"),
		IPv6:     netip.MustParseAddr("2a01:4f8::1"),
	}}}
	want := append(append([]byte{1}, fileHash[:]...), 1, 0)
	want = append(want, record...)
	if got := answer.Build(nil); !bytes.Equal(got, want) {
		t.Fatalf("answer =\n %x\nwant\n %x", got, want)
	}
	got, err := Parse(wire.ProtocolEMule, opAnswerSources2, want)
	if err != nil || !reflect.DeepEqual(got, answer) {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestExtendedSourceSkipsUnknownTags(t *testing.T) {
	body := append(append([]byte{1}, fileHash[:]...), 1, 0)
	body = append(body, unhex(t, "01000000 0200 02 89f007 09020062 6905")...)
	got, err := Parse(wire.ProtocolEMule, opAnswerSources2, body)
	if err != nil {
		t.Fatal(err)
	}
	if s := got.(AnswerSources2).Sources; len(s) != 1 || s[0].ClientID != 1 || s[0].Port != 2 {
		t.Fatalf("sources = %+v", s)
	}
}

// Ported from goed2k protocol/client/source_exchange_test.go.
func TestAnswerSourcesRejectsWrongEntrySize(t *testing.T) {
	body := append(append([]byte(nil), fileHash[:]...), 1, 0)
	body = append(body, make([]byte, 27)...)
	if _, err := Parse(wire.ProtocolEMule, opAnswerSources, body); err == nil {
		t.Fatal("want error")
	}
}

func TestAnswerSources2RejectsWrongEntrySize(t *testing.T) {
	body := append([]byte{4}, fileHash[:]...)
	body = append(body, 1, 0)
	body = append(body, make([]byte, 28)...)
	if _, err := Parse(wire.ProtocolEMule, opAnswerSources2, body); err == nil {
		t.Fatal("want error")
	}
}

func TestSendingPartRejectsLengthMismatch(t *testing.T) {
	body := SendingPart{Hash: fileHash, Start: 0, End: 10, Data: []byte{1}}.Build(nil)
	if _, err := Parse(wire.ProtocolEDonkey, opSendingPart, body); err == nil {
		t.Fatal("want error")
	}
}

func TestQueueRankingGolden(t *testing.T) {
	raw := wire.BuildPacket(nil, QueueRanking{Rank: 0x0102})
	if !bytes.Equal(raw, unhex(t, "c50d000000 60 0201 00000000000000000000")) {
		t.Fatalf("queue ranking = %x", raw)
	}
}

func TestShortBodiesFail(t *testing.T) {
	for _, op := range []byte{opHello, opFileStatus, opRequestParts, opQueueRank, opHashSetAnswer} {
		if _, err := Parse(wire.ProtocolEDonkey, op, []byte{1}); err == nil {
			t.Errorf("opcode %#x: want error", op)
		}
	}
}

// TestAICHAnswerGolden follows aMule's layout: a 16-bit list closed by an
// empty 32-bit count, or an empty 16-bit count before the 32-bit list.
func TestAICHAnswerGolden(t *testing.T) {
	root := hex.EncodeToString(aichRoot[:])
	short := AICHAnswer{Hash: fileHash, HasData: true, Part: 1, Root: aichRoot, Entries: []AICHEntry{{Ident: 6, Hash: aichRoot}}}
	want := unhex(t, "31d6cfe0d16ae931b73c59d7e0c089c0"+"0100"+root+"0100"+"0600"+root+"0000")
	if got := short.Build(nil); !bytes.Equal(got, want) {
		t.Fatalf("16-bit answer =\n %x\nwant\n %x", got, want)
	}
	long := short
	long.HasLongIdents = true
	want = unhex(t, "31d6cfe0d16ae931b73c59d7e0c089c0"+"0100"+root+"0000"+"0100"+"06000000"+root)
	if got := long.Build(nil); !bytes.Equal(got, want) {
		t.Fatalf("32-bit answer =\n %x\nwant\n %x", got, want)
	}
}

func TestAICHAnswerRejectsShortList(t *testing.T) {
	body := AICHAnswer{Hash: fileHash, HasData: true, Root: aichRoot, Entries: []AICHEntry{{Ident: 2}}}.Build(nil)
	body = body[:len(body)-4]
	if _, err := Parse(wire.ProtocolEMule, opAICHAnswer, body); err == nil {
		t.Fatal("want error for a truncated hash list")
	}
}

func TestMultiPacketKeepsOnePerOpcode(t *testing.T) {
	body := bytes.Clone(fileHash[:])
	body = append(body, bytes.Repeat([]byte{opSetRequestFileID}, 100_000)...)
	body = append(body, opAICHFileHashRequest, opSetRequestFileID, opAICHFileHashRequest)
	p, err := Parse(wire.ProtocolEMule, opMultiPacket, body)
	if err != nil {
		t.Fatal(err)
	}
	want := MultiPacket{Hash: fileHash, Requests: []wire.Packet{SetRequestFileID{Hash: fileHash}, AICHFileHashRequest{Hash: fileHash}}}
	if !reflect.DeepEqual(p, want) {
		t.Fatalf("got %+v, want %+v", p, want)
	}

	answer := bytes.Clone(fileHash[:])
	for range 50_000 {
		answer = append(answer, opFileStatus, 0, 0)
	}
	p, err = Parse(wire.ProtocolEMule, opMultiPacketAnswer, answer)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(p.(MultiPacketAnswer).Answers); got != 1 {
		t.Fatalf("answers = %d, want 1", got)
	}
}
