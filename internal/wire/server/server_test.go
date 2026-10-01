package server

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
	v6       = netip.MustParseAddr("2a01:4f8::1")
)

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

func samplePackets() []wire.Packet {
	return []wire.Packet{
		Login{UserHash: userHash, Port: 4662, Name: "Kelpie", Version: 0x3C, Flags: CapZlib | CapNewTags | CapUnicode | CapLargeFiles | CapIPv6, EmuleVersion: 0x2000, IPv6: v6, Tags: []wire.Tag{{Type: wire.TagUint32, ID: 0x0F, Uint: 4662}}},
		IDChange{ClientID: 0x04030201, Flags: FlagCompression | FlagRelatedSearch | FlagIPv6, Reserved: 4661, ReportedIP: netip.MustParseAddr("1.2.3.4")},
		IDChange{ClientID: 0x04030201, Flags: FlagTCPObfuscation, ReportedIP: netip.MustParseAddr("1.2.3.4"), ObfuscationPort: 4665},
		ServerMessage{Text: "server version 17.15\nwelcome"},
		ServerStatus{Users: 1000, Files: 200000},
		ServerIdent{Hash: fileHash, Addr: netip.MustParseAddrPort("1.2.3.4:4661"), Name: "eMule Security", Description: "desc", YourIP: v6, IPv6Status: IPv6StatusHave | IPv6StatusReachable | IPv6StatusProbed, IPv6: netip.MustParseAddr("2a01:4f8::2"), Tags: []wire.Tag{{Type: wire.TagUint32, ID: 0x87, Uint: 9}}},
		GetServerList{},
		ServerList{Servers: []netip.AddrPort{netip.MustParseAddrPort("1.2.3.4:4661"), netip.MustParseAddrPort("[2a01:4f8::1]:4661")}},
		ServerList{Servers: []netip.AddrPort{netip.MustParseAddrPort("1.2.3.4:4661")}},
		GetSources{Hash: fileHash, Size: 9728000},
		GetSources{Hash: fileHash, Size: 5 << 30},
		FoundSources{Hash: fileHash, Sources: []Source{{ClientID: 0x04030201, Port: 4662}, {ClientID: wire.IPv6Sentinel, Port: 4663, IPv6: v6}, {ClientID: 5, Port: 6}}},
		FoundSourcesObfu{Hash: fileHash, Sources: []Source{{ClientID: 1, Port: 2, CryptOptions: 0x01}, {ClientID: wire.IPv6Sentinel, Port: 3, CryptOptions: wire.CryptHasUserHash | 0x03, UserHash: userHash, IPv6: v6}}},
		CallbackRequest{ClientID: 12345},
		CallbackRequested{Addr: netip.MustParseAddrPort("1.2.3.4:4662")},
		CallbackRequested{Addr: netip.MustParseAddrPort("1.2.3.4:4662"), CryptOptions: 0x83, UserHash: userHash},
		CallbackRequestedIPv6{Addr: netip.MustParseAddrPort("[2a01:4f8::1]:4662")},
		CallbackFailed{},
		OfferFiles{Files: []OfferedFile{
			{Hash: fileHash, ClientID: CompleteID, Port: CompletePort, Tags: []wire.Tag{{Type: wire.TagString, ID: FileName, String: "kelpie.iso"}, {Type: wire.TagUint32, ID: FileSize, Uint: 9728000}}},
			{Hash: userHash, ClientID: IncompleteID, Port: IncompletePort, Tags: []wire.Tag{{Type: wire.TagUint32, ID: FileSize, Uint: 1}, {Type: wire.TagUint32, ID: FileSizeHi, Uint: 1}}},
		}},
	}
}

func TestTCPRoundTrip(t *testing.T) {
	for _, p := range samplePackets() {
		frame, _, err := wire.ParseFrame(wire.BuildPacket(nil, p))
		if err != nil {
			t.Fatal(err)
		}
		got, err := Parse(frame.Protocol, frame.Opcode, frame.Body)
		if err != nil {
			t.Fatalf("%T: %v", p, err)
		}
		if !reflect.DeepEqual(got, p) {
			t.Fatalf("%T round trip\n got  %+v\n want %+v", p, got, p)
		}
	}
}

func sampleUDPPackets() []wire.Packet {
	return []wire.Packet{
		GlobGetSources2{Files: []GetSources{{Hash: fileHash, Size: 100}, {Hash: userHash, Size: 5 << 30}}},
		GlobGetSources{Files: []wire.Hash{fileHash, userHash}},
		GlobFoundSources{Files: []FoundSources{{Hash: fileHash, Sources: []Source{{ClientID: 1, Port: 2}}}}},
		GlobFoundSources{Files: []FoundSources{
			{Hash: fileHash, Sources: []Source{{ClientID: 1, Port: 2}, {ClientID: 3, Port: 4}}},
			{Hash: userHash, Sources: []Source{{ClientID: wire.IPv6Sentinel, Port: 4, IPv6: v6}}},
		}},
		GlobServStatReq{Challenge: 0x55AA1234},
		GlobServStatRes{Challenge: 0x55AA1234, Users: 1, Files: 2, MaxUsers: 3, SoftFiles: 4, HardFiles: 5, UDPFlags: UDPFlagGetSources2 | UDPFlagLargeFiles, LowIDUsers: 6, UDPObfuscationPort: 7, TCPObfuscationPort: 8, UDPKey: 9},
	}
}

func TestUDPRoundTrip(t *testing.T) {
	for _, p := range sampleUDPPackets() {
		frame, err := wire.ParseDatagram(wire.BuildPacketDatagram(nil, p))
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

// ipv6-spec §4.4: the IPv6 bytes come last, after the obfuscation fields.
func TestFoundSourcesSentinelGolden(t *testing.T) {
	f := FoundSourcesObfu{Hash: fileHash, Sources: []Source{
		{ClientID: wire.IPv6Sentinel, Port: 4662, CryptOptions: 0x81, UserHash: userHash, IPv6: v6},
		{ClientID: 0x04030201, Port: 4662, CryptOptions: 0},
	}}
	want := unhex(t, "31d6cfe0d16ae931b73c59d7e0c089c0 02"+
		"ffffffff 3612 81 23a8ceff57a7a32d562d649ed7893796 2a0104f8000000000000000000000001"+
		"01020304 3612 00")
	if got := f.Build(nil); !bytes.Equal(got, want) {
		t.Fatalf("sources =\n %x\nwant\n %x", got, want)
	}
}

func TestFoundSourcesTruncatedSentinelFails(t *testing.T) {
	body := unhex(t, "31d6cfe0d16ae931b73c59d7e0c089c0 01 ffffffff 3612 2a0104f8")
	if _, err := Parse(wire.ProtocolEDonkey, opFoundSources, body); err == nil {
		t.Fatal("want error")
	}
}

func TestGetSourcesGolden(t *testing.T) {
	small := GetSources{Hash: fileHash, Size: 0x01020304}.Build(nil)
	if !bytes.Equal(small[16:], unhex(t, "04030201")) {
		t.Fatalf("small = %x", small[16:])
	}
	large := GetSources{Hash: fileHash, Size: 0x0102030405}.Build(nil)
	if !bytes.Equal(large[16:], unhex(t, "00000000 0504030201000000")) {
		t.Fatalf("large = %x", large[16:])
	}
}

func TestLoginGolden(t *testing.T) {
	got := Login{UserHash: userHash, ClientID: 0, Port: 4662, Flags: CapIPv6, IPv6: v6}.Build(nil)
	want := unhex(t, "23a8ceff57a7a32d562d649ed7893796 00000000 3612 02000000"+
		"03010020 00100000"+
		"010100ae 2a0104f8000000000000000000000001")
	if !bytes.Equal(got, want) {
		t.Fatalf("login =\n %x\nwant\n %x", got, want)
	}
}

func TestServerListWithoutIPv6BlockHasNoTrailingByte(t *testing.T) {
	got := ServerList{Servers: []netip.AddrPort{netip.MustParseAddrPort("1.2.3.4:4661")}}.Build(nil)
	if !bytes.Equal(got, unhex(t, "01 01020304 3512")) {
		t.Fatalf("list = %x", got)
	}
}

func TestShortStatusDecodesOldServers(t *testing.T) {
	body := unhex(t, "01000000 02000000 03000000 04000000")
	got, err := ParseUDP(wire.ProtocolEDonkey, opGlobServStatRes, body)
	if err != nil || got != (GlobServStatRes{Challenge: 1, Users: 2, Files: 3, MaxUsers: 4}) {
		t.Fatalf("got %+v, %v", got, err)
	}
	idc, err := Parse(wire.ProtocolEDonkey, opIDChange, unhex(t, "05000000"))
	if err != nil || idc != (IDChange{ClientID: 5}) {
		t.Fatalf("got %+v, %v", idc, err)
	}
}

func TestPackedServerFrameParses(t *testing.T) {
	body := ServerStatus{Users: 1, Files: 2}.Build(nil)
	frame, _, err := wire.ParseFrame(wire.BuildPackedFrame(nil, opServerStatus, body))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(frame.Protocol, frame.Opcode, frame.Body)
	if err != nil || got != (ServerStatus{Users: 1, Files: 2}) {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestUnknownOpcodesSurvive(t *testing.T) {
	got, err := Parse(wire.ProtocolEDonkey, 0x33, []byte{1})
	if err != nil || !reflect.DeepEqual(got, wire.Unknown{Proto: wire.ProtocolEDonkey, Op: 0x33, Body: []byte{1}}) {
		t.Fatalf("got %+v, %v", got, err)
	}
	got, err = ParseUDP(wire.ProtocolEDonkey, 0x99, []byte{2})
	if err != nil || !reflect.DeepEqual(got, wire.Unknown{Proto: wire.ProtocolEDonkey, Op: 0x99, Body: []byte{2}}) {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestObfuscatedPingIsBare(t *testing.T) {
	got := wire.BuildPacketDatagram(nil, ObfuscatedPing{Challenge: 0x04030201, Padding: []byte{9, 9}})
	if want := []byte{1, 2, 3, 4, 9, 9}; !bytes.Equal(got, want) {
		t.Fatalf("got %x, want %x", got, want)
	}
}
