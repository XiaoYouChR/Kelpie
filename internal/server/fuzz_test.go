package server

import (
	"encoding/binary"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/wire"
	serverwire "github.com/XiaoYouChR/Kelpie/internal/wire/server"
)

func FuzzParseMet(f *testing.F) {
	data, err := os.ReadFile("testdata/server.met")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(data)
	f.Add(buildMet(
		buildMetEntry("1.2.3.4:4661",
			wire.Tag{Type: wire.TagString, ID: 0x01, String: "one"},
			wire.Tag{Type: wire.TagUint32, ID: 0x0E, Uint: uint64(PreferenceHigh)},
			wire.Tag{Type: wire.TagUint16, ID: 0x97, Uint: 4665},
			wire.Tag{Type: wire.TagUint32, Name: "users", Uint: 5000},
		),
		buildMetEntry("0.0.0.0:4661", wire.Tag{Type: wire.TagString, ID: 0x85, String: "dyn.example"}),
	))
	f.Fuzz(func(t *testing.T, data []byte) {
		ParseMet(data)
	})
}

// buildServerScript frames packets for FuzzOnPacket: one byte choosing the
// sender (even: the connected server over TCP, odd: a listed server over
// UDP), a uint16 length, protocol, opcode and body.
func buildServerScript(packets ...wire.Packet) []byte {
	var b []byte
	for _, p := range packets {
		via := byte(0)
		if p.Protocol() == wire.ProtocolEDonkey && p.Opcode() >= 0x90 {
			via = 1
		}
		body := p.Build(nil)
		b = append(b, via)
		b = binary.LittleEndian.AppendUint16(b, uint16(len(body)+2))
		b = append(b, p.Protocol(), p.Opcode())
		b = append(b, body...)
	}
	return b
}

// FuzzOnPacket feeds the server state machine what a hostile server might
// send, over TCP to the connected server and over UDP from listed ones,
// ticking between packets.
func FuzzOnPacket(f *testing.F) {
	v6 := netip.MustParseAddr("2a01:4f8::1")
	f.Add(buildServerScript(
		serverwire.IDChange{ClientID: highID, Flags: serverwire.FlagCompression | serverwire.FlagTCPObfuscation | serverwire.FlagIPv6, ObfuscationPort: 4665},
		serverwire.ServerStatus{Users: 10, Files: 20},
		serverwire.ServerMessage{Text: "welcome"},
		serverwire.ServerIdent{Hash: fileHash(9), Addr: first, Name: "s", Description: "d", Tags: []wire.Tag{{Type: wire.TagUint32, ID: 0x87, Uint: 9}}},
		serverwire.ServerList{Servers: []netip.AddrPort{ep("1.0.0.3:4661"), netip.AddrPortFrom(v6, 4661)}},
		serverwire.FoundSources{Hash: fileHash(0), Sources: []serverwire.Source{{ClientID: highID, Port: 4662}, {ClientID: 5, Port: 6}, {ClientID: wire.IPv6Sentinel, Port: 7, IPv6: v6}}},
		serverwire.FoundSourcesObfu{Hash: fileHash(1), Sources: []serverwire.Source{{ClientID: highID, Port: 4662, CryptOptions: wire.CryptHasUserHash | 0x03, UserHash: userHash}}},
		serverwire.CallbackRequested{Addr: ep("5.6.7.8:4662"), CryptOptions: 0x83, UserHash: userHash},
		serverwire.CallbackRequestedIPv6{Addr: netip.AddrPortFrom(v6, 4662)},
		serverwire.CallbackFailed{},
		serverwire.GlobServStatRes{Challenge: 1, Users: 1, UDPFlags: serverwire.UDPFlagGetSources2 | serverwire.UDPFlagLargeFiles},
		serverwire.GlobFoundSources{Files: []serverwire.FoundSources{{Hash: fileHash(0), Sources: []serverwire.Source{{ClientID: highID, Port: 2}}}}},
	))
	entries := []Entry{{Endpoint: first, Users: 100}, {Endpoint: ep("1.0.0.2:4661"), UDPFlags: serverwire.UDPFlagGetSources2}}
	wanted := append(downloads(3), Wanted{File: fileHash(7), Size: 5 << 30, Name: "large", IsComplete: true, IsShared: true})
	f.Fuzz(func(t *testing.T, script []byte) {
		s := BuildServer(config, entries)
		now := start
		s.OnTick(now, wanted)
		s.OnConnected(first, now)
		for len(script) >= 3 {
			via := script[0]
			size := min(int(binary.LittleEndian.Uint16(script[1:3])), len(script)-3)
			raw := script[3 : 3+size]
			script = script[3+size:]
			if len(raw) < 2 {
				continue
			}
			if via%2 == 0 {
				if p, err := serverwire.Parse(raw[0], raw[1], raw[2:]); err == nil {
					s.OnPacket(first, p, now)
				}
			} else if p, err := serverwire.ParseUDP(raw[0], raw[1], raw[2:]); err == nil {
				s.OnUDPPacket(netip.AddrPortFrom(entries[int(via/2)%len(entries)].Endpoint.Addr(), 4665), p, now)
			}
			now = now.Add(time.Duration(via) * time.Second)
			s.OnTick(now, wanted)
		}
	})
}
