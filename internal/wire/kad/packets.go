// Derived from goed2k protocol/kad/types.go, packets.go and packet_combiner.go.

// Package kad encodes and decodes Kademlia 2 UDP packets. Kad is IPv4 only.
package kad

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/XiaoYouChR/Kelpie/internal/wire"
)

const (
	opBootstrapReq        byte = 0x01
	opBootstrapRes        byte = 0x09
	opHelloReq            byte = 0x11
	opHelloRes            byte = 0x19
	opReq                 byte = 0x21
	opRes                 byte = 0x29
	opSearchKeysReq       byte = 0x33
	opSearchSourcesReq    byte = 0x34
	opSearchNotesReq      byte = 0x35
	opSearchRes           byte = 0x3B
	opPublishKeysReq      byte = 0x43
	opPublishSourcesReq   byte = 0x44
	opPublishNotesRes     byte = 0x4A
	opPublishRes          byte = 0x4B
	opLegacyFirewalledReq byte = 0x50
	opFirewalledReq       byte = 0x53
	opFirewalledRes       byte = 0x58
	opPing                byte = 0x60
	opPong                byte = 0x61
	opFirewalledUDP       byte = 0x62
)

const Version byte = 0x05

// Req.SearchType values: how many contacts the asker wants back.
const (
	FindValue byte = 0x02
	Store     byte = 0x04
	FindNode  byte = 0x0B
)

// Source tag IDs carried in SearchEntry.Tags.
const (
	TagFileSize    byte = 0x02
	TagEncryption  byte = 0xF3
	TagBuddyHash   byte = 0xF8
	TagServerPort  byte = 0xFA
	TagServerIP    byte = 0xFB
	TagSourceUPort byte = 0xFC
	TagSourcePort  byte = 0xFD
	TagSourceIP    byte = 0xFE
	TagSourceType  byte = 0xFF
)

// Parse decodes a Kad packet body; wire.ParseDatagram has already inflated
// packed (0xE5) packets to 0xE4. Opcodes not listed here, including the
// buddy and notes packets Kelpie does not use yet, come back as
// wire.Unknown.
func Parse(protocol, opcode byte, body []byte) (wire.Packet, error) {
	if protocol != wire.ProtocolKad {
		return wire.Unknown{Proto: protocol, Op: opcode, Body: body}, nil
	}
	r := &wire.Reader{Rest: body}
	var p wire.Packet
	switch opcode {
	case opBootstrapReq:
		p = BootstrapReq{}
	case opBootstrapRes:
		p = BootstrapRes{ID: parseID(r), TCPPort: r.Uint16(), Version: r.Uint8(), Contacts: parseContacts(r, int(r.Uint16()))}
	case opHelloReq:
		p = HelloReq(parseHello(r))
	case opHelloRes:
		p = HelloRes(parseHello(r))
	case opReq:
		p = Req{SearchType: r.Uint8(), Target: parseID(r), Receiver: parseID(r)}
	case opRes:
		p = Res{Target: parseID(r), Contacts: parseContacts(r, int(r.Uint8()))}
	case opSearchKeysReq:
		p = SearchKeysReq{Target: parseID(r), StartPos: r.Uint16()}
	case opSearchSourcesReq:
		p = SearchSourcesReq{Target: parseID(r), StartPos: r.Uint16(), Size: r.Uint64()}
	case opSearchNotesReq:
		p = SearchNotesReq{Target: parseID(r), Size: r.Uint64()}
	case opSearchRes:
		p = SearchRes{Source: parseID(r), Target: parseID(r), Results: parseEntries(r, int(r.Uint16()))}
	case opPublishKeysReq:
		p = PublishKeysReq{KeywordID: parseID(r), Sources: parseEntries(r, int(r.Uint16()))}
	case opPublishSourcesReq:
		p = PublishSourcesReq{FileID: parseID(r), Source: parseEntry(r)}
	case opPublishRes:
		p = PublishRes{FileID: parseID(r), Load: r.Uint8()}
	case opPublishNotesRes:
		p = PublishNotesRes{FileID: parseID(r), Load: r.Uint8()}
	case opLegacyFirewalledReq:
		p = LegacyFirewalledReq{TCPPort: r.Uint16()}
	case opFirewalledReq:
		p = FirewalledReq{TCPPort: r.Uint16(), ID: parseID(r), Options: r.Uint8()}
	case opFirewalledRes:
		p = FirewalledRes{Addr: parseAddr(r)}
	case opPing:
		p = Ping{}
	case opPong:
		p = Pong{UDPPort: r.Uint16()}
	case opFirewalledUDP:
		p = FirewalledUDP{ErrorCode: r.Uint8(), Port: r.Uint16()}
	default:
		return wire.Unknown{Proto: protocol, Op: opcode, Body: body}, nil
	}
	if err := r.Err(); err != nil {
		return nil, fmt.Errorf("kad: %T: %w", p, err)
	}
	return p, nil
}

// Kad writes a 128-bit ID as four little-endian uint32 words, so each group
// of four bytes is reversed against the ID's big-endian byte form.
func parseID(r *wire.Reader) wire.Hash {
	var id wire.Hash
	raw := r.Bytes(16)
	for i := range raw {
		id[i/4*4+3-i%4] = raw[i]
	}
	return id
}

func buildID(b []byte, id wire.Hash) []byte {
	for i := range id {
		b = append(b, id[i/4*4+3-i%4])
	}
	return b
}

// Kad stores IPv4 addresses as host-order integers, written little-endian:
// the reverse of eD2k's a.b.c.d byte order.
func parseAddr(r *wire.Reader) netip.Addr {
	v := r.Uint32()
	if v == 0 {
		return netip.Addr{}
	}
	return ToAddr(v)
}

func buildAddr(b []byte, addr netip.Addr) []byte {
	return binary.LittleEndian.AppendUint32(b, ToUint32(addr))
}

// ToAddr converts a Kad IPv4 integer, as carried in packets and in the
// TagSourceIP tag, to an address. TagServerIP holds a buddy IP in eD2k byte
// order (eMule publishes the buddy's GetIP()); decode it with wire.ToAddr.
func ToAddr(v uint32) netip.Addr {
	var a [4]byte
	binary.BigEndian.PutUint32(a[:], v)
	return netip.AddrFrom4(a)
}

// ToUint32 converts an IPv4 address to Kad's integer form; other addresses
// give 0.
func ToUint32(addr netip.Addr) uint32 {
	if !addr.Is4() {
		return 0
	}
	a := addr.As4()
	return binary.BigEndian.Uint32(a[:])
}

// Contact is one Kad node as packets carry it.
type Contact struct {
	ID      wire.Hash
	Addr    netip.Addr
	UDPPort uint16
	TCPPort uint16
	Version byte
}

func buildContact(b []byte, c Contact) []byte {
	b = buildAddr(buildID(b, c.ID), c.Addr)
	b = binary.LittleEndian.AppendUint16(b, c.UDPPort)
	b = binary.LittleEndian.AppendUint16(b, c.TCPPort)
	return append(b, c.Version)
}

func parseContacts(r *wire.Reader, count int) []Contact {
	if count*25 > r.Len() {
		r.SetErr(wire.ErrShort)
		return nil
	}
	if count == 0 {
		return nil
	}
	out := make([]Contact, count)
	for i := range out {
		out[i] = Contact{ID: parseID(r), Addr: parseAddr(r), UDPPort: r.Uint16(), TCPPort: r.Uint16(), Version: r.Uint8()}
	}
	return out
}

// Entry is an ID with tags: a search result or a published source or
// keyword.
type Entry struct {
	ID   wire.Hash
	Tags []wire.Tag
}

func (e Entry) TagByID(id byte) (wire.Tag, bool) {
	for _, t := range e.Tags {
		if t.Name == "" && t.ID == id {
			return t, true
		}
	}
	return wire.Tag{}, false
}

// SourceAddrPort is the source's IPv4 address and TCP port. Whether the
// source type allows a direct connection is the caller's question.
func (e Entry) SourceAddrPort() (netip.AddrPort, bool) {
	ip, hasIP := e.TagByID(TagSourceIP)
	port, hasPort := e.TagByID(TagSourcePort)
	if !hasIP || !hasPort {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ToAddr(uint32(ip.Uint)), uint16(port.Uint)), true
}

// Kad tags always use the classic form with a uint16 name length; eMule's
// Kad reader rejects the compact eD2k form.
func buildEntry(b []byte, e Entry) []byte {
	b = append(buildID(b, e.ID), byte(len(e.Tags)))
	for _, t := range e.Tags {
		b = wire.BuildTag(b, t)
	}
	return b
}

func parseEntry(r *wire.Reader) Entry {
	e := Entry{ID: parseID(r)}
	e.Tags = parseTags(r, int(r.Uint8()))
	return e
}

func parseEntries(r *wire.Reader, count int) []Entry {
	if count*17 > r.Len() {
		r.SetErr(wire.ErrShort)
		return nil
	}
	var out []Entry
	for range count {
		out = append(out, parseEntry(r))
	}
	return out
}

func parseTags(r *wire.Reader, count int) []wire.Tag {
	var out []wire.Tag
	for range count {
		out = append(out, r.Tag())
	}
	return out
}

type BootstrapReq struct{}

func (BootstrapReq) Protocol() byte        { return wire.ProtocolKad }
func (BootstrapReq) Opcode() byte          { return opBootstrapReq }
func (BootstrapReq) Build(b []byte) []byte { return b }

type BootstrapRes struct {
	ID       wire.Hash
	TCPPort  uint16
	Version  byte
	Contacts []Contact
}

func (BootstrapRes) Protocol() byte { return wire.ProtocolKad }
func (BootstrapRes) Opcode() byte   { return opBootstrapRes }

func (p BootstrapRes) Build(b []byte) []byte {
	b = binary.LittleEndian.AppendUint16(buildID(b, p.ID), p.TCPPort)
	b = binary.LittleEndian.AppendUint16(append(b, p.Version), uint16(len(p.Contacts)))
	for _, c := range p.Contacts {
		b = buildContact(b, c)
	}
	return b
}

// Hello is the body shared by HelloReq and HelloRes.
type Hello struct {
	ID      wire.Hash
	TCPPort uint16
	Version byte
	Tags    []wire.Tag
}

type HelloReq Hello

type HelloRes Hello

func (HelloReq) Protocol() byte          { return wire.ProtocolKad }
func (HelloReq) Opcode() byte            { return opHelloReq }
func (h HelloReq) Build(b []byte) []byte { return buildHello(b, Hello(h)) }
func (HelloRes) Protocol() byte          { return wire.ProtocolKad }
func (HelloRes) Opcode() byte            { return opHelloRes }
func (h HelloRes) Build(b []byte) []byte { return buildHello(b, Hello(h)) }

func buildHello(b []byte, h Hello) []byte {
	b = binary.LittleEndian.AppendUint16(buildID(b, h.ID), h.TCPPort)
	b = append(b, h.Version, byte(len(h.Tags)))
	for _, t := range h.Tags {
		b = wire.BuildTag(b, t)
	}
	return b
}

func parseHello(r *wire.Reader) Hello {
	h := Hello{ID: parseID(r), TCPPort: r.Uint16(), Version: r.Uint8()}
	h.Tags = parseTags(r, int(r.Uint8()))
	return h
}

type Req struct {
	SearchType byte
	Target     wire.Hash
	Receiver   wire.Hash
}

func (Req) Protocol() byte { return wire.ProtocolKad }
func (Req) Opcode() byte   { return opReq }
func (p Req) Build(b []byte) []byte {
	return buildID(buildID(append(b, p.SearchType), p.Target), p.Receiver)
}

type Res struct {
	Target   wire.Hash
	Contacts []Contact
}

func (Res) Protocol() byte { return wire.ProtocolKad }
func (Res) Opcode() byte   { return opRes }
func (p Res) Build(b []byte) []byte {
	b = append(buildID(b, p.Target), byte(len(p.Contacts)))
	for _, c := range p.Contacts {
		b = buildContact(b, c)
	}
	return b
}

// SearchKeysReq is KADEMLIA2_SEARCH_KEY_REQ. Keyword search expressions,
// which follow when StartPos has bit 15 set, are not decoded.
type SearchKeysReq struct {
	Target   wire.Hash
	StartPos uint16
}

func (SearchKeysReq) Protocol() byte { return wire.ProtocolKad }
func (SearchKeysReq) Opcode() byte   { return opSearchKeysReq }
func (p SearchKeysReq) Build(b []byte) []byte {
	return binary.LittleEndian.AppendUint16(buildID(b, p.Target), p.StartPos)
}

type SearchSourcesReq struct {
	Target   wire.Hash
	StartPos uint16
	Size     uint64
}

func (SearchSourcesReq) Protocol() byte { return wire.ProtocolKad }
func (SearchSourcesReq) Opcode() byte   { return opSearchSourcesReq }
func (p SearchSourcesReq) Build(b []byte) []byte {
	b = binary.LittleEndian.AppendUint16(buildID(b, p.Target), p.StartPos)
	return binary.LittleEndian.AppendUint64(b, p.Size)
}

type SearchNotesReq struct {
	Target wire.Hash
	Size   uint64
}

func (SearchNotesReq) Protocol() byte { return wire.ProtocolKad }
func (SearchNotesReq) Opcode() byte   { return opSearchNotesReq }
func (p SearchNotesReq) Build(b []byte) []byte {
	return binary.LittleEndian.AppendUint64(buildID(b, p.Target), p.Size)
}

type SearchRes struct {
	Source  wire.Hash
	Target  wire.Hash
	Results []Entry
}

func (SearchRes) Protocol() byte { return wire.ProtocolKad }
func (SearchRes) Opcode() byte   { return opSearchRes }
func (p SearchRes) Build(b []byte) []byte {
	b = buildID(buildID(b, p.Source), p.Target)
	b = binary.LittleEndian.AppendUint16(b, uint16(len(p.Results)))
	for _, e := range p.Results {
		b = buildEntry(b, e)
	}
	return b
}

type PublishKeysReq struct {
	KeywordID wire.Hash
	Sources   []Entry
}

func (PublishKeysReq) Protocol() byte { return wire.ProtocolKad }
func (PublishKeysReq) Opcode() byte   { return opPublishKeysReq }
func (p PublishKeysReq) Build(b []byte) []byte {
	b = binary.LittleEndian.AppendUint16(buildID(b, p.KeywordID), uint16(len(p.Sources)))
	for _, e := range p.Sources {
		b = buildEntry(b, e)
	}
	return b
}

type PublishSourcesReq struct {
	FileID wire.Hash
	Source Entry
}

func (PublishSourcesReq) Protocol() byte { return wire.ProtocolKad }
func (PublishSourcesReq) Opcode() byte   { return opPublishSourcesReq }
func (p PublishSourcesReq) Build(b []byte) []byte {
	return buildEntry(buildID(b, p.FileID), p.Source)
}

// PublishRes acknowledges a publish; Load is the node's fill level in
// percent.
type PublishRes struct {
	FileID wire.Hash
	Load   byte
}

func (PublishRes) Protocol() byte          { return wire.ProtocolKad }
func (PublishRes) Opcode() byte            { return opPublishRes }
func (p PublishRes) Build(b []byte) []byte { return append(buildID(b, p.FileID), p.Load) }

type PublishNotesRes PublishRes

func (PublishNotesRes) Protocol() byte          { return wire.ProtocolKad }
func (PublishNotesRes) Opcode() byte            { return opPublishNotesRes }
func (p PublishNotesRes) Build(b []byte) []byte { return append(buildID(b, p.FileID), p.Load) }

// LegacyFirewalledReq is the Kad 1 firewall check, still sent by old nodes.
type LegacyFirewalledReq struct{ TCPPort uint16 }

func (LegacyFirewalledReq) Protocol() byte { return wire.ProtocolKad }
func (LegacyFirewalledReq) Opcode() byte   { return opLegacyFirewalledReq }
func (p LegacyFirewalledReq) Build(b []byte) []byte {
	return binary.LittleEndian.AppendUint16(b, p.TCPPort)
}

// FirewalledReq asks a node to connect back to TCPPort. ID is our user
// hash.
type FirewalledReq struct {
	TCPPort uint16
	ID      wire.Hash
	Options byte
}

func (FirewalledReq) Protocol() byte { return wire.ProtocolKad }
func (FirewalledReq) Opcode() byte   { return opFirewalledReq }
func (p FirewalledReq) Build(b []byte) []byte {
	return append(buildID(binary.LittleEndian.AppendUint16(b, p.TCPPort), p.ID), p.Options)
}

// FirewalledRes tells us the address the node sees us at.
type FirewalledRes struct{ Addr netip.Addr }

func (FirewalledRes) Protocol() byte          { return wire.ProtocolKad }
func (FirewalledRes) Opcode() byte            { return opFirewalledRes }
func (p FirewalledRes) Build(b []byte) []byte { return buildAddr(b, p.Addr) }

// FirewalledUDP is the answer to a UDP firewall test: Port is the UDP port
// it was sent to; a non-zero ErrorCode says the tester knew us already, so
// the result proves nothing.
type FirewalledUDP struct {
	ErrorCode byte
	Port      uint16
}

func (FirewalledUDP) Protocol() byte { return wire.ProtocolKad }
func (FirewalledUDP) Opcode() byte   { return opFirewalledUDP }
func (p FirewalledUDP) Build(b []byte) []byte {
	return binary.LittleEndian.AppendUint16(append(b, p.ErrorCode), p.Port)
}

type Ping struct{}

func (Ping) Protocol() byte        { return wire.ProtocolKad }
func (Ping) Opcode() byte          { return opPing }
func (Ping) Build(b []byte) []byte { return b }

// Pong reports the UDP port the node saw our ping come from.
type Pong struct{ UDPPort uint16 }

func (Pong) Protocol() byte          { return wire.ProtocolKad }
func (Pong) Opcode() byte            { return opPong }
func (p Pong) Build(b []byte) []byte { return binary.LittleEndian.AppendUint16(b, p.UDPPort) }
