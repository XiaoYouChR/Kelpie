package kad

import (
	"encoding/binary"
	"net/netip"

	"github.com/XiaoYouChR/Kelpie/internal/wire"
	kadwire "github.com/XiaoYouChR/Kelpie/internal/wire/kad"
)

// Search asks Kad to find sources for a file.
type Search struct {
	Hash wire.Hash
	Size int64
}

// Publish asks Kad to announce us as a source of a file.
type Publish struct {
	Hash wire.Hash
	Size int64
}

// Wanted is the whole set of files the engine wants searched and
// published. Each SetWanted replaces the previous set, so a dropped update
// is repaired by the next one (ADR-0005).
type Wanted struct {
	Find    []Search
	Publish []Publish
}

// Source types, as eMule's CSearch::StorePacket publishes them.
const (
	SourceOpen            byte = 1 // HighID
	SourceFirewalled      byte = 3 // reachable only through its buddy
	SourceOpenLarge       byte = 4 // HighID, file over 4 GB
	SourceFirewalledLarge byte = 5 // firewalled, file over 4 GB
)

// Source is one peer that has a file, as Kad reported it. For firewalled
// types the engine cannot connect to Addr; it asks Kad to RequestCallback
// through Buddy, and the source connects to us.
type Source struct {
	Type     byte
	UserHash wire.Hash
	// Addr is the TCP endpoint; for firewalled sources it is the address
	// the storing node saw, which is not reachable.
	Addr         netip.AddrPort
	UDPPort      uint16
	Buddy        netip.AddrPort
	BuddyID      wire.Hash
	CryptOptions byte
}

// CanObfuscate reads the "supports" bit of TAG_ENCRYPTION.
func (s Source) CanObfuscate() bool { return s.CryptOptions&0x01 != 0 }

func (s Source) IsFirewalled() bool {
	return s.Type == SourceFirewalled || s.Type == SourceFirewalledLarge
}

type SourcesFound struct {
	Hash    wire.Hash
	Sources []Source
}

type Status struct {
	Nodes        int
	IsFirewalled bool
}

// Callback asks a firewalled source's buddy to have the source connect to
// us for Hash.
type Callback struct {
	Buddy   netip.AddrPort
	BuddyID wire.Hash
	Hash    wire.Hash
}

// toSource reads a search result the way eMule's CSearch::ProcessResultFile
// and CDownloadQueue::KademliaSearchFile do. Type 6 (direct UDP callback)
// and type 2 are not used; firewalled sources are useless while we are
// firewalled ourselves.
func toSource(e kadwire.Entry, isFirewalled bool) (Source, bool) {
	s := Source{UserHash: e.ID}
	var ip netip.Addr
	var tcpPort, buddyPort uint16
	for _, t := range e.Tags {
		if t.Name != "" {
			continue
		}
		switch t.ID {
		case kadwire.TagSourceType:
			s.Type = byte(t.Uint)
		case kadwire.TagSourceIP:
			if t.Uint != 0 {
				ip = kadwire.ToAddr(uint32(t.Uint))
			}
		case kadwire.TagSourcePort:
			tcpPort = uint16(t.Uint)
		case kadwire.TagSourceUPort:
			s.UDPPort = uint16(t.Uint)
		case kadwire.TagServerIP:
			// The buddy's IP is the client's eD2k IP, not a Kad integer:
			// eMule stores CUpDownClient::GetIP() and sends to it unchanged.
			if t.Uint != 0 {
				s.Buddy = netip.AddrPortFrom(wire.ToAddr(uint32(t.Uint)), s.Buddy.Port())
			}
		case kadwire.TagServerPort:
			buddyPort = uint16(t.Uint)
		case kadwire.TagBuddyHash:
			id, ok := parseBuddyID(t)
			if !ok {
				return Source{}, false
			}
			s.BuddyID = id
		case kadwire.TagEncryption:
			s.CryptOptions = byte(t.Uint)
		}
	}
	if ip.IsValid() {
		s.Addr = netip.AddrPortFrom(ip, tcpPort)
	}
	switch s.Type {
	case SourceOpen, SourceOpenLarge:
		return s, ip.IsValid() && tcpPort != 0
	case SourceFirewalled, SourceFirewalledLarge:
		if isFirewalled || !s.Buddy.Addr().IsValid() || buddyPort == 0 || s.BuddyID == (wire.Hash{}) {
			return Source{}, false
		}
		s.Buddy = netip.AddrPortFrom(s.Buddy.Addr(), buddyPort)
		if !ip.IsValid() {
			s.Addr = netip.AddrPortFrom(netip.Addr{}, tcpPort)
		}
		return s, true
	}
	return Source{}, false
}

// eMule writes TAG_BUDDYHASH as the hex of the buddy ID's in-memory words,
// which is its Kad wire form; BuddyID holds the hash form like every other
// ID here, so buildCallback can encode it back.
func parseBuddyID(t wire.Tag) (wire.Hash, bool) {
	raw, err := wire.ParseHash(t.String)
	if t.Type != wire.TagString || err != nil {
		return wire.Hash{}, false
	}
	return parseID(&wire.Reader{Rest: raw[:]}), true
}

// opCallbackReq is KADEMLIA_CALLBACK_REQ and opFirewalledAck
// KADEMLIA_FIREWALLED_ACK_RES; wire/kad does not decode either.
const (
	opCallbackReq   byte = 0x52
	opFirewalledAck byte = 0x59
)

// callbackReq is what CUpDownClient::TryToConnect sends a firewalled
// source's buddy: buddy ID, file hash, our TCP port. The buddy forwards it
// as OP_CALLBACK over its TCP link to the source.
type callbackReq struct {
	BuddyID wire.Hash
	Hash    wire.Hash
	TCPPort uint16
}

func (callbackReq) Protocol() byte { return wire.ProtocolKad }
func (callbackReq) Opcode() byte   { return opCallbackReq }
func (p callbackReq) Build(b []byte) []byte {
	return binary.LittleEndian.AppendUint16(buildID(buildID(b, p.BuddyID), p.Hash), p.TCPPort)
}

// firewalledAck is KADEMLIA_FIREWALLED_ACK_RES, sent to a node older than
// Kad version 7 whose TCP port we reached (ClientList.cpp:600).
type firewalledAck struct{}

func (firewalledAck) Protocol() byte        { return wire.ProtocolKad }
func (firewalledAck) Opcode() byte          { return opFirewalledAck }
func (firewalledAck) Build(b []byte) []byte { return b }
