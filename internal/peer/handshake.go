package peer

import (
	"bytes"
	"net/netip"
	"strconv"
	"strings"

	"github.com/XiaoYouChR/Kelpie/internal/identity"
	"github.com/XiaoYouChR/Kelpie/internal/wire"
	"github.com/XiaoYouChR/Kelpie/internal/wire/client"
)

const clientName = "Kelpie"

// compatibleClient is Kelpie's id in the top byte of CT_EMULE_VERSION and in
// ET_COMPATIBLECLIENT. eMule and aMule assign 0-6 (SO_EMULE .. SO_HYDRANODE),
// 0x0A, 0x14, 0x28, 0x32-0x36, 0x44, 0x98 and 0xFF; 0x4B ('K') is free.
const compatibleClient = 0x4B

// Versions Kelpie implements, as eMule numbers them.
const (
	udpVersion             = 4 // UDPVERSION: UDP reask with part status
	dataCompressionVersion = 1
	emuleProtocol          = 1 // EMULE_PROTOCOL
)

func (s *Session) buildHello() client.Hello {
	modMisc := client.ModMiscExtendedSources | client.ModMiscExtendedSourcesSkipTags
	if s.cfg.IPv6.IsValid() {
		modMisc |= client.ModMiscIPv6
	}
	return client.Hello{
		UserHash: s.cfg.Self.UserHash,
		ClientID: s.cfg.ClientID,
		Port:     s.cfg.Port,
		Server:   s.cfg.Server,
		Name:     clientName,
		Version:  client.EDonkeyVersion,
		UDPPort:  s.cfg.UDPPort,
		KadPort:  s.cfg.KadPort,
		Misc1: client.MiscOptions1{
			IsUnicode:               true,
			UDPVersion:              udpVersion,
			DataCompressionVersion:  dataCompressionVersion,
			SecureIdentVersion:      identity.Support,
			ExtendedRequestsVersion: client.ExtendedRequestsVersion,
			IsSharedFilesHidden:     true,
			HasMultiPacket:          true,
		},
		Misc2: client.MiscOptions2{
			KadVersion:         s.cfg.KadVersion,
			HasLargeFiles:      true,
			HasExtMultiPacket:  true,
			HasSourceExchange2: true,
			CanCrypt:           true,
			IsCryptRequested:   true,
		},
		EmuleVersion: s.buildEmuleVersion(),
		ModMisc:      modMisc,
		YourIP:       s.remote.Addr(),
		IPv6:         s.cfg.IPv6,
	}
}

// buildEmuleVersion lays out CT_EMULE_VERSION: client id, then major, minor
// and update in 7, 7 and 3 bits.
func (s *Session) buildEmuleVersion() uint32 {
	major, minor, update := toVersion(s.cfg.Version)
	return compatibleClient<<24 | (major&0x7F)<<17 | (minor&0x7F)<<10 | (update&0x07)<<7
}

func toVersion(version string) (major, minor, update uint32) {
	var numbers [3]uint32
	for i, field := range strings.SplitN(version, ".", 3) {
		n, _ := strconv.Atoi(strings.TrimLeft(field, "v"))
		numbers[i] = uint32(n)
	}
	return numbers[0], numbers[1], numbers[2]
}

func (s *Session) onGreeting(p wire.Packet, out *Output) {
	var hello client.Hello
	switch p := p.(type) {
	case client.EmuleInfo:
		// Shareaza and MLDonkey send it before their HelloAnswer.
		s.sendEmuleInfoAnswer(out)
		s.earlyEmuleInfo = &p
		return
	case client.Hello:
		if s.isOutgoing {
			out.Close = CloseProtocol
			return
		}
		hello = p
		out.send(client.HelloAnswer(s.buildHello()))
	case client.HelloAnswer:
		if !s.isOutgoing {
			out.Close = CloseProtocol
			return
		}
		hello = client.Hello(p)
	default:
		out.Close = CloseProtocol
		return
	}
	s.setHello(hello)
	if s.earlyEmuleInfo != nil {
		s.setEmuleInfo(*s.earlyEmuleInfo)
		s.earlyEmuleInfo = nil
	}
	s.isHandshaken = true
	out.add(HandshakeCompleted{UserHash: s.userHash, YourIP: hello.YourIP})
	s.sendIdentState(out)
	s.sendFileRequests(out)
}

func (s *Session) setHello(h client.Hello) {
	s.userHash = h.UserHash
	s.caps = Capabilities{
		Name:                       h.Name,
		ClientID:                   h.ClientID,
		Port:                       h.Port,
		Server:                     h.Server,
		UDPPort:                    h.UDPPort,
		KadPort:                    h.KadPort,
		UDPVersion:                 h.Misc1.UDPVersion,
		IPv6:                       h.IPv6,
		EmuleVersion:               h.EmuleVersion,
		IsEmule:                    h.EmuleVersion != 0,
		MuleVersion:                toMuleVersion(h.EmuleVersion),
		CanCompress:                h.Misc1.DataCompressionVersion > 0,
		SecureIdent:                h.Misc1.SecureIdentVersion,
		ExtendedRequests:           h.Misc1.ExtendedRequestsVersion,
		HasMultiPacket:             h.Misc1.HasMultiPacket,
		HasExtMultiPacket:          h.Misc2.HasExtMultiPacket,
		HasLargeFiles:              h.Misc2.HasLargeFiles,
		HasSourceExchange2:         h.Misc2.HasSourceExchange2,
		HasExtendedSources:         h.ModMisc&client.ModMiscExtendedSources != 0,
		HasExtendedSourcesSkipTags: h.ModMisc&client.ModMiscExtendedSourcesSkipTags != 0,
		CryptOptions:               toCryptOptions(h.Misc2),
	}
}

func toMuleVersion(emuleVersion uint32) byte {
	if emuleVersion == 0 {
		return 0
	}
	return 0x99
}

// toCryptOptions drops a request without support and a requirement
// without request, as eMule reads the Hello.
func toCryptOptions(m client.MiscOptions2) byte {
	var options byte
	if m.CanCrypt {
		options |= CryptSupported
		if m.IsCryptRequested {
			options |= CryptRequested
			if m.IsCryptRequired {
				options |= CryptRequired
			}
		}
	}
	return options
}

// onEmuleInfo serves clients older than the Hello capability tags; a peer
// that sent CT_EMULE_VERSION already told us everything.
func (s *Session) onEmuleInfo(p client.EmuleInfo, out *Output) {
	s.sendEmuleInfoAnswer(out)
	s.setEmuleInfo(p)
}

func (s *Session) sendEmuleInfoAnswer(out *Output) {
	major, minor, _ := toVersion(s.cfg.Version)
	tag := func(id byte, v uint32) wire.Tag { return wire.Tag{Type: wire.TagUint32, ID: id, Uint: uint64(v)} }
	out.send(client.EmuleInfoAnswer{
		Version:         byte(major<<4 | minor&0x0F),
		ProtocolVersion: emuleProtocol,
		Tags: []wire.Tag{
			tag(client.InfoCompression, dataCompressionVersion),
			tag(client.InfoUDPVersion, udpVersion),
			tag(client.InfoUDPPort, uint32(s.cfg.UDPPort)),
			tag(client.InfoExtendedRequest, client.ExtendedRequestsVersion),
			tag(client.InfoCompatibleClient, compatibleClient),
			tag(client.InfoFeatures, identity.Support),
		},
	})
}

func (s *Session) setEmuleInfo(p client.EmuleInfo) {
	if s.caps.IsEmule {
		return
	}
	s.caps.IsEmule = true
	s.caps.MuleVersion = p.Version
	for _, t := range p.Tags {
		switch t.ID {
		case client.InfoCompression:
			s.caps.CanCompress = t.Uint > 0
		case client.InfoUDPVersion:
			s.caps.UDPVersion = byte(t.Uint)
		case client.InfoUDPPort:
			s.caps.UDPPort = uint16(t.Uint)
		case client.InfoExtendedRequest:
			s.caps.ExtendedRequests = byte(t.Uint)
		case client.InfoFeatures:
			s.caps.SecureIdent = byte(t.Uint) & 0x03
		}
	}
}

// identState runs Secure User Identification in both directions: we prove
// ourselves to the peer, and the peer proves itself to us.
type identState struct {
	challenge          uint32
	peerKey            []byte
	isSignaturePending bool
	pendingChallenge   uint32
	pendingKind        identity.IPKind
	isIdentified       bool
}

// sendIdentState always asks for the key too: the engine compares the key
// that signed against the one it stored, so the session needs no ledger.
func (s *Session) sendIdentState(out *Output) {
	if s.caps.SecureIdent == 0 {
		return
	}
	for s.ident.challenge == 0 {
		s.ident.challenge = s.cfg.Random.Uint32()
	}
	out.send(client.SecureIdentState{State: client.SecureIdentNeedsKeyAndSignature, Challenge: s.ident.challenge})
}

func (s *Session) onIdentState(p client.SecureIdentState, out *Output) {
	reply := identity.BuildReply(identity.State(p.State), s.caps.SecureIdent, wire.IsLowID(s.cfg.ClientID), s.ident.peerKey != nil)
	if reply.ShouldSendKey {
		out.send(client.PublicKey{Key: s.cfg.Self.PublicKey()})
	}
	switch {
	case reply.ShouldSendSignature:
		s.sendSignature(p.Challenge, reply.IPKind, out)
	case reply.IsSignaturePending:
		s.ident.isSignaturePending = true
		s.ident.pendingChallenge = p.Challenge
		s.ident.pendingKind = reply.IPKind
	}
}

func (s *Session) sendSignature(value uint32, kind identity.IPKind, out *Output) {
	challenge := identity.BuildChallenge(value, kind, wire.ToAddr(s.cfg.ClientID), s.remote.Addr())
	signature := s.cfg.Self.BuildSignature(s.ident.peerKey, challenge)
	out.send(client.Signature{Signature: signature, IPKind: byte(kind)})
}

func (s *Session) onPublicKey(p client.PublicKey, out *Output) {
	if s.ident.peerKey != nil {
		return
	}
	s.ident.peerKey = bytes.Clone(p.Key)
	if s.ident.isSignaturePending {
		s.ident.isSignaturePending = false
		s.sendSignature(s.ident.pendingChallenge, s.ident.pendingKind, out)
	}
}

func (s *Session) onSignature(p client.Signature, out *Output) {
	if s.ident.challenge == 0 {
		return
	}
	challenge := identity.BuildChallenge(s.ident.challenge, identity.IPKind(p.IPKind), s.remote.Addr(), s.toPublicIP())
	s.ident.challenge = 0
	if s.ident.peerKey == nil || !identity.MatchSignature(s.ident.peerKey, p.Signature, s.cfg.Self.PublicKey(), challenge) {
		out.add(IdentityFailed{UserHash: s.userHash})
		return
	}
	s.ident.isIdentified = true
	out.add(Identified{UserHash: s.userHash, PublicKey: s.ident.peerKey})
}

func (s *Session) toPublicIP() netip.Addr {
	if !wire.IsLowID(s.cfg.ClientID) {
		return wire.ToAddr(s.cfg.ClientID)
	}
	return s.cfg.PublicIP
}
