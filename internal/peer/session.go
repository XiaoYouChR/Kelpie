// Package peer is the state machine of one TCP connection to another eD2k
// client. One connection may download several of our files and upload
// several of theirs at once. It does no I/O: the engine feeds it packets,
// ticks and decisions, and performs the Output it returns.
package peer

import (
	"math/rand/v2"
	"net/netip"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/identity"
	"github.com/XiaoYouChR/Kelpie/internal/piece"
	"github.com/XiaoYouChR/Kelpie/internal/wire"
	"github.com/XiaoYouChR/Kelpie/internal/wire/client"
)

const (
	// CONNECTION_TIMEOUT: a connection with no packet either way for this
	// long is dead.
	connectionTimeout = 40 * time.Second
	// DOWNLOADTIMEOUT: a granted slot with blocks in flight but no data for
	// this long is given up.
	downloadTimeout = 100 * time.Second
)

// Config is our side of the handshake, fixed for the session's lifetime.
type Config struct {
	Self identity.Self
	// Version is Kelpie's "major.minor.update".
	Version string
	// ClientID is the id the server gave us: HighID, LowID, or 0 when no
	// server is connected.
	ClientID uint32
	// PublicIP is our IPv4 address as the world sees it, if known.
	PublicIP   netip.Addr
	IPv6       netip.Addr
	Port       uint16
	UDPPort    uint16
	KadPort    uint16
	KadVersion byte
	Server     netip.AddrPort
	// Pipeline is how many blocks a download keeps in flight.
	Pipeline int
	Random   *rand.Rand
	// Buddy is our Kad buddy's IP and UDP port while it serves us.
	Buddy netip.AddrPort
	// HasDirectCallback: we take Kad callback requests ourselves, over UDP.
	HasDirectCallback bool
}

// Capabilities is what the peer told us about itself in the handshake.
type Capabilities struct {
	Name         string
	ClientID     uint32
	Port         uint16
	Server       netip.AddrPort
	UDPPort      uint16
	KadPort      uint16
	UDPVersion   byte
	KadVersion   byte
	IPv6         netip.Addr
	EmuleVersion uint32
	// IsEmule: the peer speaks the eMule extended protocol (CT_EMULE_VERSION
	// in Hello or OP_EMULEINFO).
	IsEmule bool
	// MuleVersion is aMule's m_byEmuleVersion: 0x99 when Hello carried
	// CT_EMULE_VERSION, else the OP_EMULEINFO version byte, else 0
	// (BaseClient.cpp:631,884).
	MuleVersion                byte
	CanCompress                bool
	SecureIdent                byte
	ExtendedRequests           byte
	HasMultiPacket             bool
	HasExtMultiPacket          bool
	HasFileIdentifiers         bool
	HasLargeFiles              bool
	HasSourceExchange2         bool
	HasExtendedSources         bool
	HasExtendedSourcesSkipTags bool
	HasAICH                    bool
	// CryptOptions is the peer's obfuscation setting from its Hello, in
	// Source's layout.
	CryptOptions byte
}

type Session struct {
	cfg          Config
	remote       netip.AddrPort
	isOutgoing   bool
	isHandshaken bool
	userHash     wire.Hash
	caps         Capabilities
	lastActive   time.Time
	timeout      time.Duration
	// earlyEmuleInfo is an OP_EMULEINFO that came before the peer's Hello.
	earlyEmuleInfo *client.EmuleInfo
	recovery       *recoveryRequest

	ident identState
	down  downloadState
	up    uploadState
	sx    sourceState
}

// BuildOutgoing starts a session on a connection we opened to remote; the
// returned Output carries our Hello.
func BuildOutgoing(cfg Config, remote netip.AddrPort, now time.Time) (*Session, Output) {
	s := buildSession(cfg, remote, now)
	s.isOutgoing = true
	var out Output
	out.send(client.Hello(s.buildHello()))
	return s, out
}

// BuildIncoming starts a session on a connection remote opened to us; it
// waits for the peer's Hello.
func BuildIncoming(cfg Config, remote netip.AddrPort, now time.Time) *Session {
	return buildSession(cfg, remote, now)
}

func buildSession(cfg Config, remote netip.AddrPort, now time.Time) *Session {
	return &Session{
		cfg:        cfg,
		remote:     netip.AddrPortFrom(remote.Addr().Unmap(), remote.Port()),
		lastActive: now,
		timeout:    connectionTimeout,
		down:       downloadState{files: map[wire.Hash]*download{}},
		up:         uploadState{parts: map[wire.Hash]piece.Set{}, sizes: map[wire.Hash]int64{}, blocks: map[uploadBlock]bool{}},
		sx:         sourceState{asked: map[wire.Hash]bool{}, answers: map[wire.Hash]byte{}},
	}
}

func (s *Session) Capabilities() Capabilities { return s.caps }
func (s *Session) UserHash() wire.Hash        { return s.userHash }
func (s *Session) isIdentified() bool         { return s.ident.isIdentified }

// OnPacket reacts to one packet from the peer. shares tells which of our
// files we offer, for the packets that ask about them.
func (s *Session) OnPacket(p wire.Packet, shares Shares, now time.Time) Output {
	s.lastActive = now
	var out Output
	if !s.isHandshaken {
		s.onGreeting(p, &out)
		return out
	}
	switch p := p.(type) {
	case client.Hello, client.HelloAnswer:
		out.Close = CloseProtocol
	case client.EmuleInfo:
		s.onEmuleInfo(p, &out)
	case client.IPv6Changed:
		s.caps.IPv6 = p.Addr
	case client.SecureIdentState:
		s.onIdentState(p, &out)
	case client.PublicKey:
		s.onPublicKey(p, &out)
	case client.Signature:
		s.onSignature(p, &out)

	case client.FileNameAnswer:
		s.onFileName(p.Hash, &out)
	case client.FileStatus:
		s.onFileStatus(p, &out)
	case client.MultiPacketAnswer:
		s.onMultiPacketAnswer(p.Answers, &out)
	case client.MultiPacketAnswerExt2:
		s.onMultiPacketAnswerExt2(p, &out)
	case client.NoFile:
		s.onNoFile(p.Hash, &out)
	case client.HashSetAnswer:
		s.onHashSet(p, &out)
	case client.QueueRanking:
		s.onQueueRank(uint32(p.Rank), &out)
	case client.QueueRank:
		s.onQueueRank(p.Rank, &out)
	case client.AcceptUploadRequest:
		s.onSlotGranted(now, &out)
	case client.OutOfParts:
		s.stopSlot(&out)
	case client.SendingPart:
		s.onPart(p.Hash, int64(p.Start), p.Data, now, &out)
	case client.SendingPart64:
		s.onPart(p.Hash, int64(p.Start), p.Data, now, &out)
	case client.CompressedPart:
		s.onCompressedPart(p.Hash, int64(p.Start), p.PackedSize, p.Data, now, &out)
	case client.CompressedPart64:
		s.onCompressedPart(p.Hash, int64(p.Start), p.PackedSize, p.Data, now, &out)
	case client.AICHFileHashAnswer:
		s.onRoot(p.Hash, p.Root, &out)
	case client.AICHAnswer:
		s.onRecoveryAnswer(p, &out)

	case client.FileRequest:
		s.onFileRequest(p, shares, &out)
	case client.SetRequestFileID:
		s.onStatusRequest(p.Hash, shares, &out)
	case client.MultiPacket:
		s.onMultiPacket(client.FileIdentifier{Hash: p.Hash}, p.Requests, false, shares, now, &out)
	case client.MultiPacketExt:
		s.onMultiPacket(client.FileIdentifier{Hash: p.Hash, Size: p.Size}, p.Requests, false, shares, now, &out)
	case client.MultiPacketExt2:
		s.onMultiPacket(p.File, p.Requests, true, shares, now, &out)
	case client.HashSetRequest:
		s.onHashSetRequest(p.Hash, shares, &out)
	case client.HashSetRequest2:
		s.onHashSetRequest2(p, shares, &out)
	case client.StartUploadRequest:
		s.onUploadRequest(p.Hash, shares, &out)
	case client.RequestParts:
		s.onPartsRequest(p.Hash, toBlocks32(p), shares, &out)
	case client.RequestParts64:
		s.onPartsRequest(p.Hash, toBlocks64(p), shares, &out)
	case client.CancelTransfer:
		s.onUploadCancelled(&out)
	case client.AICHFileHashRequest:
		if share, ok := shares(p.Hash); ok {
			if answer, ok := s.onRootRequest(p.Hash, share, &out); ok {
				out.send(answer)
			}
		}
	case client.AICHRequest:
		s.onRecoveryRequest(p, shares, &out)

	case client.RequestSources2:
		s.onSourcesRequest(p, shares, now, &out)
	case client.AnswerSources2:
		s.onSourcesAnswer(p, &out)
	}
	return out
}

// OnSent notes that a packet was written to the peer. aMule resets the
// connection timeout on every send as well as every receive
// (ClientTCPSocket.cpp:1840-1850, 2010-2035), so a peer we upload to slowly
// is not dropped.
func (s *Session) OnSent(now time.Time) {
	s.lastActive = now
}

// SetIdleTimeout sets how long the connection may be silent before it
// counts as dead; aMule gives a Kad buddy link longer than other
// connections (ClientTCPSocket.cpp:144).
func (s *Session) SetIdleTimeout(d time.Duration) {
	s.timeout = d
}

// OnTick closes an idle connection and gives up a slot that stopped
// delivering.
func (s *Session) OnTick(now time.Time) Output {
	var out Output
	if now.Sub(s.lastActive) > s.timeout {
		out.Close = CloseTimeout
		return out
	}
	if s.down.isSlotGranted && s.hasBlocksInFlight() && now.Sub(s.down.lastData) > downloadTimeout {
		out.send(client.CancelTransfer{})
		s.stopSlot(&out)
	}
	return out
}
