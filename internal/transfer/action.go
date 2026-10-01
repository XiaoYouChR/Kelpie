package transfer

import (
	"net/netip"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/piece"
	"github.com/XiaoYouChR/Kelpie/internal/wire"
)

// Action is something the engine performs for a Transfer. The Transfer never
// performs I/O itself.
type Action interface{ isAction() }

// Connect opens a TCP connection to a source, obfuscated when the source
// supports it and its user hash is known.
type Connect struct {
	Endpoint     netip.AddrPort
	UserHash     wire.Hash
	CanObfuscate bool
}

// ReaskUDP sends OP_REASKFILEPING to the source's UDP endpoint, obfuscated
// like Connect.
type ReaskUDP struct {
	Endpoint     netip.AddrPort
	UserHash     wire.Hash
	CanObfuscate bool
}

// RequestServerCallback asks our server to make a LowID source connect to us.
type RequestServerCallback struct{ ClientID uint32 }

// RequestKadCallback asks a firewalled Kad source's buddy to make it connect
// to us; with IsDirect, Buddy is the source itself, asked over UDP,
// obfuscated like Connect.
type RequestKadCallback struct {
	Buddy        netip.AddrPort
	BuddyID      wire.Hash
	IsDirect     bool
	UserHash     wire.Hash
	CanObfuscate bool
}

// RequestSources asks a connected peer for its sources by Source Exchange;
// the server and Kad pace their own source searches.
type RequestSources struct{ Peer uint64 }

// RequestHashSet asks a connected peer for the file's part hashes.
type RequestHashSet struct{ Peer uint64 }

// Publish announces the parts we can share, to the server and to Kad.
type Publish struct{ Parts piece.Set }

// Write stores a received block on disk; the engine answers with OnBlockWritten
// or OnDiskFailed.
type Write struct {
	Block piece.Block
	Data  []byte
}

// HashPart reads the part back from disk and hashes it with MD4; the engine
// answers with OnPartHashed or OnDiskFailed.
type HashPart struct{ Part int }

// Close ends a peer connection for this Transfer.
type Close struct {
	Peer   uint64
	Reason string
}

// TraceEvent is one source lifecycle line for the trace file (docs/protocol.md
// Trace). Fields that the event does not use are zero.
type TraceEvent struct {
	Time    time.Time
	Hash    wire.Hash
	Source  string
	Event   Event
	Channel Channel
	IsIPv6  bool
	Reason  string
	Rank    int
	Bytes   int64
}

type Event string

const (
	EventFound     Event = "found"
	EventConnected Event = "connected"
	EventFailed    Event = "failed"
	EventQueued    Event = "queued"
	EventSlot      Event = "slot"
	EventReceived  Event = "received"
	EventClosed    Event = "closed"
)

// Channel is where a source came from, or where sources are requested.
type Channel string

const (
	ChannelLink         Channel = "link"
	ChannelServer       Channel = "server"
	ChannelGlobalServer Channel = "globalServer"
	ChannelKad          Channel = "kad"
	ChannelExchange     Channel = "exchange"
	ChannelIncoming     Channel = "incoming"
)

func (Connect) isAction()               {}
func (ReaskUDP) isAction()              {}
func (RequestServerCallback) isAction() {}
func (RequestKadCallback) isAction()    {}
func (RequestSources) isAction()        {}
func (RequestHashSet) isAction()        {}
func (Publish) isAction()               {}
func (Write) isAction()                 {}
func (HashPart) isAction()              {}
func (Close) isAction()                 {}
func (TraceEvent) isAction()            {}
