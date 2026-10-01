package peer

import (
	"net/netip"

	"github.com/XiaoYouChR/Kelpie/internal/piece"
	"github.com/XiaoYouChR/Kelpie/internal/wire"
)

// Output is what the engine must do after a call: write Send to the
// connection in order, handle Events, then close the connection if Close is
// set.
type Output struct {
	Send   []wire.Packet
	Events []Event
	Close  CloseReason
}

func (o *Output) send(p ...wire.Packet) { o.Send = append(o.Send, p...) }
func (o *Output) add(e Event)           { o.Events = append(o.Events, e) }

// CloseReason says why the session wants its connection closed; empty means
// keep it open.
type CloseReason string

const (
	CloseTimeout  CloseReason = "timeout"
	CloseProtocol CloseReason = "protocol violation"
)

type Event interface{ isEvent() }

// HandshakeCompleted: both hellos are exchanged and Capabilities is final.
// YourIP is the address the peer sees us at, a vote rather than a fact.
type HandshakeCompleted struct {
	UserHash wire.Hash
	YourIP   netip.Addr
}

// Identified: the peer proved it holds PublicKey. The engine checks the key
// against the one it stored for UserHash, if any.
type Identified struct {
	UserHash  wire.Hash
	PublicKey []byte
}

type IdentityFailed struct{ UserHash wire.Hash }

// StatusReceived carries which parts of File the peer has.
type StatusReceived struct {
	File  wire.Hash
	Parts piece.Set
}

// HashSetReceived carries part hashes already checked against File.
type HashSetReceived struct {
	File   wire.Hash
	Hashes []wire.Hash
}

// FileRejected: the peer does not share File; the session forgot it.
type FileRejected struct{ File wire.Hash }

type Queued struct {
	File wire.Hash
	Rank uint32
}

// SlotGranted: the peer accepted our upload request. File is zero when the
// grant arrives before any Start on this connection, typically on a
// connection the peer opened to us; the engine then Adds and Starts the file
// it queued for with this user.
type SlotGranted struct{ File wire.Hash }

// SlotRevoked: the peer ended our slot, or the session gave up on it after
// DOWNLOADTIMEOUT. Every block in flight for File is dropped.
type SlotRevoked struct{ File wire.Hash }

// BlocksWanted asks the engine to Request up to Count blocks of File.
type BlocksWanted struct {
	File  wire.Hash
	Count int
}

type BlockReceived struct {
	File  wire.Hash
	Block piece.Block
	Data  []byte
}

// UploadRequested: the peer wants to join our upload queue for File. Parts
// is what its file request said it has of File; nil when it did not say.
type UploadRequested struct {
	File  wire.Hash
	Parts piece.Set
}

// BlocksRequested asks the engine to read Blocks and SendBlock each one.
type BlocksRequested struct {
	File   wire.Hash
	Blocks []piece.Block
}

// UploadCancelled: the peer no longer wants anything uploaded.
type UploadCancelled struct{}

// SourcesRequested asks the engine to SendSources for File. Parts is as in
// UploadRequested, so that the answer lists only sources the peer needs.
type SourcesRequested struct {
	File  wire.Hash
	Parts piece.Set
}

type SourcesFound struct {
	File    wire.Hash
	Sources []Source
}

func (HandshakeCompleted) isEvent() {}
func (Identified) isEvent()         {}
func (IdentityFailed) isEvent()     {}
func (StatusReceived) isEvent()     {}
func (HashSetReceived) isEvent()    {}
func (FileRejected) isEvent()       {}
func (Queued) isEvent()             {}
func (SlotGranted) isEvent()        {}
func (SlotRevoked) isEvent()        {}
func (BlocksWanted) isEvent()       {}
func (BlockReceived) isEvent()      {}
func (UploadRequested) isEvent()    {}
func (BlocksRequested) isEvent()    {}
func (UploadCancelled) isEvent()    {}
func (SourcesRequested) isEvent()   {}
func (SourcesFound) isEvent()       {}
