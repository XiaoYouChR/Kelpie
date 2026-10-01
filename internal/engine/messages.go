package engine

import (
	"io"

	"github.com/XiaoYouChR/Kelpie/internal/wire"
)

// RunID is chosen by Kelpie and never reused within one Engine Process.
type RunID uint64

type Mode int

const (
	ModeDownload Mode = iota
	ModeSeed
)

// Command is posted to the Engine by the gateway; see docs/protocol.md.
type Command interface{ isCommand() }

type RunCommand struct {
	ID   RunID
	Mode Mode
	Link string
	File string
}

type StopCommand struct{ ID RunID }

type RemoveCommand struct{ Hash wire.Hash }

type RateLimitsCommand struct{ Download, Upload int64 }

func (RunCommand) isCommand()        {}
func (StopCommand) isCommand()       {}
func (RemoveCommand) isCommand()     {}
func (RateLimitsCommand) isCommand() {}

type Config struct {
	Version     string
	DataFolder  string
	Port        int
	EnableKad   bool
	EnableUPnP  bool
	ServerLists []string
	NodeLists   []string
	TraceFile   string
	RateLimits  RateLimitsCommand
	// PacketLog, when set, gets one line per TCP packet sent or received
	// and per closed connection, for debugging against real peers.
	PacketLog io.Writer
}

type Progress struct {
	Hash         wire.Hash
	Size         int64
	Received     int64
	DownloadRate int64
	UploadRate   int64
	Uploaded     int64
	Peers        int
	ActivePeers  int
}

type Network struct {
	IsServerConnected bool
	IsHighID          bool
	IsKadFirewalled   bool
	KadNodes          int
	// IsBehindCarrierNat follows docs/protocol.md "network".
	IsBehindCarrierNat bool
}

type Code string

const (
	CodeInvalidLink  Code = "INVALID_LINK"
	CodeOutputExists Code = "OUTPUT_EXISTS"
	CodeTransferBusy Code = "TRANSFER_BUSY"
	CodeDiskFull     Code = "DISK_FULL"
	CodeFileError    Code = "FILE_ERROR"
	CodeStartFailed  Code = "START_FAILED"
	CodeInternal     Code = "INTERNAL"
)

type Error struct {
	Code    Code
	Message string
}

func (e *Error) Error() string { return string(e.Code) + ": " + e.Message }

// Events is how the Engine reports to the gateway. Implementations must never
// block: progress and network are latest-value slots, and every run gets
// exactly one SendEnded (ADR-0005).
type Events interface {
	SetProgress(id RunID, progress Progress)
	SendEnded(id RunID, err *Error)
	SetNetwork(network Network)
}
