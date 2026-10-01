// Package store loads and saves the Engine Process's Durable State.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/wire"
)

const fileName = "state.json"

type State struct {
	Identity  Identity
	Kad       Kad
	Credits   map[wire.Hash]Credit
	Transfers map[wire.Hash]Transfer
	Servers   []Server
}

type Identity struct {
	UserHash wire.Hash
	// PrivateKey is the DER encoded RSA key for Secure User Identification;
	// empty until the engine creates one.
	PrivateKey []byte
}

type Kad struct {
	ID           wire.Hash
	IsFirewalled bool
	Nodes        []KadNode
}

type KadNode struct {
	ID      wire.Hash
	Addr    netip.AddrPort
	Version byte
}

// Server is what the Engine Process learned about one listed eD2k server,
// as aMule keeps it in its own server.met (ServerList.cpp:689-800). A
// server listed by address is named by Endpoint, one listed by host name
// by Host and Port.
type Server struct {
	Endpoint           netip.AddrPort
	Host               string
	Port               uint16
	Failures           uint32
	Ping               uint32
	Users              uint32
	Files              uint32
	SoftFiles          uint32
	UDPFlags           uint32
	TCPObfuscationPort uint16
	UDPObfuscationPort uint16
	PingedAt           time.Time
}

type Credit struct {
	Uploaded   uint64
	Downloaded uint64
	PublicKey  []byte
	LastSeen   time.Time
}

type Transfer struct {
	Size          int64
	File          string
	PartHashes    []wire.Hash
	VerifiedParts []bool
	WrittenBlocks []Block
	Uploaded      uint64
	Created       time.Time
}

// Block is one 184320-byte block written to a part that is not yet verified.
type Block struct {
	Part  int
	Index int
}

func buildState() State {
	return State{Credits: map[wire.Hash]Credit{}, Transfers: map[wire.Hash]Transfer{}}
}

// Load reads the state in folder. A missing file is an empty State; a file
// written by goed2k is converted.
func Load(folder string) (State, error) {
	raw, err := os.ReadFile(filepath.Join(folder, fileName))
	if errors.Is(err, fs.ErrNotExist) {
		return buildState(), nil
	}
	if err != nil {
		return State{}, err
	}
	var header struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(raw, &header); err != nil {
		return State{}, fmt.Errorf("load %s: %w", fileName, err)
	}
	var state State
	switch header.Version {
	case 0, 1, 2, 3:
		state, err = parseGoed2k(raw)
	case version:
		state, err = parse(raw)
	default:
		err = fmt.Errorf("unsupported version %d", header.Version)
	}
	if err != nil {
		return State{}, fmt.Errorf("load %s: %w", fileName, err)
	}
	return state, nil
}

// Save replaces the state in folder so that a crash leaves either the old or
// the new file, never a torn one.
func Save(folder string, state State) error {
	raw, err := json.MarshalIndent(toFile(state), "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(folder, 0o755); err != nil {
		return err
	}
	temp, err := os.CreateTemp(folder, fileName+".*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	_, err = temp.Write(raw)
	if err == nil {
		err = temp.Sync()
	}
	if closeErr := temp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(temp.Name(), filepath.Join(folder, fileName)); err != nil {
		return err
	}
	return flushFolder(folder)
}

// flushFolder makes the rename durable. Windows cannot open a directory for
// flushing; NTFS journals the rename instead.
func flushFolder(folder string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	dir, err := os.Open(folder)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
