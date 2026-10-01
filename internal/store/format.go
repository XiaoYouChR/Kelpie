package store

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"slices"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/wire"
)

// version is Kelpie's state.json format; goed2k wrote versions up to 3.
const version = 4

type stateFile struct {
	Version    int            `json:"version"`
	UserHash   hashText       `json:"userHash"`
	PrivateKey []byte         `json:"privateKey,omitempty"`
	Kad        kadFile        `json:"kad"`
	Credits    []creditFile   `json:"credits"`
	Transfers  []transferFile `json:"transfers"`
}

type kadFile struct {
	ID           hashText      `json:"id"`
	IsFirewalled bool          `json:"isFirewalled"`
	UDPKey       uint32        `json:"udpKey,omitempty"`
	Nodes        []kadNodeFile `json:"nodes"`
}

type kadNodeFile struct {
	ID      hashText       `json:"id"`
	Addr    netip.AddrPort `json:"addr"`
	Version byte           `json:"version"`
}

type creditFile struct {
	UserHash   hashText  `json:"userHash"`
	Uploaded   uint64    `json:"uploaded"`
	Downloaded uint64    `json:"downloaded"`
	PublicKey  []byte    `json:"publicKey,omitempty"`
	LastSeen   time.Time `json:"lastSeen"`
}

type transferFile struct {
	Hash          hashText    `json:"hash"`
	Size          int64       `json:"size"`
	File          string      `json:"file"`
	PartHashes    []hashText  `json:"partHashes"`
	VerifiedParts []bool      `json:"verifiedParts"`
	WrittenBlocks []blockFile `json:"writtenBlocks"`
	Uploaded      uint64      `json:"uploaded"`
	Created       time.Time   `json:"created"`
}

type blockFile struct {
	Part  int `json:"part"`
	Index int `json:"index"`
}

// hashText is a wire.Hash written as uppercase hex, with "" for the zero hash
// as goed2k wrote it.
type hashText wire.Hash

func (h hashText) MarshalText() ([]byte, error) {
	if h == (hashText{}) {
		return nil, nil
	}
	return []byte(wire.Hash(h).String()), nil
}

func (h *hashText) UnmarshalText(text []byte) error {
	if len(bytes.TrimSpace(text)) == 0 {
		*h = hashText{}
		return nil
	}
	hash, err := wire.ParseHash(string(text))
	*h = hashText(hash)
	return err
}

func toFile(state State) stateFile {
	file := stateFile{
		Version:    version,
		UserHash:   hashText(state.Identity.UserHash),
		PrivateKey: state.Identity.PrivateKey,
		Kad:        kadFile{ID: hashText(state.Kad.ID), IsFirewalled: state.Kad.IsFirewalled, UDPKey: state.Kad.UDPKey, Nodes: []kadNodeFile{}},
		Credits:    []creditFile{},
		Transfers:  []transferFile{},
	}
	for _, node := range state.Kad.Nodes {
		file.Kad.Nodes = append(file.Kad.Nodes, kadNodeFile{ID: hashText(node.ID), Addr: node.Addr, Version: node.Version})
	}
	for hash, credit := range state.Credits {
		file.Credits = append(file.Credits, creditFile{
			UserHash:   hashText(hash),
			Uploaded:   credit.Uploaded,
			Downloaded: credit.Downloaded,
			PublicKey:  credit.PublicKey,
			LastSeen:   credit.LastSeen,
		})
	}
	slices.SortFunc(file.Credits, func(a, b creditFile) int { return bytes.Compare(a.UserHash[:], b.UserHash[:]) })
	for hash, transfer := range state.Transfers {
		entry := transferFile{
			Hash:          hashText(hash),
			Size:          transfer.Size,
			File:          transfer.File,
			PartHashes:    []hashText{},
			VerifiedParts: transfer.VerifiedParts,
			WrittenBlocks: []blockFile{},
			Uploaded:      transfer.Uploaded,
			Created:       transfer.Created,
		}
		for _, part := range transfer.PartHashes {
			entry.PartHashes = append(entry.PartHashes, hashText(part))
		}
		for _, block := range transfer.WrittenBlocks {
			entry.WrittenBlocks = append(entry.WrittenBlocks, blockFile(block))
		}
		file.Transfers = append(file.Transfers, entry)
	}
	slices.SortFunc(file.Transfers, func(a, b transferFile) int { return bytes.Compare(a.Hash[:], b.Hash[:]) })
	return file
}

func parse(raw []byte) (State, error) {
	var file stateFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return State{}, err
	}
	state := buildState()
	state.Identity = Identity{UserHash: wire.Hash(file.UserHash), PrivateKey: file.PrivateKey}
	state.Kad = Kad{ID: wire.Hash(file.Kad.ID), IsFirewalled: file.Kad.IsFirewalled, UDPKey: file.Kad.UDPKey}
	for _, node := range file.Kad.Nodes {
		state.Kad.Nodes = append(state.Kad.Nodes, KadNode{ID: wire.Hash(node.ID), Addr: node.Addr, Version: node.Version})
	}
	for _, credit := range file.Credits {
		state.Credits[wire.Hash(credit.UserHash)] = Credit{
			Uploaded:   credit.Uploaded,
			Downloaded: credit.Downloaded,
			PublicKey:  credit.PublicKey,
			LastSeen:   credit.LastSeen,
		}
	}
	for _, entry := range file.Transfers {
		transfer := Transfer{
			Size:          entry.Size,
			File:          entry.File,
			VerifiedParts: entry.VerifiedParts,
			Uploaded:      entry.Uploaded,
			Created:       entry.Created,
		}
		for _, part := range entry.PartHashes {
			transfer.PartHashes = append(transfer.PartHashes, wire.Hash(part))
		}
		for _, block := range entry.WrittenBlocks {
			transfer.WrittenBlocks = append(transfer.WrittenBlocks, Block(block))
		}
		state.Transfers[wire.Hash(entry.Hash)] = transfer
	}
	return state, nil
}
