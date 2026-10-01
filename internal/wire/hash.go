package wire

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// Hash is an MD4 digest: a file hash, a part hash, or a user hash.
type Hash [16]byte

func ParseHash(text string) (Hash, error) {
	var hash Hash
	if len(text) != 32 {
		return hash, fmt.Errorf("hash %q: want 32 hex digits", text)
	}
	if _, err := hex.Decode(hash[:], []byte(text)); err != nil {
		return hash, fmt.Errorf("hash %q: %w", text, err)
	}
	return hash, nil
}

func (h Hash) String() string {
	return strings.ToUpper(hex.EncodeToString(h[:]))
}
