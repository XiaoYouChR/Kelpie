package link

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/XiaoYouChR/Kelpie/internal/piece"
	"github.com/XiaoYouChR/Kelpie/internal/wire"
)

// ErrInvalid wraps every Parse error: the text is not an eD2k file link.
var ErrInvalid = errors.New("invalid ed2k file link")

// maxSize is eMule's MAX_EMULE_FILE_SIZE (256 GiB).
const maxSize int64 = 256 << 30

// File is what an eD2k file link says about a file. PartHashes is empty unless
// the link carries a hash set that matches the file hash; AICHHash is zero
// unless the link carries one; Sources holds only the sources given as
// IP:port.
type File struct {
	Name       string
	Size       int64
	Hash       wire.Hash
	PartHashes []wire.Hash
	AICHHash   wire.AICHHash
	Sources    []netip.AddrPort
}

// Parse reads ed2k://|file|<name>|<size>|<hash>|[h=<AICH>|][p=<hashes>|]/[|sources,<ip:port>,...|/].
// Unknown fields and HTTP sources are ignored.
func Parse(text string) (File, error) {
	text = strings.TrimSpace(text)
	const scheme = "ed2k://"
	if len(text) < len(scheme) || !strings.EqualFold(text[:len(scheme)], scheme) {
		return File{}, fmt.Errorf("%w: missing ed2k:// scheme", ErrInvalid)
	}
	fields := strings.Split(text[len(scheme):], "|")
	if len(fields) < 5 || fields[0] != "" || !strings.EqualFold(fields[1], "file") {
		return File{}, fmt.Errorf("%w: not a file link", ErrInvalid)
	}

	file := File{Name: toUnescaped(fields[2])}
	if file.Name == "" {
		return File{}, fmt.Errorf("%w: empty name", ErrInvalid)
	}
	size, err := parseSize(fields[3])
	if err != nil {
		return File{}, err
	}
	file.Size = size
	if file.Hash, err = wire.ParseHash(fields[4]); err != nil {
		return File{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}

	for _, field := range fields[5:] {
		switch {
		case strings.HasPrefix(field, "p="):
			file.PartHashes = parsePartHashes(field[len("p="):], file.Size, file.Hash)
		case strings.HasPrefix(field, "h="):
			// aMule rejects the link over a malformed AICH hash
			// (ED2KLink.cpp:260-267); like a bad hash set, it is only dropped.
			file.AICHHash, _ = wire.ParseAICHHash(field[len("h="):])
		case strings.HasPrefix(strings.ToLower(field), "sources,"):
			file.Sources = append(file.Sources, parseSources(field)...)
		}
	}
	return file, nil
}

func parseSize(text string) (int64, error) {
	if text == "" || strings.Trim(text, "0123456789") != "" {
		return 0, fmt.Errorf("%w: size %q is not a decimal number", ErrInvalid, text)
	}
	size, err := strconv.ParseInt(text, 10, 64)
	if err != nil || size <= 0 || size > maxSize {
		return 0, fmt.Errorf("%w: size %q is not between 1 and %d", ErrInvalid, text, maxSize)
	}
	return size, nil
}

// parsePartHashes drops a hash set that does not belong to the file rather
// than rejecting the link: the file hash alone is enough to download.
func parsePartHashes(text string, size int64, fileHash wire.Hash) []wire.Hash {
	var hashes []wire.Hash
	for _, item := range strings.Split(text, ":") {
		hash, err := wire.ParseHash(item)
		if err != nil {
			return nil
		}
		hashes = append(hashes, hash)
	}
	if len(hashes) != piece.HashCount(size) || piece.BuildFileHash(hashes) != fileHash {
		return nil
	}
	return hashes
}

// parseSources skips host names: resolving them is I/O and eMule rarely
// writes them.
func parseSources(field string) []netip.AddrPort {
	var sources []netip.AddrPort
	for _, item := range strings.Split(field, ",")[1:] {
		source, err := netip.ParseAddrPort(strings.TrimSpace(item))
		if err == nil && source.Port() != 0 {
			sources = append(sources, source)
		}
	}
	return sources
}

// toUnescaped decodes %XX escapes like Python's urllib.parse.unquote, so both
// sides of testdata/links.json agree: a malformed escape stays literal and '+'
// stays a plus.
func toUnescaped(text string) string {
	var decoded []byte
	for i := 0; i < len(text); i++ {
		if text[i] == '%' && i+2 < len(text) && isHex(text[i+1]) && isHex(text[i+2]) {
			value, _ := strconv.ParseUint(text[i+1:i+3], 16, 8)
			decoded = append(decoded, byte(value))
			i += 2
			continue
		}
		decoded = append(decoded, text[i])
	}
	return strings.ToValidUTF8(string(decoded), "\uFFFD")
}

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}
