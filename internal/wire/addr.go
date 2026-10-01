package wire

import (
	"encoding/binary"
	"net/netip"
)

// LowIDLimit is the first HighID. A HighID is the client's IPv4 address read
// as a little-endian uint32, so every address whose first byte is non-zero
// lands at or above it; anything below is a server-assigned LowID.
const LowIDLimit = 16777216

// IPv6Sentinel is the client id that marks a source carrying an IPv6
// address (emule-qt ipv6-spec §1.4, §4.4).
const IPv6Sentinel = 0xFFFFFFFF

func IsLowID(id uint32) bool { return id < LowIDLimit }

// ToClientID returns the HighID of an IPv4 address; other addresses give 0.
func ToClientID(addr netip.Addr) uint32 {
	if !addr.Is4() {
		return 0
	}
	a := addr.As4()
	return binary.LittleEndian.Uint32(a[:])
}

// ToAddr returns the IPv4 address a HighID stands for.
func ToAddr(id uint32) netip.Addr {
	var a [4]byte
	binary.LittleEndian.PutUint32(a[:], id)
	return netip.AddrFrom4(a)
}
