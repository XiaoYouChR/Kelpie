package obfuscation

import (
	"bytes"
	"crypto/md5"
	"crypto/rc4"
	"net/netip"
	"testing"

	"github.com/XiaoYouChR/Kelpie/internal/wire"
)

// rc4Of is RC4 keyed with MD5 of key, written out apart from the package so
// that a mistake in the key layout cannot cancel out in a round trip.
func rc4Of(key []byte) *rc4.Cipher {
	sum := md5.Sum(key)
	c, err := rc4.NewCipher(sum[:])
	if err != nil {
		panic(err)
	}
	return c
}

// sealAsAMule builds an eD2k datagram as EncryptSendClient and
// EncryptSendServer lay it out, padding included; padLen is the byte sent
// for the padding's length.
func sealAsAMule(marker byte, keyPart [2]byte, key []byte, magic [4]byte, padLen byte, padding, packet []byte) []byte {
	plain := append(append(append(magic[:], padLen), padding...), packet...)
	sealed := make([]byte, len(plain))
	rc4Of(key).XORKeyStream(sealed, plain)
	return append([]byte{marker, keyPart[0], keyPart[1]}, sealed...)
}

// openAsAMule reverses sealAsAMule.
func openAsAMule(data []byte, key []byte) (magic [4]byte, padLen byte, rest []byte) {
	plain := make([]byte, len(data)-3)
	rc4Of(key).XORKeyStream(plain, data[3:])
	copy(magic[:], plain)
	return magic, plain[4], plain[5:]
}

var (
	testUser   = wire.Hash{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0x01}
	testSender = netip.MustParseAddr("198.51.100.9")
	// MAGICVALUE_UDP_SYNC_CLIENT and _SERVER as they go on the wire.
	syncClient = [4]byte{0xC1, 0x2E, 0x5F, 0x39}
	syncServer = [4]byte{0xD5, 0x24, 0xEF, 0x13}
)

func peerKey(keyPart [2]byte) []byte {
	key := append(testUser[:], 198, 51, 100, 9, 91)
	return append(key, keyPart[:]...)
}

func serverKey(direction byte, keyPart [2]byte) []byte {
	return []byte{0x78, 0x56, 0x34, 0x12, direction, keyPart[0], keyPart[1]}
}

func TestPeerDatagramAsAMuleBuildsIt(t *testing.T) {
	packet := []byte{0xC5, 0x90, 1, 2, 3}
	sealed := sealAsAMule(0x37, [2]byte{0xAA, 0xBB}, peerKey([2]byte{0xAA, 0xBB}), syncClient, 3, []byte{9, 9, 9}, packet)
	got, ok := ParsePeerDatagram(sealed, testUser, testSender)
	if !ok || !bytes.Equal(got, packet) {
		t.Fatalf("parsed %x, %v", got, ok)
	}
	if _, ok := ParsePeerDatagram(sealed, testUser, netip.MustParseAddr("198.51.100.10")); ok {
		t.Fatal("decrypted with another sender address")
	}
}

func TestPeerDatagramAsAMuleReadsIt(t *testing.T) {
	packet := []byte{0xC5, 0x91, 7}
	data := BuildPeerDatagram(packet, testUser, testSender, 0x00C4BBAA)
	if data[0]&0x01 == 0 || matchPlainDatagram(data[0]) || data[1] != 0xAA || data[2] != 0xBB {
		t.Fatalf("header %x", data[:3])
	}
	magic, padLen, rest := openAsAMule(data, peerKey([2]byte{0xAA, 0xBB}))
	if magic != syncClient || padLen != 0 || !bytes.Equal(rest, packet) {
		t.Fatalf("magic %x padding %d packet %x", magic, padLen, rest)
	}
}

func TestServerDatagramAsAMuleBuildsIt(t *testing.T) {
	packet := []byte{0xE3, 0x97, 1, 2, 3, 4}
	keyPart := [2]byte{0x01, 0x02}
	// A server's padding length counts modulo 16: 0x22 is two bytes.
	sealed := sealAsAMule(0xC5, keyPart, serverKey(0xA5, keyPart), syncServer, 0x22, []byte{5, 5}, packet)
	got, ok := ParseServerDatagram(sealed, 0x12345678)
	if !ok || !bytes.Equal(got, packet) {
		t.Fatalf("parsed %x, %v", got, ok)
	}
	if _, ok := ParseServerDatagram(sealed, 0x12345679); ok {
		t.Fatal("decrypted with another key")
	}
}

func TestServerDatagramAsAMuleReadsIt(t *testing.T) {
	packet := []byte{0xE3, 0x9A, 1}
	data := BuildServerDatagram(packet, 0x12345678, 0x00E30201)
	if data[0] == 0xE3 || data[1] != 0x01 || data[2] != 0x02 {
		t.Fatalf("header %x", data[:3])
	}
	magic, padLen, rest := openAsAMule(data, serverKey(0x6B, [2]byte{0x01, 0x02}))
	if magic != syncServer || padLen != 0 || !bytes.Equal(rest, packet) {
		t.Fatalf("magic %x padding %d packet %x", magic, padLen, rest)
	}
}

func TestPlainDatagramsPassThrough(t *testing.T) {
	plain := append([]byte{0xC5, 0x90}, make([]byte, 20)...)
	if _, ok := ParsePeerDatagram(plain, testUser, testSender); ok {
		t.Fatal("took a plain peer datagram for an obfuscated one")
	}
	plain[0] = 0xE3
	if _, ok := ParseServerDatagram(plain, 1); ok {
		t.Fatal("took a plain server datagram for an obfuscated one")
	}
	// A plain server datagram does not start with a peer protocol byte, so
	// it is tried, and fails on the magic.
	if _, ok := ParsePeerDatagram(plain, testUser, testSender); ok {
		t.Fatal("decrypted a plain server datagram")
	}
}

func TestPeerMarkerIsNeverAProtocolByte(t *testing.T) {
	for random := range uint32(256) {
		if b := BuildPeerDatagram([]byte{1}, testUser, testSender, random<<16)[0]; matchPlainDatagram(b) || b&0x01 == 0 {
			t.Fatalf("marker %#x", b)
		}
		if b := BuildServerDatagram([]byte{1}, 1, random<<16)[0]; b == wire.ProtocolEDonkey {
			t.Fatalf("server marker %#x", b)
		}
	}
}
