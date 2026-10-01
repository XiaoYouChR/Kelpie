package obfuscation

import (
	"bytes"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"testing"
)

// peerConn plays a peer that sends data and swallows whatever we write.
type peerConn struct {
	net.Conn
	r io.Reader
}

func (c *peerConn) Read(b []byte) (int, error)  { return c.r.Read(b) }
func (c *peerConn) Write(b []byte) (int, error) { return len(b), nil }

// readAll drains an opened connection the way the frame reader would.
func readAll(conn net.Conn) {
	buf := make([]byte, 512)
	for {
		if _, err := conn.Read(buf); err != nil {
			return
		}
	}
}

// encrypt keys RC4 as the peer would, so the fuzzer mutates the plaintext
// behind the magic value instead of guessing it.
func encrypt(plain []byte, parts ...[]byte) []byte {
	out := append([]byte(nil), plain...)
	buildCipher(parts...).XORKeyStream(out, out)
	return out
}

func buildHandshake(padding int, payload []byte) []byte {
	b := binary.LittleEndian.AppendUint32(nil, magicSync)
	b = append(b, methodObfuscation, methodObfuscation, byte(padding))
	b = append(b, make([]byte, padding)...)
	return append(b, payload...)
}

func FuzzOpenIncoming(f *testing.F) {
	f.Add([]byte{1, 2, 3, 4, 5}, buildHandshake(3, []byte{0xE3, 1, 0, 0, 0, 1}), true)
	f.Add([]byte{0xE3, 5, 0, 0, 0, 1}, []byte{1, 2, 3, 4}, false)
	f.Fuzz(func(t *testing.T, head, rest []byte, isEncrypted bool) {
		data := append(append([]byte(nil), head...), rest...)
		if isEncrypted && len(head) >= 5 {
			data = append(append([]byte(nil), head...), encrypt(rest, user[:], []byte{magicRequester}, head[1:5])...)
		}
		if conn, err := OpenIncoming(&peerConn{r: bytes.NewReader(data)}, user); err == nil {
			readAll(conn)
		}
	})
}

func FuzzOpenOutgoing(f *testing.F) {
	keyPart := [4]byte{1, 2, 3, 4}
	answer := func(padding int, payload []byte) []byte {
		b := binary.LittleEndian.AppendUint32(nil, magicSync)
		b = append(b, methodObfuscation, byte(padding))
		b = append(b, make([]byte, padding)...)
		return append(b, payload...)
	}
	f.Add(answer(0, nil), true)
	f.Add(answer(200, []byte{0xC5, 2, 0, 0, 0, 0x60, 1}), true)
	f.Add([]byte{0xE3, 1, 2, 3}, false)
	f.Fuzz(func(t *testing.T, data []byte, isEncrypted bool) {
		if isEncrypted {
			data = encrypt(data, user[:], []byte{magicServer}, keyPart[:])
		}
		if conn, err := OpenOutgoing(&peerConn{r: bytes.NewReader(data)}, user, keyPart); err == nil {
			readAll(conn)
		}
	})
}

func FuzzOpenServer(f *testing.F) {
	secret := [16]byte{9, 8, 7, 6, 5, 4, 3, 2, 1}
	public := new(big.Int).Exp(big.NewInt(2), big.NewInt(12345), dhPrime).FillBytes(make([]byte, primeSize))
	answer := func(padding int, payload []byte) []byte {
		b := binary.LittleEndian.AppendUint32(nil, magicSync)
		b = append(b, methodObfuscation, methodObfuscation, byte(padding))
		b = append(b, make([]byte, padding)...)
		return append(b, payload...)
	}
	f.Add(public, answer(0, nil), true)
	f.Add(public, answer(16, []byte{0xE3, 5, 0, 0, 0, 0x34, 1, 0, 0, 0}), true)
	f.Add(make([]byte, primeSize), []byte{1, 2, 3}, false)
	f.Fuzz(func(t *testing.T, public, rest []byte, isEncrypted bool) {
		data := append(append([]byte(nil), public...), rest...)
		if isEncrypted && len(public) == primeSize {
			shared := new(big.Int).Exp(new(big.Int).SetBytes(public), new(big.Int).SetBytes(secret[:]), dhPrime).FillBytes(make([]byte, primeSize))
			data = append(append([]byte(nil), public...), encrypt(rest, shared, []byte{magicServer})...)
		}
		if conn, err := OpenServer(&peerConn{r: bytes.NewReader(data)}, secret, 0x10); err == nil {
			readAll(conn)
		}
	})
}
