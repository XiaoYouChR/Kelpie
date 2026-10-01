// Package obfuscation is eMule's protocol obfuscation for TCP connections
// between clients: an RC4 stream keyed by the receiving client's user hash.
// Clients that require it close a plain connection as soon as our Hello
// arrives; on the real network those were the fastest sources of a hot file.
package obfuscation

import (
	"bufio"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"errors"
	"io"
	"net"

	"github.com/XiaoYouChR/Kelpie/internal/wire"
)

const (
	// MAGICVALUE_REQUESTER and MAGICVALUE_SERVER salt the key of each
	// direction; MAGICVALUE_SYNC opens the encrypted handshake.
	magicRequester byte   = 34
	magicServer    byte   = 203
	magicSync      uint32 = 0x835E6FC4
	// methodObfuscation is ENM_OBFUSCATION, the only method eMule defines.
	methodObfuscation byte = 0x00
	// rc4Discard is how much keystream eMule throws away after keying.
	rc4Discard = 1024
)

var ErrHandshake = errors.New("obfuscation: bad handshake")

// Conn encrypts what it writes and decrypts what it reads. Read and Write
// may run on different goroutines.
type Conn struct {
	net.Conn
	r    io.Reader
	in   *rc4.Cipher
	out  *rc4.Cipher
	wbuf []byte
}

func (c *Conn) Read(b []byte) (int, error) {
	n, err := c.r.Read(b)
	c.in.XORKeyStream(b[:n], b[:n])
	return n, err
}

func (c *Conn) Write(b []byte) (int, error) {
	c.wbuf = append(c.wbuf[:0], b...)
	c.out.XORKeyStream(c.wbuf, c.wbuf)
	return c.Conn.Write(c.wbuf)
}

// readAnswer reads <MagicValue 4><MethodSelected 1><PaddingLen 1><Padding>.
func (c *Conn) readAnswer() error {
	var head [6]byte
	if _, err := io.ReadFull(c.r, head[:]); err != nil {
		return err
	}
	c.in.XORKeyStream(head[:], head[:])
	if binary.LittleEndian.Uint32(head[:]) != magicSync || head[4] != methodObfuscation {
		return ErrHandshake
	}
	return c.discard(int(head[5]))
}

func (c *Conn) discard(n int) error {
	padding := make([]byte, n)
	if _, err := io.ReadFull(c.r, padding); err != nil {
		return err
	}
	c.in.XORKeyStream(padding, padding)
	return nil
}

func buildCipher(user wire.Hash, magic byte, keyPart [4]byte) *rc4.Cipher {
	sum := md5.Sum(append(append(user[:], magic), keyPart[:]...))
	c, _ := rc4.NewCipher(sum[:])
	discard := make([]byte, rc4Discard)
	c.XORKeyStream(discard, discard)
	return c
}

// matchPlain tells whether the first byte of a connection starts a plain
// eD2k frame.
func matchPlain(b byte) bool {
	return b == wire.ProtocolEDonkey || b == wire.ProtocolEMule || b == wire.ProtocolPacked
}

// OpenOutgoing starts obfuscation on a connection we opened to the client
// with user hash user. keyPart is random; it salts both keys. It blocks
// until the peer has answered, as eMule holds its Hello until then (aMule
// drops a peer that sends more than the handshake step needs): the caller
// sets a deadline.
//
// Request: <Marker 1><KeyPart 4>, then encrypted <MagicValue 4>
// <MethodsSupported 1><MethodPreferred 1><PaddingLen 1>.
func OpenOutgoing(conn net.Conn, user wire.Hash, keyPart [4]byte) (*Conn, error) {
	c := &Conn{
		Conn: conn,
		r:    bufio.NewReader(conn),
		in:   buildCipher(user, magicServer, keyPart),
		out:  buildCipher(user, magicRequester, keyPart),
	}
	marker := keyPart[0] ^ keyPart[3]
	for matchPlain(marker) {
		marker++
	}
	request := binary.LittleEndian.AppendUint32(nil, magicSync)
	request = append(request, methodObfuscation, methodObfuscation, 0)
	c.out.XORKeyStream(request, request)
	if _, err := conn.Write(append(append([]byte{marker}, keyPart[:]...), request...)); err != nil {
		return nil, err
	}
	if err := c.readAnswer(); err != nil {
		return nil, err
	}
	return c, nil
}

// OpenIncoming reads the first byte of a connection a peer opened to us,
// whose user hash is self. A plain eD2k frame is returned as it came; an
// obfuscation request is answered and the encrypted Conn returned. It blocks
// until the peer has sent its handshake: the caller sets a deadline.
func OpenIncoming(conn net.Conn, self wire.Hash) (net.Conn, error) {
	r := bufio.NewReader(conn)
	first, err := r.Peek(1)
	if err != nil {
		return nil, err
	}
	if matchPlain(first[0]) {
		return &plainConn{Conn: conn, r: r}, nil
	}
	var head [1 + 4 + 7]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, err
	}
	keyPart := [4]byte(head[1:5])
	c := &Conn{
		Conn: conn,
		r:    r,
		in:   buildCipher(self, magicRequester, keyPart),
		out:  buildCipher(self, magicServer, keyPart),
	}
	request := head[5:]
	c.in.XORKeyStream(request, request)
	// request[4] lists the methods the peer supports, request[5] its
	// preferred one; obfuscation is the only method and always supported.
	if binary.LittleEndian.Uint32(request) != magicSync {
		return nil, ErrHandshake
	}
	if err := c.discard(int(request[6])); err != nil {
		return nil, err
	}
	answer := binary.LittleEndian.AppendUint32(nil, magicSync)
	answer = append(answer, methodObfuscation, 0)
	if _, err := c.Write(answer); err != nil {
		return nil, err
	}
	return c, nil
}

// plainConn gives back the byte OpenIncoming peeked at.
type plainConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *plainConn) Read(b []byte) (int, error) { return c.r.Read(b) }
