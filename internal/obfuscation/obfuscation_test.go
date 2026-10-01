package obfuscation

import (
	"bytes"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"encoding/hex"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/wire"
)

var user = wire.Hash{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}

// buildPair is a loopback TCP connection: unlike net.Pipe it buffers, as the
// handshake expects.
func buildPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	a, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	b, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close(); b.Close() })
	return a, b
}

// The expected bytes were computed by an independent RC4 and MD5 following
// eMule's EncryptedStreamSocket description; aMule clients that require
// obfuscation accepted this handshake on the real network.
func TestOutgoingRequestBytes(t *testing.T) {
	a, b := buildPair(t)
	go OpenOutgoing(a, user, [4]byte{1, 2, 3, 4})
	got := make([]byte, 12)
	if _, err := io.ReadFull(b, got); err != nil {
		t.Fatal(err)
	}
	if matchPlain(got[0]) || !bytes.Equal(got[1:5], []byte{1, 2, 3, 4}) {
		t.Fatalf("head %x", got[:5])
	}
	if want := "1716dcbe604f14"; hex.EncodeToString(got[5:]) != want {
		t.Fatalf("request %x, want %s", got[5:], want)
	}
}

func TestIncomingAnswerBytes(t *testing.T) {
	a, b := buildPair(t)
	request, _ := hex.DecodeString("11010203041716dcbe604f14")
	a.Write(request)
	if _, err := OpenIncoming(b, user); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 6)
	if _, err := io.ReadFull(a, got); err != nil {
		t.Fatal(err)
	}
	if want := "a3fb30fc2126"; hex.EncodeToString(got) != want {
		t.Fatalf("answer %x, want %s", got, want)
	}
}

func TestRoundTrip(t *testing.T) {
	a, b := buildPair(t)
	incoming := make(chan net.Conn)
	go func() {
		c, err := OpenIncoming(b, user)
		if err != nil {
			t.Error(err)
		}
		incoming <- c
	}()
	out, err := OpenOutgoing(a, user, [4]byte{9, 8, 7, 6})
	if err != nil {
		t.Fatal(err)
	}
	in := <-incoming
	if _, ok := in.(*cipherConn); !ok {
		t.Fatalf("incoming is %T", in)
	}
	hello := wire.BuildFrame(nil, wire.ProtocolEDonkey, 0x01, []byte("hello"))
	out.Write(hello)
	got := make([]byte, len(hello))
	if _, err := io.ReadFull(in, got); err != nil || !bytes.Equal(got, hello) {
		t.Fatalf("incoming read %x %v", got, err)
	}
	in.Write([]byte("answer"))
	got = make([]byte, 6)
	if _, err := io.ReadFull(out, got); err != nil || string(got) != "answer" {
		t.Fatalf("outgoing read %q %v", got, err)
	}
}

func TestIncomingPlainPassesThrough(t *testing.T) {
	a, b := buildPair(t)
	hello := wire.BuildFrame(nil, wire.ProtocolEDonkey, 0x01, []byte("hello"))
	a.Write(hello)
	in, err := OpenIncoming(b, user)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(hello))
	if _, err := io.ReadFull(in, got); err != nil || !bytes.Equal(got, hello) {
		t.Fatalf("read %x %v", got, err)
	}
}

func TestWrongUserHashFails(t *testing.T) {
	a, b := buildPair(t)
	go OpenOutgoing(a, wire.Hash{1}, [4]byte{1, 2, 3, 4})
	if _, err := OpenIncoming(b, user); err != errHandshake {
		t.Fatalf("err %v", err)
	}
}

// eMule holds its Hello until the peer answered; aMule drops a peer that
// sends more than a handshake step needs.
func TestOutgoingWaitsForAnswer(t *testing.T) {
	a, b := buildPair(t)
	opened := make(chan error)
	go func() {
		_, err := OpenOutgoing(a, user, [4]byte{1, 2, 3, 4})
		opened <- err
	}()
	io.ReadFull(b, make([]byte, 12))
	select {
	case err := <-opened:
		t.Fatalf("returned before the answer: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	answer, _ := hex.DecodeString("a3fb30fc2126")
	b.Write(answer)
	if err := <-opened; err != nil {
		t.Fatal(err)
	}
}

func TestOutgoingRejectsBadAnswer(t *testing.T) {
	a, b := buildPair(t)
	go func() {
		io.ReadFull(b, make([]byte, 12))
		b.Write([]byte{1, 2, 3, 4, 5, 6})
	}()
	if _, err := OpenOutgoing(a, user, [4]byte{1, 2, 3, 4}); err != errHandshake {
		t.Fatalf("err %v", err)
	}
}

// aMule pads its answer with up to 128 random bytes, and a peer may send
// payload right behind it (aMule accepts that on a connection it opened).
func TestOutgoingReadsPaddedAnswerAndPayload(t *testing.T) {
	a, b := buildPair(t)
	keyPart := [4]byte{1, 2, 3, 4}
	go func() {
		io.ReadFull(b, make([]byte, 12))
		answer := binary.LittleEndian.AppendUint32(nil, magicSync)
		answer = append(answer, methodObfuscation, 3, 7, 7, 7)
		answer = append(answer, "data"...)
		buildCipher(user[:], []byte{magicServer}, keyPart[:]).XORKeyStream(answer, answer)
		b.Write(answer)
	}()
	out, err := OpenOutgoing(a, user, keyPart)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(out, got); err != nil || string(got) != "data" {
		t.Fatalf("read %q %v", got, err)
	}
}

// The side that accepted sends its answer and then nothing until the
// peer's first packet, as eMule does.
func TestIncomingSendsOnlyTheAnswer(t *testing.T) {
	a, b := buildPair(t)
	request, _ := hex.DecodeString("11010203041716dcbe604f14")
	a.Write(request)
	if _, err := OpenIncoming(b, user); err != nil {
		t.Fatal(err)
	}
	a.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	got, _ := io.ReadAll(a)
	if len(got) != 6 {
		t.Fatalf("sent %d bytes, want the 6-byte answer", len(got))
	}
}

// TestServerHandshake plays the server side with its own Diffie-Hellman,
// following aMule's EncryptedStreamSocket description: the prime is typed
// in again here, so a wrong byte on either side fails.
func TestServerHandshake(t *testing.T) {
	prime, _ := new(big.Int).SetString("F2BF52C55F587ADD5371A936E886EB3C6217A33EC34CB40DC73A41A643AFFCE7"+
		"21FC286366535BDBCE259F2286DA4A91B207CBAA5255D4F61CCEAED45AD5E0747DF7781828105F340F762387F88B2891"+
		"42FB42688F05150F548B5F436AF70DF3", 16)
	secret := [16]byte{0x9A, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 0xFF}
	b := big.NewInt(0x1234567890ABCDEF)
	clientSide, serverSide := buildPair(t)
	opened := make(chan net.Conn)
	go func() {
		c, err := OpenServer(clientSide, secret, wire.ProtocolEDonkey)
		if err != nil {
			t.Error(err)
		}
		opened <- c
	}()

	request := make([]byte, 98)
	if _, err := io.ReadFull(serverSide, request); err != nil {
		t.Fatal(err)
	}
	if matchPlain(request[0]) || request[97] != 0 {
		t.Fatalf("marker %#x, padding %d", request[0], request[97])
	}
	gA := new(big.Int).SetBytes(request[1:97])
	if want := new(big.Int).Exp(big.NewInt(2), new(big.Int).SetBytes(secret[:]), prime); gA.Cmp(want) != 0 {
		t.Fatalf("g^a = %x, want %x", gA, want)
	}
	shared := make([]byte, 97)
	new(big.Int).Exp(gA, b, prime).FillBytes(shared[:96])
	key := func(magic byte) *rc4.Cipher {
		shared[96] = magic
		sum := md5.Sum(shared)
		c, _ := rc4.NewCipher(sum[:])
		drop := make([]byte, 1024)
		c.XORKeyStream(drop, drop)
		return c
	}
	send, receive := key(203), key(34)
	answer := make([]byte, 96, 96+9)
	new(big.Int).Exp(big.NewInt(2), b, prime).FillBytes(answer)
	tail := binary.LittleEndian.AppendUint32(nil, 0x835E6FC4)
	tail = append(tail, 0, 0, 2, 0xEE, 0xEE)
	send.XORKeyStream(tail, tail)
	serverSide.Write(append(answer, tail...))

	reply := make([]byte, 6)
	if _, err := io.ReadFull(serverSide, reply); err != nil {
		t.Fatal(err)
	}
	receive.XORKeyStream(reply, reply)
	if binary.LittleEndian.Uint32(reply) != 0x835E6FC4 || reply[4] != 0 || reply[5] != 0 {
		t.Fatalf("reply %x", reply)
	}
	c := <-opened
	c.Write([]byte("login"))
	got := make([]byte, 5)
	io.ReadFull(serverSide, got)
	receive.XORKeyStream(got, got)
	if string(got) != "login" {
		t.Fatalf("client sent %q", got)
	}
	idChange := []byte("id")
	send.XORKeyStream(idChange, idChange)
	serverSide.Write(idChange)
	io.ReadFull(c, got[:2])
	if string(got[:2]) != "id" {
		t.Fatalf("client read %q", got[:2])
	}
}

func TestServerHandshakeRejectsBadMagic(t *testing.T) {
	clientSide, serverSide := buildPair(t)
	go func() {
		io.ReadFull(serverSide, make([]byte, 98))
		serverSide.Write(make([]byte, 96+7))
	}()
	clientSide.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := OpenServer(clientSide, [16]byte{1}, 0x55); err != errHandshake {
		t.Fatalf("err = %v, want errHandshake", err)
	}
}
