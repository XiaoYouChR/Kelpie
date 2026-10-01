package obfuscation

import (
	"bytes"
	"encoding/hex"
	"io"
	"net"
	"testing"

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
	OpenOutgoing(a, user, [4]byte{1, 2, 3, 4})
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
	if _, ok := in.(*Conn); !ok {
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
	OpenOutgoing(a, wire.Hash{1}, [4]byte{1, 2, 3, 4})
	if _, err := OpenIncoming(b, user); err != ErrHandshake {
		t.Fatalf("err %v", err)
	}
}
