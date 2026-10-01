package engine

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/wire"
)

// openRaw opens a TCP connection from a new host at ip to n, for tests that
// write bytes no well-behaved client would.
func (w *world) openRaw(ip string, n *node) net.Conn {
	w.t.Helper()
	host := w.network.AddHost(netip.MustParseAddr(ip))
	w.t.Cleanup(host.Close)
	conn, err := host.OpenTCP(context.Background(), n.endpoint())
	if err != nil {
		w.t.Fatal(err)
	}
	return conn
}

// requireClosed reads conn until the engine closes it.
func requireClosed(t *testing.T, conn net.Conn) {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(waitTimeout))
	if _, err := io.Copy(io.Discard, conn); err != nil {
		t.Fatalf("connection not closed by the engine: %v", err)
	}
}

func TestOversizedFrameClosesConnection(t *testing.T) {
	w := buildWorld(t)
	b := w.addNode("198.51.100.2")
	b.start()
	conn := w.openRaw("198.51.100.9", b)
	head := []byte{wire.ProtocolEDonkey, 0, 0, 0, 0, 0x01}
	binary.LittleEndian.PutUint32(head[1:5], wire.MaxFrameSize+1)
	conn.Write(head)
	requireClosed(t, conn)
}
