package transport

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"
)

var (
	v4a = netip.MustParseAddr("10.0.0.1")
	v4b = netip.MustParseAddr("10.0.0.2")
	v6a = netip.MustParseAddr("2001:db8::1")
	v6b = netip.MustParseAddr("2001:db8::2")
)

type pair struct {
	server, client Transport
	serverAddr     netip.Addr
}

func buildPairs(t *testing.T) map[string]pair {
	network := BuildNetwork()
	server := network.AddHost(v4a, v6a)
	client := network.AddHost(v4b, v6b)
	pairs := map[string]pair{
		"fake/v4": {server, client, v4a},
		"fake/v6": {server, client, v6a},
		"real/v4": {Real{}, Real{}, netip.MustParseAddr("127.0.0.1")},
	}
	if l, err := net.Listen("tcp6", "[::1]:0"); err == nil {
		l.Close()
		pairs["real/v6"] = pair{Real{}, Real{}, netip.IPv6Loopback()}
	} else {
		t.Logf("no IPv6 loopback: %v", err)
	}
	return pairs
}

func TestTCPContract(t *testing.T) {
	for name, p := range buildPairs(t) {
		t.Run(name, func(t *testing.T) {
			listener, err := p.server.OpenListener(0)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			accepted := make(chan net.Conn, 1)
			go func() {
				c, err := listener.Accept()
				if err != nil {
					t.Error(err)
				}
				accepted <- c
			}()
			client, err := p.client.OpenTCP(context.Background(), netip.AddrPortFrom(p.serverAddr, uint16(listener.Port())))
			if err != nil {
				t.Fatal(err)
			}
			server := <-accepted
			peer := server.RemoteAddr().(*net.TCPAddr).AddrPort()
			if peer.Addr().Unmap().Is4() != p.serverAddr.Is4() {
				t.Fatalf("peer %v has the wrong family", peer)
			}
			if _, err := client.Write([]byte("hello")); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, 5)
			if _, err := io.ReadFull(server, got); err != nil || string(got) != "hello" {
				t.Fatalf("read %q %v", got, err)
			}
			client.Close()
			if _, err := server.Read(got); err != io.EOF {
				t.Fatalf("want EOF after peer close, got %v", err)
			}
			server.Close()
		})
	}
}

func TestUDPContract(t *testing.T) {
	for name, p := range buildPairs(t) {
		t.Run(name, func(t *testing.T) {
			server, err := p.server.OpenUDP(0)
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			client, err := p.client.OpenUDP(0)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if _, err := client.WriteTo([]byte("ping"), netip.AddrPortFrom(p.serverAddr, uint16(server.Port()))); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 64)
			n, from, err := server.ReadFrom(buf)
			if err != nil || string(buf[:n]) != "ping" {
				t.Fatalf("read %q %v", buf[:n], err)
			}
			if from.Addr().Is4() != p.serverAddr.Is4() || from.Addr().Is4In6() || int(from.Port()) != client.Port() {
				t.Fatalf("sender %v", from)
			}
			if _, err := server.WriteTo([]byte("pong"), from); err != nil {
				t.Fatal(err)
			}
			n, _, err = client.ReadFrom(buf)
			if err != nil || string(buf[:n]) != "pong" {
				t.Fatalf("reply %q %v", buf[:n], err)
			}
		})
	}
}

func TestPacketConnCloseUnblocksRead(t *testing.T) {
	for name, p := range buildPairs(t) {
		t.Run(name, func(t *testing.T) {
			conn, err := p.server.OpenUDP(0)
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error)
			go func() {
				_, _, err := conn.ReadFrom(make([]byte, 1))
				done <- err
			}()
			conn.Close()
			if err := <-done; !errors.Is(err, net.ErrClosed) {
				t.Fatalf("want closed, got %v", err)
			}
		})
	}
}

func dialErrno(t *testing.T, from *Host, to netip.AddrPort) error {
	t.Helper()
	conn, err := from.OpenTCP(context.Background(), to)
	if err == nil {
		conn.Close()
	}
	return err
}

func TestFakeDialFailures(t *testing.T) {
	network := BuildNetwork()
	server := network.AddHost(v4a)
	client := network.AddHost(v4b, v6b)
	onlyV6 := network.AddHost(v6a)
	listener, _ := server.OpenListener(4662)
	defer listener.Close()
	target := netip.AddrPortFrom(v4a, 4662)

	if err := dialErrno(t, client, netip.AddrPortFrom(v4a, 4663)); !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("closed port: %v", err)
	}
	if err := dialErrno(t, client, netip.AddrPortFrom(netip.MustParseAddr("10.9.9.9"), 1)); !errors.Is(err, syscall.EHOSTUNREACH) {
		t.Fatalf("unknown host: %v", err)
	}
	if err := dialErrno(t, onlyV6, target); !errors.Is(err, syscall.ENETUNREACH) {
		t.Fatalf("no IPv4 address: %v", err)
	}

	server.SetUnreachable(true)
	if err := dialErrno(t, client, target); !errors.Is(err, syscall.EHOSTUNREACH) {
		t.Fatalf("unreachable: %v", err)
	}
	server.SetUnreachable(false)

	server.SetLowID(true)
	if err := dialErrno(t, client, target); !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("LowID: %v", err)
	}
	if err := dialErrno(t, server, netip.AddrPortFrom(v4b, 1)); !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("LowID dialing out to a closed port: %v", err)
	}
	server.SetLowID(false)

	if err := dialErrno(t, client, netip.AddrPortFrom(netip.AddrFrom16(v4a.As16()), 4662)); err != nil {
		t.Fatalf("IPv4-mapped address: %v", err)
	}
	if _, err := server.OpenListener(4662); !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("port in use: %v", err)
	}
}

func TestFakeLowIDHostCanDialOut(t *testing.T) {
	network := BuildNetwork()
	lowID := network.AddHost(v4a)
	highID := network.AddHost(v4b)
	lowID.SetLowID(true)
	listener, _ := highID.OpenListener(4662)
	defer listener.Close()
	if err := dialErrno(t, lowID, netip.AddrPortFrom(v4b, 4662)); err != nil {
		t.Fatal(err)
	}
}

func TestFakeUnreachableDropsDatagrams(t *testing.T) {
	network := BuildNetwork()
	a := network.AddHost(v4a)
	b := network.AddHost(v4b)
	sa, _ := a.OpenUDP(4672)
	sb, _ := b.OpenUDP(4672)
	b.SetUnreachable(true)
	if _, err := sa.WriteTo([]byte("lost"), netip.AddrPortFrom(v4b, 4672)); err != nil {
		t.Fatal(err)
	}
	b.SetUnreachable(false)
	sa.WriteTo([]byte("kept"), netip.AddrPortFrom(v4b, 4672))
	buf := make([]byte, 8)
	n, _, _ := sb.ReadFrom(buf)
	if string(buf[:n]) != "kept" {
		t.Fatalf("got %q", buf[:n])
	}
}

func TestFakeHostCloseClosesEverything(t *testing.T) {
	network := BuildNetwork()
	server := network.AddHost(v4a)
	client := network.AddHost(v4b)
	listener, _ := server.OpenListener(4662)
	socket, _ := server.OpenUDP(4672)
	conn, err := client.OpenTCP(context.Background(), netip.AddrPortFrom(v4a, 4662))
	if err != nil {
		t.Fatal(err)
	}
	accepted, _ := listener.Accept()

	server.Close()
	if _, err := listener.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("accept: %v", err)
	}
	if _, _, err := socket.ReadFrom(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("udp: %v", err)
	}
	if _, err := accepted.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("own conn: %v", err)
	}
	if _, err := conn.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("peer conn: %v", err)
	}
	if _, err := conn.Write([]byte("x")); err == nil {
		t.Fatal("wrote to a closed peer")
	}
	if err := dialErrno(t, client, netip.AddrPortFrom(v4a, 4662)); !errors.Is(err, syscall.EHOSTUNREACH) {
		t.Fatalf("dial closed host: %v", err)
	}
}

func createConnPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	network := BuildNetwork()
	server := network.AddHost(v4a)
	client := network.AddHost(v4b)
	listener, _ := server.OpenListener(4662)
	t.Cleanup(func() { listener.Close() })
	conn, err := client.OpenTCP(context.Background(), netip.AddrPortFrom(v4a, 4662))
	if err != nil {
		t.Fatal(err)
	}
	accepted, _ := listener.Accept()
	t.Cleanup(func() { conn.Close(); accepted.Close() })
	return conn, accepted
}

func TestFakeBothSidesWriteBeforeReading(t *testing.T) {
	a, b := createConnPair(t)
	payload := bytes.Repeat([]byte("x"), 100<<10)
	var wg sync.WaitGroup
	for _, c := range []net.Conn{a, b} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.Write(payload); err != nil {
				t.Error(err)
			}
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, payload) {
				t.Errorf("read %d bytes: %v", len(got), err)
			}
		}()
	}
	wg.Wait()
}

func TestFakeWriterBlocksWhenPeerFallsBehind(t *testing.T) {
	a, b := createConnPair(t)
	a.SetWriteDeadline(time.Now().Add(20 * time.Millisecond))
	n, err := a.Write(make([]byte, pipeBufferSize+1))
	if !errors.Is(err, os.ErrDeadlineExceeded) || n != pipeBufferSize {
		t.Fatalf("wrote %d: %v", n, err)
	}
	a.SetWriteDeadline(time.Time{})
	done := make(chan error)
	go func() {
		_, err := a.Write([]byte("more"))
		done <- err
	}()
	io.ReadFull(b, make([]byte, 1<<10))
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestFakeReadDeadline(t *testing.T) {
	a, _ := createConnPair(t)
	a.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	if _, err := a.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("want deadline, got %v", err)
	}
}

func TestFakeIsRaceFree(t *testing.T) {
	network := BuildNetwork()
	server := network.AddHost(v4a, v6a)
	listener, _ := server.OpenListener(4662)
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				io.Copy(c, c)
				c.Close()
			}()
		}
	}()
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client := network.AddHost(netip.AddrFrom4([4]byte{10, 1, 0, byte(i)}))
			conn, err := client.OpenTCP(context.Background(), netip.AddrPortFrom(v4a, 4662))
			if err != nil {
				t.Error(err)
				return
			}
			go conn.Write(bytes.Repeat([]byte{byte(i)}, 4096))
			io.ReadFull(conn, make([]byte, 4096))
			client.Close()
		}()
	}
	wg.Wait()
	server.Close()
}

func TestLookupHost(t *testing.T) {
	network := BuildNetwork()
	host := network.AddHost(v4a)
	network.SetName("server.example", v4b)
	ctx := context.Background()
	if addrs, err := host.LookupHost(ctx, "server.example"); err != nil || len(addrs) != 1 || addrs[0] != v4b {
		t.Fatalf("fake lookup = %v, %v", addrs, err)
	}
	var dnsErr *net.DNSError
	if _, err := host.LookupHost(ctx, "missing.example"); !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
		t.Fatalf("missing name: %v", err)
	}
	addrs, err := Real{}.LookupHost(ctx, "localhost")
	if err != nil || len(addrs) == 0 || !addrs[0].Is4() || !addrs[0].IsLoopback() {
		t.Fatalf("real lookup of localhost = %v, %v", addrs, err)
	}
}
