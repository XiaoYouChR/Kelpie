package transport

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

// socksServer is a SOCKS5 Proxy on loopback, enough of RFC 1928 and 1929 to
// test the client against: CONNECT dials for real, UDP ASSOCIATE relays.
type socksServer struct {
	t               *testing.T
	listener        net.Listener
	user, password  string
	connectReply    byte
	isUDPRefused    bool
	isRelayWildcard bool
	relays          chan *net.UDPConn
	controls        chan net.Conn
	lastClient      chan netip.AddrPort
}

func startSocksServer(t *testing.T, configure func(*socksServer)) *socksServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &socksServer{
		t: t, listener: listener,
		relays: make(chan *net.UDPConn, 4), controls: make(chan net.Conn, 4), lastClient: make(chan netip.AddrPort, 16),
	}
	if configure != nil {
		configure(s)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go s.serve(conn)
		}
	}()
	return s
}

func (s *socksServer) url(scheme string) string {
	u := scheme + "://"
	if s.user != "" {
		u += s.user + ":" + s.password + "@"
	}
	return u + s.listener.Addr().String()
}

func (s *socksServer) serve(conn net.Conn) {
	var greeting [2]byte
	if _, err := io.ReadFull(conn, greeting[:]); err != nil {
		conn.Close()
		return
	}
	methods := make([]byte, greeting[1])
	io.ReadFull(conn, methods)
	if s.user == "" {
		conn.Write([]byte{5, 0})
	} else {
		conn.Write([]byte{5, 2})
		var head [2]byte
		io.ReadFull(conn, head[:])
		user := make([]byte, head[1])
		io.ReadFull(conn, user)
		var n [1]byte
		io.ReadFull(conn, n[:])
		password := make([]byte, n[0])
		io.ReadFull(conn, password)
		if string(user) != s.user || string(password) != s.password {
			conn.Write([]byte{1, 1})
			conn.Close()
			return
		}
		conn.Write([]byte{1, 0})
	}
	var request [4]byte
	if _, err := io.ReadFull(conn, request[:]); err != nil {
		conn.Close()
		return
	}
	size := 4
	if request[3] == atypIPv6 {
		size = 16
	}
	body := make([]byte, size+2)
	io.ReadFull(conn, body)
	ip, _ := netip.AddrFromSlice(body[:size])
	target := netip.AddrPortFrom(ip, binary.BigEndian.Uint16(body[size:]))
	switch request[1] {
	case cmdConnect:
		s.connect(conn, target)
	case cmdAssociate:
		s.associate(conn)
	}
}

func (s *socksServer) reply(conn net.Conn, code byte, bound netip.AddrPort) {
	conn.Write(append([]byte{5, code, 0}, buildAddr(bound)...))
}

func (s *socksServer) connect(conn net.Conn, target netip.AddrPort) {
	if s.connectReply != replySucceeded {
		s.reply(conn, s.connectReply, netip.AddrPortFrom(netip.IPv4Unspecified(), 0))
		conn.Close()
		return
	}
	upstream, err := net.Dial("tcp", target.String())
	if err != nil {
		s.reply(conn, replyRefused, netip.AddrPortFrom(netip.IPv4Unspecified(), 0))
		conn.Close()
		return
	}
	s.reply(conn, replySucceeded, upstream.LocalAddr().(*net.TCPAddr).AddrPort())
	go func() { io.Copy(upstream, conn); upstream.Close() }()
	io.Copy(conn, upstream)
	conn.Close()
}

func (s *socksServer) associate(conn net.Conn) {
	if s.isUDPRefused {
		s.reply(conn, replyNotSupported, netip.AddrPortFrom(netip.IPv4Unspecified(), 0))
		conn.Close()
		return
	}
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		s.t.Error(err)
		return
	}
	bound := relay.LocalAddr().(*net.UDPAddr).AddrPort()
	if s.isRelayWildcard {
		bound = netip.AddrPortFrom(netip.IPv4Unspecified(), bound.Port())
	}
	s.reply(conn, replySucceeded, bound)
	s.relays <- relay
	s.controls <- conn
	go func() {
		io.Copy(io.Discard, conn)
		relay.Close()
	}()
	// The first sender is the client; everyone else is a target replying.
	var client netip.AddrPort
	buf := make([]byte, 2048)
	for {
		n, from, err := relay.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		if !client.IsValid() {
			client = from
			s.lastClient <- client
		}
		if from != client {
			relay.WriteToUDPAddrPort(append(append([]byte{0, 0, 0}, buildAddr(from)...), buf[:n]...), client)
			continue
		}
		if target, payload, ok := parseRelayed(buf[:n]); ok {
			relay.WriteToUDPAddrPort(payload, target)
		}
	}
}

func startEcho(t *testing.T, network string, addr netip.Addr) netip.AddrPort {
	t.Helper()
	if network == "udp" {
		conn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(addr, 0)))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		go func() {
			buf := make([]byte, 2048)
			for {
				n, from, err := conn.ReadFromUDPAddrPort(buf)
				if err != nil {
					return
				}
				conn.WriteToUDPAddrPort(buf[:n], from)
			}
		}()
		return conn.LocalAddr().(*net.UDPAddr).AddrPort()
	}
	listener, err := net.ListenTCP("tcp", net.TCPAddrFromAddrPort(netip.AddrPortFrom(addr, 0)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(conn, conn); conn.Close() }()
		}
	}()
	return listener.Addr().(*net.TCPAddr).AddrPort()
}

// openProxied opens a Proxied Transport that retries quickly and records
// the issues it reports.
func openProxied(t *testing.T, proxyURL string) (Transport, chan string) {
	t.Helper()
	issues := make(chan string, 16)
	p, err := Proxied(Real{}, proxyURL, func(issue string) { issues <- issue })
	if err != nil {
		t.Fatal(err)
	}
	p.(*proxy).retryMin, p.(*proxy).retryMax = 20*time.Millisecond, 40*time.Millisecond
	return p, issues
}

func waitIssue(t *testing.T, issues chan string, want string) {
	t.Helper()
	timeout := time.After(5 * time.Second)
	for {
		select {
		case got := <-issues:
			if got == want {
				return
			}
		case <-timeout:
			t.Fatalf("no issue %q", want)
		}
	}
}

func TestProxiedConnectReachesIPv4AndIPv6Targets(t *testing.T) {
	s := startSocksServer(t, func(s *socksServer) { s.user, s.password = "kelpie", "secret" })
	targets := []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	if l, err := net.Listen("tcp6", "[::1]:0"); err == nil {
		l.Close()
		targets = append(targets, netip.IPv6Loopback())
	}
	p, _ := openProxied(t, s.url("socks5"))
	for _, addr := range targets {
		conn, err := p.OpenTCP(context.Background(), startEcho(t, "tcp", addr))
		if err != nil {
			t.Fatalf("%s: %v", addr, err)
		}
		conn.Write([]byte("hello"))
		got := make([]byte, 5)
		if _, err := io.ReadFull(conn, got); err != nil || string(got) != "hello" {
			t.Fatalf("%s: echo %q, %v", addr, got, err)
		}
		conn.Close()
	}
}

func TestProxiedFailuresSayWhoseFaultItIs(t *testing.T) {
	target := startEcho(t, "tcp", netip.MustParseAddr("127.0.0.1"))
	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	closedURL := "socks5://" + closed.Addr().String()
	closed.Close()
	wrongPassword := startSocksServer(t, func(s *socksServer) { s.user, s.password = "kelpie", "secret" })
	cases := map[string]struct {
		proxyURL               string
		isProxyDown, isRefused bool
	}{
		"proxy unreachable":  {closedURL, true, false},
		"wrong password":     {"socks5://kelpie:wrong@" + wrongPassword.listener.Addr().String(), true, false},
		"target refused":     {startSocksServer(t, func(s *socksServer) { s.connectReply = replyRefused }).url("socks5"), false, true},
		"target unreachable": {startSocksServer(t, func(s *socksServer) { s.connectReply = replyHostUnreachable }).url("socks5"), false, true},
		"ruleset forbids":    {startSocksServer(t, func(s *socksServer) { s.connectReply = 2 }).url("socks5"), false, false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			p, issues := openProxied(t, c.proxyURL)
			_, err := p.OpenTCP(context.Background(), target)
			if err == nil {
				t.Fatal("connected")
			}
			if isProxyDown(err) != c.isProxyDown || IsRefused(err) != c.isRefused {
				t.Fatalf("%v: isProxyDown %v, IsRefused %v", err, isProxyDown(err), IsRefused(err))
			}
			if c.isProxyDown {
				waitIssue(t, issues, issueUnreachable)
			}
		})
	}
}

func TestProxiedConnectGivesUpWithItsContext(t *testing.T) {
	silent, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	go func() {
		conn, err := silent.Accept()
		if err == nil {
			defer conn.Close()
			io.Copy(io.Discard, conn)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	p, _ := openProxied(t, "socks5://"+silent.Addr().String())
	_, err = p.OpenTCP(ctx, netip.MustParseAddrPort("127.0.0.1:1"))
	if !isProxyDown(err) {
		t.Fatalf("err %v", err)
	}
}

func TestProxiedUDPRoundTrip(t *testing.T) {
	for name, isWildcard := range map[string]bool{"relay address": false, "unspecified relay": true} {
		t.Run(name, func(t *testing.T) {
			s := startSocksServer(t, func(s *socksServer) { s.isRelayWildcard = isWildcard })
			p, _ := openProxied(t, s.url("socks5"))
			conn, err := p.OpenUDP(0)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			echo := startEcho(t, "udp", netip.MustParseAddr("127.0.0.1"))
			if _, err := conn.WriteTo([]byte("ping"), echo); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 64)
			n, from, err := conn.ReadFrom(buf)
			if err != nil || string(buf[:n]) != "ping" || from != echo {
				t.Fatalf("read %q from %s: %v", buf[:n], from, err)
			}
		})
	}
}

func TestRelayConnHearsOnlyWellFormedRelayedDatagrams(t *testing.T) {
	s := startSocksServer(t, nil)
	p, _ := openProxied(t, s.url("socks5"))
	conn, err := p.OpenUDP(0)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	relay := <-s.relays
	client := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(conn.Port()))
	stranger, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer stranger.Close()
	source := buildAddr(netip.MustParseAddrPort("192.0.2.1:4672"))
	stranger.WriteToUDPAddrPort(append(append([]byte{0, 0, 0}, source...), "direct"...), client)
	relay.WriteToUDPAddrPort(append(append([]byte{0, 0, 1}, source...), "fragment"...), client)
	relay.WriteToUDPAddrPort([]byte{0, 0, 0, atypIPv4, 1}, client)
	relay.WriteToUDPAddrPort(append([]byte{0, 0, 0, atypDomain, 3, 'a', 'b', 'c', 0, 1}, "named"...), client)
	conn.WriteTo([]byte("hello"), startEcho(t, "udp", netip.MustParseAddr("127.0.0.1")))
	buf := make([]byte, 64)
	n, _, err := conn.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "hello" {
		t.Fatalf("heard %q: %v", buf[:n], err)
	}
}

func TestUDPWithoutAssociateDropsAndReportsNoUDP(t *testing.T) {
	s := startSocksServer(t, func(s *socksServer) { s.isUDPRefused = true })
	p, issues := openProxied(t, s.url("socks5"))
	conn, err := p.OpenUDP(0)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	waitIssue(t, issues, issueNoUDP)
	if n, err := conn.WriteTo([]byte("lost"), netip.MustParseAddrPort("127.0.0.1:9")); n != 4 || err != nil {
		t.Fatalf("write %d %v", n, err)
	}
	conn.Close()
	waitIssue(t, issues, "")
}

func TestAssociationComesBackAfterItsControlConnectionCloses(t *testing.T) {
	s := startSocksServer(t, nil)
	p, issues := openProxied(t, s.url("socks5"))
	conn, err := p.OpenUDP(0)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	<-s.relays
	(<-s.controls).Close()
	waitIssue(t, issues, issueNoUDP)
	waitIssue(t, issues, "")
	echo := startEcho(t, "udp", netip.MustParseAddr("127.0.0.1"))
	deadline := time.Now().Add(5 * time.Second)
	reads := make(chan string, 1)
	go func() {
		buf := make([]byte, 64)
		if n, _, err := conn.ReadFrom(buf); err == nil {
			reads <- string(buf[:n])
		}
	}()
	for time.Now().Before(deadline) {
		conn.WriteTo([]byte("again"), echo)
		select {
		case got := <-reads:
			if got != "again" {
				t.Fatalf("read %q", got)
			}
			return
		case <-time.After(50 * time.Millisecond):
		}
	}
	t.Fatal("no datagram after associating again")
}

func TestProxiedSchemes(t *testing.T) {
	for _, bad := range []string{"http://127.0.0.1:8080", "socks4://127.0.0.1:1080", "socks5://", "socks5://host:99999"} {
		if _, err := Proxied(Real{}, bad, func(string) {}); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	remote, _ := openProxied(t, "socks5h://127.0.0.1:1080")
	if _, err := remote.LookupHost(context.Background(), "localhost"); err == nil {
		t.Error("socks5h resolved a name locally")
	}
	local, _ := openProxied(t, "socks5://127.0.0.1:1080")
	if addrs, err := local.LookupHost(context.Background(), "localhost"); err != nil || len(addrs) == 0 {
		t.Errorf("socks5 lookup: %v %v", addrs, err)
	}
}

func TestBuildAddrRoundTripsThroughParseRelayed(t *testing.T) {
	for _, addr := range []netip.AddrPort{
		netip.MustParseAddrPort("192.0.2.7:4662"),
		netip.MustParseAddrPort("[2001:db8::7]:4672"),
	} {
		datagram := append(append([]byte{0, 0, 0}, buildAddr(addr)...), "x"...)
		got, payload, ok := parseRelayed(datagram)
		if !ok || got != addr || !bytes.Equal(payload, []byte("x")) {
			t.Errorf("%s: %s %q %v", addr, got, payload, ok)
		}
	}
}
