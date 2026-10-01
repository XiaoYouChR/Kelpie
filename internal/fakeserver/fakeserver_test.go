package fakeserver_test

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/clock"
	"github.com/XiaoYouChR/Kelpie/internal/fakeserver"
	"github.com/XiaoYouChR/Kelpie/internal/server"
	"github.com/XiaoYouChR/Kelpie/internal/transport"
	"github.com/XiaoYouChR/Kelpie/internal/wire"
	packet "github.com/XiaoYouChR/Kelpie/internal/wire/server"
)

const peerPort = 4662

var (
	serverAddr = netip.MustParseAddrPort("10.0.0.1:4661")
	fileA      = wire.Hash{0xAA}
	fileB      = wire.Hash{0xBB}
)

func startServer(t *testing.T, network *transport.Network, config fakeserver.Config) *fakeserver.Server {
	t.Helper()
	if config.Transport == nil {
		config.Transport = network.AddHost(serverAddr.Addr())
	}
	if config.Clock == nil {
		config.Clock = clock.BuildFake(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	}
	if !config.Addr.IsValid() {
		config.Addr = serverAddr
	}
	s, err := fakeserver.Create(config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- s.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Run: %v", err)
		}
	})
	return s
}

// addPeer adds a host listening on peerPort; a LowID host refuses the
// server's connect-back.
func addPeer(t *testing.T, network *transport.Network, ip string, isLowID bool) *transport.Host {
	t.Helper()
	host := network.AddHost(netip.MustParseAddr(ip))
	host.SetLowID(isLowID)
	if _, err := host.OpenListener(peerPort); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(host.Close)
	return host
}

func login(t *testing.T, host *transport.Host, to netip.AddrPort) (net.Conn, packet.IDChange) {
	t.Helper()
	conn, err := host.OpenTCP(context.Background(), to)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	send(t, conn, packet.Login{UserHash: wire.Hash{0x55}, Port: peerPort, Name: "test", Flags: packet.CapSupportCrypt | packet.CapRequestCrypt})
	id := receive[packet.IDChange](t, conn)
	receive[packet.ServerStatus](t, conn)
	receive[packet.ServerIdent](t, conn)
	return conn, id
}

func send(t *testing.T, conn net.Conn, p wire.Packet) {
	t.Helper()
	if _, err := conn.Write(wire.BuildPacket(nil, p)); err != nil {
		t.Fatal(err)
	}
}

func receive[T wire.Packet](t *testing.T, conn net.Conn) T {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	frame, err := wire.ParseFrameFrom(conn)
	if err != nil {
		t.Fatal(err)
	}
	p, err := packet.Parse(frame.Protocol, frame.Opcode, frame.Body)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := p.(T)
	if !ok {
		t.Fatalf("got %T, want %T", p, got)
	}
	return got
}

func TestLoginGivesHighIDOnlyWhenReachable(t *testing.T) {
	network := transport.BuildNetwork()
	s := startServer(t, network, fakeserver.Config{Name: "fake"})
	_, high := login(t, addPeer(t, network, "10.0.0.2", false), s.Addr())
	if want := wire.ToClientID(netip.MustParseAddr("10.0.0.2")); high.ClientID != want {
		t.Errorf("reachable peer got id %#x, want %#x", high.ClientID, want)
	}
	if high.ReportedIP != netip.MustParseAddr("10.0.0.2") {
		t.Errorf("reported IP = %v", high.ReportedIP)
	}
	_, low1 := login(t, addPeer(t, network, "10.0.0.3", true), s.Addr())
	_, low2 := login(t, addPeer(t, network, "10.0.0.4", true), s.Addr())
	if !wire.IsLowID(low1.ClientID) || !wire.IsLowID(low2.ClientID) || low1.ClientID == low2.ClientID {
		t.Errorf("LowID peers got ids %#x and %#x", low1.ClientID, low2.ClientID)
	}
}

func TestDroppedLoginGetsNoAnswer(t *testing.T) {
	network := transport.BuildNetwork()
	s := startServer(t, network, fakeserver.Config{ShouldDropLogins: true})
	conn, err := addPeer(t, network, "10.0.0.2", false).OpenTCP(context.Background(), s.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	send(t, conn, packet.Login{Port: peerPort})
	conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, err := wire.ParseFrameFrom(conn); err == nil {
		t.Fatal("dropped login was answered")
	}
}

func TestOfferThenGetSources(t *testing.T) {
	network := transport.BuildNetwork()
	s := startServer(t, network, fakeserver.Config{})
	high, highID := login(t, addPeer(t, network, "10.0.0.2", false), s.Addr())
	low, lowID := login(t, addPeer(t, network, "10.0.0.3", true), s.Addr())
	asker, _ := login(t, addPeer(t, network, "10.0.0.4", false), s.Addr())

	send(t, high, packet.OfferFiles{Files: []packet.OfferedFile{{Hash: fileA, ClientID: packet.CompleteID, Port: packet.CompletePort}}})
	send(t, low, packet.OfferFiles{Files: []packet.OfferedFile{{Hash: fileA, ClientID: packet.IncompleteID, Port: packet.IncompletePort}}})
	// A round trip on each connection makes sure the offers were handled.
	send(t, high, packet.GetSources{Hash: fileB, Size: 1000})
	receive[packet.FoundSources](t, high)
	send(t, low, packet.GetSources{Hash: fileA, Size: 1000})
	if got := receive[packet.FoundSources](t, low); len(got.Sources) != 1 || got.Sources[0].ClientID != highID.ClientID {
		t.Fatalf("LowID peer's sources = %+v, want only the HighID peer", got.Sources)
	}

	send(t, asker, packet.GetSources{Hash: fileA, Size: 1000})
	got := receive[packet.FoundSources](t, asker)
	want := map[uint32]bool{highID.ClientID: true, lowID.ClientID: true}
	if got.Hash != fileA || len(got.Sources) != 2 {
		t.Fatalf("sources = %+v", got)
	}
	for _, src := range got.Sources {
		if !want[src.ClientID] || src.Port != peerPort {
			t.Errorf("unexpected source %+v", src)
		}
	}
}

func TestGlobalSourcesOverUDP(t *testing.T) {
	network := transport.BuildNetwork()
	s := startServer(t, network, fakeserver.Config{})
	high, highID := login(t, addPeer(t, network, "10.0.0.2", false), s.Addr())
	send(t, high, packet.OfferFiles{Files: []packet.OfferedFile{{Hash: fileA}, {Hash: fileB}}})
	send(t, high, packet.GetSources{Hash: fileA, Size: 1000})
	receive[packet.FoundSources](t, high)

	udp, err := addPeer(t, network, "10.0.0.5", true).OpenUDP(0)
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	serverUDP := netip.AddrPortFrom(s.Addr().Addr(), s.Addr().Port()+4)
	request := func(p wire.Packet) wire.Packet {
		t.Helper()
		if _, err := udp.WriteTo(wire.BuildPacketDatagram(nil, p), serverUDP); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 2048)
		n, from, err := udp.ReadFrom(buf)
		if err != nil || from != serverUDP {
			t.Fatalf("read from %v: %v", from, err)
		}
		frame, err := wire.ParseDatagram(buf[:n])
		if err != nil {
			t.Fatal(err)
		}
		reply, err := packet.ParseUDP(frame.Protocol, frame.Opcode, frame.Body)
		if err != nil {
			t.Fatal(err)
		}
		return reply
	}

	stat := request(packet.GlobServStatReq{Challenge: 0x55AA1234}).(packet.GlobServStatRes)
	if stat.Challenge != 0x55AA1234 || stat.Users != 1 || stat.Files != 2 || stat.UDPFlags&packet.UDPFlagGetSources2 == 0 {
		t.Errorf("status = %+v", stat)
	}
	found := request(packet.GlobGetSources2{Files: []packet.GetSources{{Hash: wire.Hash{0xCC}, Size: 1000}, {Hash: fileA, Size: 1000}, {Hash: fileB, Size: 1000}}}).(packet.GlobFoundSources)
	if len(found.Files) != 2 || found.Files[0].Hash != fileA || found.Files[1].Hash != fileB {
		t.Fatalf("found = %+v", found)
	}
	for _, f := range found.Files {
		if len(f.Sources) != 1 || f.Sources[0] != (packet.Source{ClientID: highID.ClientID, Port: peerPort}) {
			t.Errorf("sources of %v = %+v", f.Hash, f.Sources)
		}
	}
	found = request(packet.GlobGetSources{Files: []wire.Hash{fileB, {0xCC}}}).(packet.GlobFoundSources)
	if len(found.Files) != 1 || found.Files[0].Hash != fileB {
		t.Fatalf("found by hash alone = %+v", found)
	}
}

func TestCallbackRelay(t *testing.T) {
	network := transport.BuildNetwork()
	s := startServer(t, network, fakeserver.Config{})
	high, _ := login(t, addPeer(t, network, "10.0.0.2", false), s.Addr())
	low, lowID := login(t, addPeer(t, network, "10.0.0.3", true), s.Addr())

	send(t, high, packet.CallbackRequest{ClientID: lowID.ClientID})
	got := receive[packet.CallbackRequested](t, low)
	want := packet.CallbackRequested{Addr: netip.MustParseAddrPort("10.0.0.2:4662"), CryptOptions: 0x03, UserHash: wire.Hash{0x55}}
	if got != want {
		t.Errorf("callback = %+v, want %+v", got, want)
	}
	send(t, high, packet.CallbackRequest{ClientID: lowID.ClientID + 100})
	receive[packet.CallbackFailed](t, high)
}

func TestDelayHoldsAnswersOnClock(t *testing.T) {
	network := transport.BuildNetwork()
	fake := clock.BuildFake(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	s := startServer(t, network, fakeserver.Config{Clock: fake, Delay: 3 * time.Second})
	conn, err := addPeer(t, network, "10.0.0.2", false).OpenTCP(context.Background(), s.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	send(t, conn, packet.Login{Port: peerPort})
	for fake.Waiters() == 0 {
		time.Sleep(time.Millisecond)
	}
	conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	if _, err := wire.ParseFrameFrom(conn); err == nil {
		t.Fatal("answered before the delay")
	}
	fake.Advance(3 * time.Second)
	receive[packet.IDChange](t, conn)
}

func TestMetLoadsInServerList(t *testing.T) {
	network := transport.BuildNetwork()
	other := netip.MustParseAddrPort("10.0.0.9:4242")
	servers := []*fakeserver.Server{
		startServer(t, network, fakeserver.Config{}),
		startServer(t, network, fakeserver.Config{Transport: network.AddHost(other.Addr()), Addr: other, ObfuscationPort: 4246}),
	}
	entries, err := server.ParseMet(fakeserver.BuildMet(servers...))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries", len(entries))
	}
	for i, e := range entries {
		if e.Endpoint != servers[i].Addr() || e.UDPFlags&packet.UDPFlagGetSources2 == 0 || e.Name == "" {
			t.Errorf("entry %d = %+v", i, e)
		}
	}
	if e := entries[1]; e.TCPObfuscationPort != 4246 || e.UDPFlags&packet.UDPFlagTCPObfuscation == 0 {
		t.Errorf("obfuscating entry = %+v", e)
	}
}
