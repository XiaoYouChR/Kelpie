package nat

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"
)

var testTiming = timing{lifetime: time.Second, retry: 50 * time.Millisecond, window: 400 * time.Millisecond, minWait: 100 * time.Millisecond}

type pcpRequest struct {
	version  byte
	op       string // "map:TCP:4662" or "external"
	lifetime uint32
	clientIP netip.Addr
	nonce    [12]byte
	suggest  uint16
}

// fakePCP answers PCP and NAT-PMP like a home gateway would.
type fakePCP struct {
	t        *testing.T
	conn     *net.UDPConn
	speaksV2 bool   // false answers PCP with NAT-PMP's UNSUPP_VERSION
	result   byte   // PCP result code for MAP requests
	external string // reported external IPv4

	mu       sync.Mutex
	requests []pcpRequest
}

func newFakePCP(t *testing.T, network, address string, setups ...func(*fakePCP)) *fakePCP {
	conn, err := net.ListenUDP(network, net.UDPAddrFromAddrPort(netip.MustParseAddrPort(address)))
	if err != nil {
		t.Skipf("listen %s: %v", address, err)
	}
	f := &fakePCP{t: t, conn: conn, speaksV2: true, external: "203.0.113.9"}
	for _, setup := range setups {
		setup(f)
	}
	t.Cleanup(func() { conn.Close() })
	go f.serve()
	return f
}

func (f *fakePCP) route() route {
	return route{gateway: f.conn.LocalAddr().(*net.UDPAddr).AddrPort()}
}

func (f *fakePCP) serve() {
	buffer := make([]byte, maxPCPLen)
	for {
		n, from, err := f.conn.ReadFromUDPAddrPort(buffer)
		if err != nil {
			return
		}
		if reply := f.answer(buffer[:n], from.Addr()); reply != nil {
			f.conn.WriteToUDPAddrPort(reply, from)
		}
	}
}

func toProtocolName(number byte) string {
	if number == 6 {
		return "TCP"
	}
	return "UDP"
}

func (f *fakePCP) answer(packet []byte, from netip.Addr) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case packet[0] == pcpVersion && !f.speaksV2:
		f.requests = append(f.requests, pcpRequest{version: pcpVersion, op: "rejected"})
		return []byte{0, 0, 0, 1, 0, 0, 0, 0}
	case packet[0] == pcpVersion:
		r := pcpRequest{
			version:  pcpVersion,
			op:       fmt.Sprintf("map:%s:%d", toProtocolName(packet[36]), binary.BigEndian.Uint16(packet[40:42])),
			lifetime: binary.BigEndian.Uint32(packet[4:8]),
			clientIP: netip.AddrFrom16([16]byte(packet[8:24])).Unmap(),
			nonce:    [12]byte(packet[24:36]),
			suggest:  binary.BigEndian.Uint16(packet[42:44]),
		}
		f.requests = append(f.requests, r)
		reply := make([]byte, 60)
		copy(reply[24:], packet[24:60])
		reply[0], reply[1], reply[3] = pcpVersion, isResponse|pcpOpMap, f.result
		if r.clientIP != from.Unmap().WithZone("") {
			reply[3] = 12 // ADDRESS_MISMATCH
		}
		binary.BigEndian.PutUint32(reply[4:], r.lifetime)
		external := netip.MustParseAddr(f.external).As16()
		if r.clientIP.Is6() {
			external = r.clientIP.As16()
		}
		copy(reply[44:], external[:])
		return reply
	case packet[0] == pmpVersion && packet[1] == 0:
		f.requests = append(f.requests, pcpRequest{op: "external"})
		reply := []byte{0, isResponse, 0, 0, 0, 0, 0, 0}
		ip := netip.MustParseAddr(f.external).As4()
		return append(reply, ip[:]...)
	case packet[0] == pmpVersion:
		protocol := "UDP"
		if packet[1] == 2 {
			protocol = "TCP"
		}
		r := pcpRequest{
			op:       fmt.Sprintf("map:%s:%d", protocol, binary.BigEndian.Uint16(packet[4:6])),
			lifetime: binary.BigEndian.Uint32(packet[8:12]),
			suggest:  binary.BigEndian.Uint16(packet[6:8]),
		}
		f.requests = append(f.requests, r)
		reply := make([]byte, 16)
		reply[0], reply[1] = 0, isResponse|packet[1]
		copy(reply[8:10], packet[4:6])
		copy(reply[10:12], packet[4:6])
		copy(reply[12:16], packet[8:12])
		return reply
	}
	return nil
}

func (f *fakePCP) snapshot() []pcpRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.requests)
}

func (f *fakePCP) ops() []string {
	var ops []string
	for _, r := range f.snapshot() {
		op := r.op
		if r.op != "external" && r.op != "rejected" && r.lifetime == 0 {
			op = "delete:" + op
		}
		ops = append(ops, op)
	}
	return ops
}

func (f *fakePCP) countOf(op string, lifetime uint32) int {
	count := 0
	for _, r := range f.snapshot() {
		if r.op == op && r.lifetime == lifetime {
			count++
		}
	}
	return count
}

func waitFor(t *testing.T, what string, condition func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if condition() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

func refuseUPnP(t *testing.T) func(context.Context) []string {
	return func(context.Context) []string {
		t.Error("UPnP was tried")
		return nil
	}
}

func TestOpenMapsWithPCPRefreshesAndCloseDeletes(t *testing.T) {
	gateway := newFakePCP(t, "udp4", "127.0.0.1:0")

	closeMappings, external, err := openWith(context.Background(), gateway.route(), route{}, refuseUPnP(t), 4662, 4672, "Kelpie", testTiming)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if want := netip.MustParseAddr("203.0.113.9"); external != want {
		t.Fatalf("external = %v, want %v", external, want)
	}
	if got, want := gateway.ops(), []string{"map:TCP:4662", "map:UDP:4672"}; !slices.Equal(got, want) {
		t.Fatalf("ops = %v, want %v", got, want)
	}

	waitFor(t, "refresh", func() bool {
		return gateway.countOf("map:TCP:4662", 1) >= 2 && gateway.countOf("map:UDP:4672", 1) >= 2
	})
	requests := gateway.snapshot()
	for _, r := range requests {
		if r.version != pcpVersion || r.clientIP != netip.MustParseAddr("127.0.0.1") || r.nonce != requests[0].nonce {
			t.Errorf("unexpected request %+v", r)
		}
		if r.op == "map:TCP:4662" && r.suggest != 4662 {
			t.Errorf("suggested external port = %d", r.suggest)
		}
	}

	if err := closeMappings(context.Background()); err != nil {
		t.Fatalf("close: %v", err)
	}
	ops := gateway.ops()
	if got, want := ops[len(ops)-2:], []string{"delete:map:TCP:4662", "delete:map:UDP:4672"}; !slices.Equal(got, want) {
		t.Fatalf("last ops = %v, want %v", got, want)
	}
	time.Sleep(700 * time.Millisecond)
	if got := len(gateway.ops()); got != len(ops) {
		t.Fatalf("%d requests after close", got-len(ops))
	}
}

func TestOpenFallsBackToNATPMP(t *testing.T) {
	gateway := newFakePCP(t, "udp4", "127.0.0.1:0", func(f *fakePCP) {
		f.speaksV2 = false
		f.external = "198.51.100.4"
	})

	closeMappings, external, err := openWith(context.Background(), gateway.route(), route{}, refuseUPnP(t), 4662, 4672, "Kelpie", testTiming)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if want := netip.MustParseAddr("198.51.100.4"); external != want {
		t.Fatalf("external = %v, want %v", external, want)
	}
	want := []string{"rejected", "map:TCP:4662", "external", "map:UDP:4672", "external"}
	if got := gateway.ops(); !slices.Equal(got, want) {
		t.Fatalf("ops = %v, want %v", got, want)
	}
	waitFor(t, "refresh", func() bool { return gateway.countOf("map:UDP:4672", 1) >= 2 })

	if err := closeMappings(context.Background()); err != nil {
		t.Fatalf("close: %v", err)
	}
	ops := gateway.ops()
	if got, want := ops[len(ops)-2:], []string{"delete:map:TCP:4662", "delete:map:UDP:4672"}; !slices.Equal(got, want) {
		t.Fatalf("last ops = %v, want %v", got, want)
	}
	for _, r := range gateway.snapshot() {
		if r.lifetime == 0 && r.op != "external" && r.suggest != 0 {
			t.Errorf("NAT-PMP delete suggests external port %d", r.suggest)
		}
	}
}

func TestOpenFallsBackToUPnPWhenGatewayIsSilent(t *testing.T) {
	silent, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	upnp := newFakeGateway(t, igdV1Description, "/ctl/IPConn")
	probeUPnP := func(context.Context) []string { return []string{upnp.location()} }

	started := time.Now()
	closeMappings, external, err := openWith(context.Background(), route{gateway: silent.LocalAddr().(*net.UDPAddr).AddrPort()}, route{}, probeUPnP, 4662, 4672, "Kelpie", testTiming)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Errorf("fallback took %v", elapsed)
	}
	if want := netip.MustParseAddr("203.0.113.7"); external != want {
		t.Fatalf("external = %v, want %v", external, want)
	}
	if err := closeMappings(context.Background()); err != nil {
		t.Fatalf("close: %v", err)
	}
	want := []string{"add:TCP:4662", "add:UDP:4672", "delete:TCP:4662", "delete:UDP:4672"}
	if got := upnp.actions(); !slices.Equal(got, want) {
		t.Fatalf("actions = %v, want %v", got, want)
	}
}

func TestOpenFallsBackToUPnPWhenPCPRefuses(t *testing.T) {
	gateway := newFakePCP(t, "udp4", "127.0.0.1:0", func(f *fakePCP) { f.result = 2 }) // NOT_AUTHORIZED
	upnp := newFakeGateway(t, igdV1Description, "/ctl/IPConn")
	probeUPnP := func(context.Context) []string { return []string{upnp.location()} }

	if _, _, err := openWith(context.Background(), gateway.route(), route{}, probeUPnP, 4662, 0, "Kelpie", testTiming); err != nil {
		t.Fatalf("open: %v", err)
	}
	if got, want := upnp.actions(), []string{"add:TCP:4662"}; !slices.Equal(got, want) {
		t.Fatalf("actions = %v, want %v", got, want)
	}
}

func TestOpenWithoutAnyGatewayFails(t *testing.T) {
	_, _, err := openWith(context.Background(), route{}, route{}, func(context.Context) []string { return nil }, 4662, 4672, "Kelpie", testTiming)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestOpenMapsIPv6PinholeWithPCP(t *testing.T) {
	gateway6 := newFakePCP(t, "udp6", "[::1]:0")
	route6 := gateway6.route()
	route6.local = netip.MustParseAddr("::1")

	closeMappings, external, err := openWith(context.Background(), route{}, route6, func(context.Context) []string { return nil }, 4662, 4672, "Kelpie", testTiming)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if external.IsValid() {
		t.Fatalf("external = %v, want zero Addr", external)
	}
	for _, r := range gateway6.snapshot() {
		if r.clientIP != netip.MustParseAddr("::1") {
			t.Errorf("client IP = %v", r.clientIP)
		}
	}
	if err := closeMappings(context.Background()); err != nil {
		t.Fatalf("close: %v", err)
	}
	ops := gateway6.ops()
	if got, want := ops[len(ops)-2:], []string{"delete:map:TCP:4662", "delete:map:UDP:4672"}; !slices.Equal(got, want) {
		t.Fatalf("last ops = %v, want %v", got, want)
	}
}

func TestOpenMapsIPv4AndIPv6Together(t *testing.T) {
	gateway4 := newFakePCP(t, "udp4", "127.0.0.1:0")
	gateway6 := newFakePCP(t, "udp6", "[::1]:0")
	route6 := gateway6.route()
	route6.local = netip.MustParseAddr("::1")

	closeMappings, external, err := openWith(context.Background(), gateway4.route(), route6, refuseUPnP(t), 4662, 0, "Kelpie", testTiming)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if want := netip.MustParseAddr("203.0.113.9"); external != want {
		t.Fatalf("external = %v, want %v", external, want)
	}
	if err := closeMappings(context.Background()); err != nil {
		t.Fatalf("close: %v", err)
	}
	for name, gateway := range map[string]*fakePCP{"v4": gateway4, "v6": gateway6} {
		if got := gateway.ops(); got[0] != "map:TCP:4662" || got[len(got)-1] != "delete:map:TCP:4662" {
			t.Errorf("%s ops = %v", name, got)
		}
	}
}

func TestParseProcRoute(t *testing.T) {
	text := `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
wlan0	00000000	FE01A8C0	0003	0	0	600	00000000	0	0	0
eth0	00000000	0101A8C0	0003	0	0	100	00000000	0	0	0
eth0	0001A8C0	00000000	0001	0	0	100	00FFFFFF	0	0	0
`
	ip, err := parseProcRoute(text)
	if err != nil || ip != netip.MustParseAddr("192.168.1.1") {
		t.Fatalf("got %v, %v", ip, err)
	}
	if _, err := parseProcRoute("Iface\tDestination\n"); err == nil {
		t.Fatal("expected error")
	}
}

func TestParseProcIPv6Route(t *testing.T) {
	text := `20010db8000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001 eth0
00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000002 00000000 00450003 eth0
00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200 lo
`
	ip, err := parseProcIPv6Route(text)
	if err != nil || ip != netip.MustParseAddr("fe80::1%eth0") {
		t.Fatalf("got %v, %v", ip, err)
	}
}

func TestParseRouteGet(t *testing.T) {
	text := `   route to: ::
destination: ::
       mask: default
    gateway: fe80::1%en5
  interface: en5
`
	ip, err := parseRouteGet(text)
	if err != nil || ip != netip.MustParseAddr("fe80::1%en5") {
		t.Fatalf("got %v, %v", ip, err)
	}
	if _, err := parseRouteGet("route: writing to routing socket: not in table\n"); err == nil {
		t.Fatal("expected error")
	}
}
