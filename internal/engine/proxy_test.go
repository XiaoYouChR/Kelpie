package engine

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"testing/synctest"

	"github.com/XiaoYouChR/Kelpie/internal/transport"
	"github.com/XiaoYouChR/Kelpie/internal/wire"
	kadwire "github.com/XiaoYouChR/Kelpie/internal/wire/kad"
)

const proxyPort = 1080

// startSocks runs a SOCKS5 Proxy at ip on the fake network: CONNECT, and
// UDP ASSOCIATE unless isUDPRefused. It returns the Proxy URL.
func (w *world) startSocks(ip string, isUDPRefused bool) string {
	addr := netip.MustParseAddr(ip)
	host := w.network.AddHost(addr)
	listener, err := host.OpenListener(proxyPort)
	if err != nil {
		w.t.Fatal(err)
	}
	w.t.Cleanup(host.Close)
	go func() {
		for {
			conn, _, err := listener.Accept()
			if err != nil {
				return
			}
			go serveSocks(host, conn, addr, isUDPRefused)
		}
	}()
	return "socks5://" + netip.AddrPortFrom(addr, proxyPort).String()
}

func serveSocks(host *transport.Host, conn net.Conn, addr netip.Addr, isUDPRefused bool) {
	var greeting [3]byte
	io.ReadFull(conn, greeting[:])
	conn.Write([]byte{5, 0})
	var request [10]byte
	if _, err := io.ReadFull(conn, request[:]); err != nil || request[3] != 1 {
		conn.Close()
		return
	}
	ip, _ := netip.AddrFromSlice(request[4:8])
	target := netip.AddrPortFrom(ip, binary.BigEndian.Uint16(request[8:]))
	reply := func(code byte, bound netip.AddrPort) {
		b := append([]byte{5, code, 0, 1}, bound.Addr().AsSlice()...)
		conn.Write(binary.BigEndian.AppendUint16(b, bound.Port()))
	}
	none := netip.AddrPortFrom(netip.IPv4Unspecified(), 0)
	switch {
	case request[1] == 1:
		upstream, err := host.OpenTCP(context.Background(), target)
		if err != nil {
			reply(5, none)
			conn.Close()
			return
		}
		reply(0, none)
		go func() { io.Copy(upstream, conn); upstream.Close() }()
		io.Copy(conn, upstream)
		conn.Close()
	case isUDPRefused:
		reply(7, none)
		conn.Close()
	default:
		relay, err := host.OpenUDP(0)
		if err != nil {
			conn.Close()
			return
		}
		reply(0, netip.AddrPortFrom(addr, uint16(relay.Port())))
		go func() { io.Copy(io.Discard, conn); relay.Close() }()
		var client netip.AddrPort
		buf := make([]byte, 65536)
		for {
			n, from, err := relay.ReadFrom(buf)
			if err != nil {
				return
			}
			if !client.IsValid() {
				client = from
			}
			if from != client {
				header := append([]byte{0, 0, 0, 1}, from.Addr().AsSlice()...)
				relay.WriteTo(append(binary.BigEndian.AppendUint16(header, from.Port()), buf[:n]...), client)
				continue
			}
			if n < 10 || buf[3] != 1 {
				continue
			}
			ip, _ := netip.AddrFromSlice(buf[4:8])
			relay.WriteTo(buf[10:n], netip.AddrPortFrom(ip, binary.BigEndian.Uint16(buf[8:10])))
		}
	}
}

// kadWitness is a scripted Kad node that answers a bootstrap and records
// the address of everyone who sent it a datagram.
type kadWitness struct {
	node    kadNode
	mu      sync.Mutex
	senders []netip.Addr
}

func (w *world) startKadWitness(ip string) *kadWitness {
	addr := netip.MustParseAddr(ip)
	conn, err := w.network.AddHost(addr).OpenUDP(kadPort)
	if err != nil {
		w.t.Fatal(err)
	}
	id := wire.Hash{0x5A, addr.As4()[3]}
	k := &kadWitness{node: kadNode{id: id, addr: netip.AddrPortFrom(addr, kadPort), version: guideVersion}}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 65536)
		for {
			n, from, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			k.mu.Lock()
			k.senders = append(k.senders, from.Addr())
			k.mu.Unlock()
			frame, err := wire.ParseDatagram(buf[:n])
			if err != nil {
				continue
			}
			p, _ := kadwire.Parse(frame.Protocol, frame.Opcode, frame.Body)
			var reply wire.Packet
			switch p.(type) {
			case kadwire.BootstrapReq:
				reply = kadwire.BootstrapRes{ID: id, TCPPort: peerPort, Version: guideVersion}
			case kadwire.HelloReq:
				reply = kadwire.HelloRes{ID: id, TCPPort: peerPort, Version: guideVersion}
			case kadwire.Ping:
				reply = kadwire.Pong{UDPPort: from.Port()}
			}
			if reply != nil {
				conn.WriteTo(reply.Build(nil), from)
			}
		}
	}()
	w.t.Cleanup(func() {
		conn.Close()
		wg.Wait()
	})
	return k
}

// sendersSince returns who sent datagrams from the i-th on.
func (k *kadWitness) sendersSince(i int) []netip.Addr {
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([]netip.Addr(nil), k.senders[min(i, len(k.senders)):]...)
}

// TestKadGoesOnlyThroughTheProxy: with a Proxy set at start, every Kad
// datagram the witness hears comes from the Proxy, none from the node.
func TestKadGoesOnlyThroughTheProxy(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		w := buildWorld(t)
		witness := w.startKadWitness("198.51.100.9")
		b := w.addNode("198.51.100.2")
		b.setKad(wire.Hash{0x41}, witness.node)
		b.config.Proxy = w.startSocks("203.0.113.5", false)
		b.start()
		w.waitFor("b to learn the witness through the Proxy", func() bool { return b.events.lastNetwork().KadNodes > 0 })
		for _, from := range witness.sendersSince(0) {
			if from != netip.MustParseAddr("203.0.113.5") {
				t.Fatalf("witness heard %s", from)
			}
		}
		if issue := b.events.lastNetwork().ProxyIssue; issue != "" {
			t.Fatalf("proxyIssue %q", issue)
		}
	})
}

// TestSettingAProxyMovesKadAtOnce: a Proxy set while running moves Kad's
// UDP to it; after the first datagram through the Proxy, none comes direct.
func TestSettingAProxyMovesKadAtOnce(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		w := buildWorld(t)
		witness := w.startKadWitness("198.51.100.9")
		b := w.addNode("198.51.100.2")
		b.setKad(wire.Hash{0x41}, witness.node)
		proxy := netip.MustParseAddr("203.0.113.5")
		url := w.startSocks(proxy.String(), false)
		b.start()
		w.waitFor("the witness to hear b directly", func() bool { return len(witness.sendersSince(0)) > 0 })

		b.engine.Post(Settings{EnableKad: true, Proxy: url})
		first := -1
		w.waitFor("the witness to hear b through the Proxy", func() bool {
			for i, from := range witness.sendersSince(0) {
				if from == proxy {
					first = i
					return true
				}
			}
			return false
		})
		w.waitFor("Kad to keep talking", func() bool { return len(witness.sendersSince(first)) > 3 })
		for _, from := range witness.sendersSince(first) {
			if from != proxy {
				t.Fatalf("witness heard %s after the Proxy took over", from)
			}
		}
	})
}

// TestProxyWithoutUDPKeepsKadQuietAndSaysWhy: a Proxy that relays no UDP
// leaves Kad silent rather than direct, and Network names the issue.
func TestProxyWithoutUDPKeepsKadQuietAndSaysWhy(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		w := buildWorld(t)
		witness := w.startKadWitness("198.51.100.9")
		b := w.addNode("198.51.100.2")
		b.setKad(wire.Hash{0x41}, witness.node)
		b.config.Proxy = w.startSocks("203.0.113.5", true)
		b.start()
		w.waitFor("Network to name the issue", func() bool { return b.events.lastNetwork().ProxyIssue == "noUdp" })
		if heard := witness.sendersSince(0); len(heard) > 0 {
			t.Fatalf("witness heard %v", heard)
		}
	})
}
