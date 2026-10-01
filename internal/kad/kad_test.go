package kad

import (
	"bytes"
	"context"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/clock"
	"github.com/XiaoYouChR/Kelpie/internal/store"
	"github.com/XiaoYouChR/Kelpie/internal/transport"
	"github.com/XiaoYouChR/Kelpie/internal/wire"
	kadwire "github.com/XiaoYouChR/Kelpie/internal/wire/kad"
)

// startKad runs k until the test ends.
func startKad(t *testing.T, k *Kad) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- k.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Run: %v", err)
		}
	})
}

// waitParked waits until every one of n tickers is parked on the clock,
// so the next Advance never runs ahead of a Kad still busy with a tick.
func waitParked(t *testing.T, clk *clock.Fake, n int) {
	deadline := time.Now().Add(5 * time.Second)
	for clk.Waiters() < n {
		if time.Now().After(deadline) {
			t.Fatal("Kad never waited on its ticker")
		}
		runtime.Gosched()
	}
}

func readFrom(t *testing.T, conn transport.PacketConn) (netip.AddrPort, []byte) {
	t.Helper()
	got := make(chan Datagram, 1)
	go func() {
		buf := make([]byte, 2048)
		n, from, err := conn.ReadFrom(buf)
		if err == nil {
			got <- Datagram{Addr: from, Data: buf[:n]}
		}
	}()
	select {
	case d := <-got:
		return d.Addr, d.Data
	case <-time.After(5 * time.Second):
		t.Fatal("no datagram arrived")
		return netip.AddrPort{}, nil
	}
}

func TestKadSharesItsSocketWithTheEngine(t *testing.T) {
	network := transport.BuildNetwork()
	kadHost := network.AddHost(netip.MustParseAddr("10.0.0.1"))
	peerHost := network.AddHost(netip.MustParseAddr("10.0.0.2"))
	clk := clock.BuildFake(start)
	k := BuildKad(Config{Transport: kadHost, Clock: clk, Port: 4672, TCPPort: 4662, UserHash: userHash})
	startKad(t, k)
	waitParked(t, clk, 1)
	peer, err := peerHost.OpenUDP(4672)
	if err != nil {
		t.Fatal(err)
	}
	kadAddr := netip.MustParseAddrPort("10.0.0.1:4672")

	reask := []byte{wire.ProtocolEMule, 0x90, 1, 2, 3}
	peer.WriteTo(reask, kadAddr)
	select {
	case d := <-k.Received():
		if d.Addr != netip.MustParseAddrPort("10.0.0.2:4672") || !bytes.Equal(d.Data, reask) {
			t.Fatalf("forwarded %+v", d)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("eD2k datagram not forwarded to the engine")
	}

	k.Send(Datagram{Addr: netip.MustParseAddrPort("10.0.0.2:4672"), Data: []byte{wire.ProtocolEMule, 0x91}})
	if from, data := readFrom(t, peer); from != kadAddr || !bytes.Equal(data, []byte{wire.ProtocolEMule, 0x91}) {
		t.Fatalf("engine datagram arrived as %v %x", from, data)
	}

	peer.WriteTo(wire.BuildPacketDatagram(nil, kadwire.Ping{}), kadAddr)
	_, data := readFrom(t, peer)
	if p, ok := parsePacket(data); !ok || p != (kadwire.Pong{UDPPort: 4672}) {
		t.Fatalf("Kad answered a ping with %x", data)
	}
	select {
	case d := <-k.Received():
		t.Fatalf("Kad datagram forwarded to the engine: %+v", d)
	default:
	}

	k.RequestCallback(Callback{Buddy: netip.MustParseAddrPort("10.0.0.2:4672"), BuddyID: fileHash, Hash: fileHash})
	if _, data := readFrom(t, peer); len(data) != 36 || data[0] != wire.ProtocolKad || data[1] != (kadwire.CallbackReq{}).Opcode() {
		t.Fatalf("callback request %x", data)
	}
}

func TestKadNetworkFindsPublishedSource(t *testing.T) {
	const count = 5
	network := transport.BuildNetwork()
	clk := clock.BuildFake(start)
	rng := rand.New(rand.NewPCG(9, 9))
	var kads []*Kad
	var addrs []netip.Addr
	var seed Node
	for i := range count {
		id := fileHash
		for j := 2; j < len(id); j++ {
			id[j] = byte(rng.UintN(256))
		}
		var user wire.Hash
		user[0], user[15] = 0xEE, byte(i)
		addr := netip.MustParseAddr(fmt.Sprintf("10.0.1.%d", i+1))
		cfg := Config{
			Transport: network.AddHost(addr), Clock: clk, Port: 4672, TCPPort: 4662, UserHash: user,
			State: store.Kad{ID: id}, Rand: rand.New(rand.NewPCG(uint64(i), 5)),
		}
		if i == 0 {
			seed = Node{ID: id, Addr: netip.AddrPortFrom(addr, 4672), Version: kadwire.Version}
		} else {
			cfg.Nodes = []Node{seed}
		}
		k := BuildKad(cfg)
		startKad(t, k)
		kads = append(kads, k)
		addrs = append(addrs, addr)
	}
	waitParked(t, clk, count)

	publisher, searcher := kads[1], kads[count-1]
	publisher.SetWanted(Wanted{Publish: []Publish{{Hash: fileHash, Size: 1000}}})
	want := Source{Type: SourceOpen, UserHash: publisher.cfg.UserHash, Addr: netip.AddrPortFrom(addrs[1], 4662), UDPPort: 4672, CryptOptions: connectOptions}
	for step := 0; ; step++ {
		// A search finding nothing waits an hour to ask again, so search
		// only once the publisher has had time to publish.
		if step == 300 {
			searcher.SetWanted(Wanted{Find: []Search{{Hash: fileHash, Size: 1000}}})
		}
		if step == 600 {
			t.Fatal("searcher never found the publisher")
		}
		// Every node's engine passes every TCP firewall check it is asked
		// for; Kad counts only the nodes it asked.
		for i, k := range kads {
			for j, addr := range addrs {
				if i != j {
					k.SendFirewallAck(addr)
				}
			}
		}
		clk.Advance(time.Second)
		waitParked(t, clk, count)
		time.Sleep(time.Millisecond)
		select {
		case f := <-searcher.Found():
			if f.Hash != fileHash || len(f.Sources) != 1 || f.Sources[0] != want {
				t.Fatalf("found %+v, want %+v", f, want)
			}
			status := <-searcher.Statuses()
			if status.Nodes < 2 || status.IsFirewalled {
				t.Fatalf("searcher status %+v", status)
			}
			state := searcher.State()
			if state.ID == (wire.Hash{}) || len(state.Nodes) < 2 || state.IsFirewalled {
				t.Fatalf("searcher state %+v", state)
			}
			return
		default:
		}
	}
}
