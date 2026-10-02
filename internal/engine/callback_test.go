package engine

import (
	"testing"

	"github.com/XiaoYouChR/Kelpie/internal/obfuscation"
	"github.com/XiaoYouChR/Kelpie/internal/peer"
	"github.com/XiaoYouChR/Kelpie/internal/wire"
	"github.com/XiaoYouChR/Kelpie/internal/wire/client"
)

// A LowID source whose Hello offers direct callbacks is asked over UDP, at
// its Kad port, to connect to us when its reask is due, with Kad off and
// the source on no server of ours (aMule BaseClient.cpp:1718-1747).
func TestLowIDSourceFromHelloIsCalledBackDirectly(t *testing.T) {
	w := buildWorld(t)
	srv := w.startFakeServer("198.51.100.100")
	b := w.addNode("198.51.100.2")
	b.setServer(srv)
	b.start()
	w.waitFor("server login", func() bool { return b.events.lastNetwork().IsHighID })
	f := buildTestFile("direct.bin", 100_000, 24)
	p := w.addScriptedPeer("198.51.100.5", f)
	p.cfg.ClientID, p.cfg.KadPort, p.cfg.HasDirectCallback = 1234, 4672, true
	udp, err := p.host.OpenUDP(int(p.cfg.KadPort))
	if err != nil {
		t.Fatal(err)
	}
	requests := make(chan wire.Packet, 1)
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			data := buf[:n]
			if plain, ok := obfuscation.ParsePeerDatagram(data, p.cfg.Self.UserHash, from.Addr()); ok {
				data = plain
			}
			frame, err := wire.ParseDatagram(data)
			if err != nil {
				continue
			}
			if packet, err := client.ParseUDP(frame.Protocol, frame.Opcode, frame.Body); err == nil {
				requests <- packet
				return
			}
		}
	}()

	b.download(1, f, p.endpoint())
	w.waitFor("B to queue on the peer", func() bool { return p.matchConn(0, hasEvent[peer.UploadRequested]) })
	p.closeConn(0)
	var request wire.Packet
	w.waitFor("a direct callback request", func() bool {
		select {
		case request = <-requests:
			return true
		default:
			return false
		}
	})
	if got, ok := request.(client.DirectCallbackReq); !ok || got.TCPPort != peerPort || got.UserHash != b.engine.self.UserHash {
		t.Fatalf("request %#v", request)
	}
	if p.connCount() != 1 {
		t.Fatalf("%d connections, want no dial to the LowID source", p.connCount())
	}
}
