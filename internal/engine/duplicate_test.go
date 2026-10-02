package engine

import (
	"bytes"
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/identity"
	"github.com/XiaoYouChR/Kelpie/internal/peer"
	"github.com/XiaoYouChR/Kelpie/internal/wire"
	"github.com/XiaoYouChR/Kelpie/internal/wire/client"
	kadwire "github.com/XiaoYouChR/Kelpie/internal/wire/kad"
)

func isClosed(c *scriptedConn) bool { return c.isClosed }

// A client that connects again from where it was keeps its new connection
// and the old one closes, as aMule's AttachToAlreadyKnown does: the old one
// may be dead without our knowing.
func TestReconnectedClientKeepsNewConnection(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		w := buildWorld(t)
		b := w.addNode("198.51.100.2")
		b.start()
		p := w.addScriptedPeer("198.51.100.5", buildTestFile("dup.bin", 100_000, 21))
		p.open(b)
		w.waitFor("the first handshake", func() bool { return p.matchConn(0, hasEvent[peer.HandshakeCompleted]) })
		p.open(b)
		w.waitFor("the old connection to close", func() bool { return p.matchConn(0, isClosed) })
		settle := w.clock.Now().Add(5 * time.Second)
		w.waitUntil(settle)
		if p.matchConn(1, isClosed) {
			t.Fatal("the new connection closed too")
		}
	})
}

// When both ends dial each other at once, both keep the connection the
// client with the smaller user hash opened, so they never close both.
func TestSimultaneousDialKeepsOneConnection(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		w := buildWorld(t)
		b := w.addNode("198.51.100.2")
		b.start()
		for i, isOursSmaller := range []bool{true, false} {
			f := buildTestFile("both.bin", 100_000, uint64(22+i))
			p := w.addScriptedPeer(fmt.Sprintf("198.51.100.%d", 5+i), f)
			for {
				self, other := b.engine.self.UserHash, p.cfg.Self.UserHash
				if bytes.Compare(self[:], other[:]) < 0 == isOursSmaller {
					break
				}
				var err error
				if p.cfg.Self, err = identity.CreateSelf(); err != nil {
					t.Fatal(err)
				}
			}
			b.download(RunID(1+i), f, p.endpoint())
			w.waitFor("B's connection", func() bool { return p.matchConn(0, hasEvent[peer.HandshakeCompleted]) })
			p.open(b)
			w.waitFor("one connection to close", func() bool {
				return p.matchConn(0, isClosed) || p.matchConn(1, isClosed)
			})
			w.waitUntil(w.clock.Now().Add(5 * time.Second))
			// Connection 0 is the one B opened.
			kept, closed := 1, 0
			if isOursSmaller {
				kept, closed = 0, 1
			}
			if !p.matchConn(closed, isClosed) || p.matchConn(kept, isClosed) {
				t.Fatalf("B's hash smaller %v: connection %d should stay and %d close", isOursSmaller, kept, closed)
			}
		}
	})
}

// A connection we opened long enough ago is no simultaneous dial: the
// client came back, and its new connection stays.
func TestClientBackLaterKeepsNewConnection(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		w := buildWorld(t)
		b := w.addNode("198.51.100.2")
		b.start()
		f := buildTestFile("later.bin", 100_000, 23)
		p := w.addScriptedPeer("198.51.100.5", f)
		b.download(1, f, p.endpoint())
		w.waitFor("B's connection", func() bool { return p.matchConn(0, hasEvent[peer.HandshakeCompleted]) })
		for range 5 {
			w.waitUntil(w.clock.Now().Add(10 * time.Second))
			p.mu.Lock()
			p.perform(p.conns[0], p.conns[0].session.SendQueueRank(5))
			p.mu.Unlock()
		}
		p.open(b)
		w.waitFor("the old connection to close", func() bool { return p.matchConn(0, isClosed) })
		w.waitUntil(w.clock.Now().Add(5 * time.Second))
		if p.matchConn(1, isClosed) {
			t.Fatal("the new connection closed")
		}
	})
}

// Two nodes that check each other's TCP port at once each dial the other:
// once B has acknowledged the peer's check over its connection, the peer's
// connection for its own check comes in, and closing either as a duplicate
// would lose an acknowledgement.
func TestMutualFirewallChecksKeepBothConnections(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		w := buildWorld(t)
		b := w.addNode("198.51.100.2")
		b.config.EnableKad = true
		b.start()
		p := w.addScriptedPeer("198.51.100.5", buildTestFile("check.bin", 100_000, 24))
		p.cfg.KadPort, p.cfg.KadVersion = kadPort, kadwire.Version
		asker, err := p.host.OpenUDP(kadPort)
		if err != nil {
			t.Fatal(err)
		}
		defer asker.Close()
		asker.WriteTo(kadwire.FirewalledReq{TCPPort: peerPort, ID: p.cfg.Self.UserHash}.Build(nil), netip.AddrPortFrom(b.ip, kadPort))
		w.waitFor("B to acknowledge the peer's check", func() bool {
			return p.matchConn(0, func(c *scriptedConn) bool {
				return slices.ContainsFunc(c.received, func(p wire.Packet) bool { return p == client.KadFirewallAck{} })
			})
		})

		p.open(b)
		w.waitFor("the peer's own check connection", func() bool {
			return p.matchConn(1, func(c *scriptedConn) bool { return c.isClosed || hasEvent[peer.HandshakeCompleted](c) })
		})
		w.waitUntil(w.clock.Now().Add(5 * time.Second))
		if p.matchConn(0, isClosed) || p.matchConn(1, isClosed) {
			t.Fatal("B closed a firewall check connection as a duplicate")
		}
	})
}
