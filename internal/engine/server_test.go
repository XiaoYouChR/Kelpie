package engine

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/XiaoYouChR/Kelpie/internal/fakeserver"
)

// startFakeServer runs an eD2k server on its own host until the test ends.
func (w *world) startFakeServer(ip string) *fakeserver.Server {
	return w.startFakeServerWith(fakeserver.Config{Addr: netip.AddrPortFrom(netip.MustParseAddr(ip), 4661)})
}

// startFakeServerWith fills in the host, clock and name of config.
func (w *world) startFakeServerWith(config fakeserver.Config) *fakeserver.Server {
	w.t.Helper()
	config.Transport = w.network.AddHost(config.Addr.Addr())
	config.Clock = w.clock
	config.Name = "test"
	srv, err := fakeserver.Create(config)
	if err != nil {
		w.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.Run(ctx)
	}()
	w.t.Cleanup(func() {
		cancel()
		<-done
	})
	return srv
}

func (n *node) setServer(srv *fakeserver.Server) {
	path := filepath.Join(n.folder, "server.met")
	if err := os.WriteFile(path, fakeserver.BuildMet(srv), 0o644); err != nil {
		n.w.t.Fatal(err)
	}
	n.config.ServerLists = []string{path}
}

// A server that lists an obfuscation port is logged in to there, through
// the Diffie-Hellman handshake, before any plain attempt.
func TestServerLoginObfuscated(t *testing.T) {
	w := buildWorld(t)
	srv := w.startFakeServerWith(fakeserver.Config{Addr: netip.MustParseAddrPort("198.51.100.100:4661"), ObfuscationPort: 4665})
	a := w.addNode("198.51.100.1")
	log := &lockedBuffer{}
	a.config.PacketLog = log
	a.setServer(srv)
	a.start()
	w.waitFor("server login", func() bool { return a.events.lastNetwork().IsServerConnected })
	text := log.String()
	if !strings.Contains(text, "open 198.51.100.100:4665 obfuscated=true") || strings.Contains(text, "open 198.51.100.100:4661") {
		t.Fatalf("login not obfuscated:\n%s", text)
	}
	if !strings.Contains(text, "in  198.51.100.100:4661 server.IDChange") {
		t.Fatalf("no IDChange over the obfuscated connection:\n%s", text)
	}
}
