package engine

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"

	"github.com/XiaoYouChR/Kelpie/internal/fakeserver"
)

// startFakeServer runs an eD2k server on its own host until the test ends.
func (w *world) startFakeServer(ip string) *fakeserver.Server {
	w.t.Helper()
	addr := netip.MustParseAddr(ip)
	srv, err := fakeserver.Create(fakeserver.Config{
		Transport: w.network.AddHost(addr),
		Clock:     w.clock,
		Addr:      netip.AddrPortFrom(addr, 4661),
		Name:      "test",
	})
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
	if err := os.WriteFile(path, fakeserver.BuildMet(srv.Addr()), 0o644); err != nil {
		n.w.t.Fatal(err)
	}
	n.config.ServerLists = []string{path}
}
