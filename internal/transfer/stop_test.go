package transfer_test

import (
	"math/rand/v2"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/piece"
	"github.com/XiaoYouChR/Kelpie/internal/transfer"
)

// The next Run's Transfer takes over the sources of the stopped one: the
// queued and the asked source keep their reask time, the sending one is due
// MIN_REQUESTTIME after we asked it, and a dial in flight is made again.
func TestNextTransferKeepsTheSources(t *testing.T) {
	const minRequestTime = 590 * time.Second
	data := buildData(piece.PartSize + 100)
	h := buildHarness(t, data, transfer.Options{File: buildFile(data)})
	var found []transfer.Source
	for i := 1; i <= 4; i++ {
		found = append(found, transfer.Source{Endpoint: endpoint(i)})
	}
	h.run(h.transfer.OnSourcesFound(found, transfer.ChannelServer, start))
	h.tick(transfer.Tick{ConnectBudget: 4})
	h.run(h.transfer.OnPeerConnected(1, transfer.Source{Endpoint: endpoint(1), UserHash: userHash(1)}, start))
	h.transfer.OnPeerParts(1, piece.Set{true, true})
	h.run(h.transfer.OnQueued(1, 3, start))
	h.connect(2, 2, piece.Set{true, true})
	h.deliver(2, 1, false)
	h.run(h.transfer.OnPeerConnected(3, transfer.Source{Endpoint: endpoint(3), UserHash: userHash(3)}, start))

	stopped := start.Add(time.Minute)
	closed := traces(h.transfer.Stop(stopped), transfer.EventClosed)
	if len(closed) != 3 || slices.ContainsFunc(closed, func(e transfer.TraceEvent) bool { return e.Reason != "run ended" }) {
		t.Fatalf("closed on stop: %+v", closed)
	}
	if got := h.transfer.OnPeerGone(2, "run ended", stopped); len(got) != 0 {
		t.Fatalf("peer still attached after Stop: %+v", got)
	}

	next, started := transfer.Build(transfer.Options{File: buildFile(data, endpoint(1)), Path: path, Random: rand.New(rand.NewPCG(3, 4)), Previous: h.transfer}, stopped)
	if got := traces(started, transfer.EventFound); len(got) != 0 {
		t.Fatalf("known link source found again: %+v", got)
	}
	at := func(d time.Duration) []netip.AddrPort {
		var dialled []netip.AddrPort
		for _, c := range connects(next.OnTick(transfer.Tick{Now: start.Add(d), ConnectBudget: 4})) {
			dialled = append(dialled, c.Endpoint)
		}
		return dialled
	}
	for _, step := range []struct {
		at   time.Duration
		want []netip.AddrPort
	}{
		{time.Minute, []netip.AddrPort{endpoint(4)}},
		{minRequestTime - time.Second, nil},
		{minRequestTime, []netip.AddrPort{endpoint(2)}},
		{fileReaskTime - time.Second, nil},
		{fileReaskTime, []netip.AddrPort{endpoint(1), endpoint(3)}},
	} {
		if got := at(step.at); !slices.Equal(got, step.want) {
			t.Fatalf("dialled %v at %v, want %v", got, step.at, step.want)
		}
	}
}
