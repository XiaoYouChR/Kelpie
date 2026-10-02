package transfer_test

import (
	"fmt"
	"slices"
	"testing"

	"github.com/XiaoYouChR/Kelpie/internal/piece"
	"github.com/XiaoYouChR/Kelpie/internal/transfer"
)

// Progress lists the sources sending, queued and connecting with what
// their Hello and queue rank told, and where each was found.
func TestProgressListsSources(t *testing.T) {
	data := buildData(2 * piece.BlockSize)
	h := buildHarness(t, data, transfer.Options{File: buildFile(data, endpoint(1), endpoint(2), endpoint(3))})
	h.run(h.started)
	h.run(h.transfer.OnSourcesFound([]transfer.Source{{Endpoint: endpoint(4)}}, transfer.ChannelGlobalServer, h.now))
	h.tick(transfer.Tick{ConnectBudget: 4})

	h.run(h.transfer.OnPeerConnected(1, transfer.Source{Endpoint: endpoint(1), UserHash: userHash(1), Software: "eMule 0.70b"}, h.now))
	h.transfer.OnPeerParts(1, piece.Set{true})
	h.run(h.transfer.OnSlotGranted(1, h.now))
	if h.deliver(1, 1, false) != 1 {
		t.Fatal("no block delivered")
	}
	h.run(h.transfer.OnPeerConnected(2, transfer.Source{Endpoint: endpoint(2), UserHash: userHash(2), Software: "aMule 2.3.3"}, h.now))
	h.transfer.OnPeerParts(2, piece.Set{true})
	h.run(h.transfer.OnQueued(2, 17, h.now))

	p := h.transfer.Progress(h.now)
	want := []transfer.SourceProgress{
		{Address: endpoint(1).String(), Software: "eMule 0.70b", Status: "transferring", DownloadRate: p.DownloadRate, Channel: "link"},
		{Address: endpoint(2).String(), Software: "aMule 2.3.3", Status: "queued", Rank: 17, Channel: "link"},
		{Address: endpoint(3).String(), Status: "connecting", Channel: "link"},
		{Address: endpoint(4).String(), Status: "connecting", Channel: "server"},
	}
	if p.DownloadRate == 0 || !slices.Equal(p.Sources, want) {
		t.Fatalf("sources %+v, want %+v", p.Sources, want)
	}
}

// Of more queued sources than Progress lists, the best ranks are listed,
// unknown ranks last.
func TestProgressListsBestRanksFirst(t *testing.T) {
	data := buildData(piece.BlockSize)
	h := buildHarness(t, data, transfer.Options{File: buildFile(data)})
	for i := 1; i <= 60; i++ {
		peer := uint64(i)
		h.run(h.transfer.OnPeerConnected(peer, transfer.Source{Endpoint: endpoint(i), UserHash: userHash(i)}, h.now))
		h.transfer.OnPeerParts(peer, piece.Set{true})
		if i > 1 {
			h.run(h.transfer.OnQueued(peer, 100-i, h.now))
		}
	}
	sources := h.transfer.Progress(h.now).Sources
	var ranks []string
	for _, s := range sources {
		ranks = append(ranks, fmt.Sprint(s.Rank))
	}
	if len(sources) != 50 || sources[0].Rank != 40 || sources[49].Rank != 89 {
		t.Fatalf("listed %d sources, ranks %v", len(sources), ranks)
	}
}
