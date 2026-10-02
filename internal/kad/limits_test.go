package kad

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/XiaoYouChR/Kelpie/internal/wire"
	kadwire "github.com/XiaoYouChR/Kelpie/internal/wire/kad"
)

// A search reports at most SEARCHFILE_TOTAL sources, however many nodes
// answer.
func TestSearchResultsAreCapped(t *testing.T) {
	h := buildHarness(t)
	req := runSearch(t, h)
	for batch := range 4 {
		var results []kadwire.Entry
		for i := range 100 {
			n := batch*100 + i
			results = append(results, buildOpenEntry(wire.Hash{byte(n), byte(n >> 8), 0xEE}, fmt.Sprintf("1.2.%d.%d", n>>8, n&0xFF), 4662))
		}
		h.receive(req.to, kadwire.SearchRes{Target: fileHash, Results: results})
	}
	total := 0
	for _, f := range h.found {
		total += len(f.Sources)
	}
	if total != fileTotal {
		t.Fatalf("search reported %d sources, want %d", total, fileTotal)
	}
}

// Sources published to us are stored up to maxIndexed over all files, and
// room comes back as they expire.
func TestIndexIsBounded(t *testing.T) {
	h := buildHarness(t)
	publisher := netip.MustParseAddrPort("10.7.0.1:4672")
	publish := func(n int) bool {
		file := selfID
		file[15] ^= byte(n)
		file[14] ^= byte(n >> 8)
		source := kadwire.Entry{ID: wire.Hash{byte(n), byte(n >> 8), byte(n >> 16), 0xAB}, Tags: []wire.Tag{
			{Type: wire.TagUint8, ID: kadwire.TagSourceType, Uint: 1},
		}}
		_, isStored := h.c.index.onPublishSources(h.c.id, publisher, kadwire.PublishSourcesReq{FileID: file, Source: source}, h.now)
		return isStored
	}
	for n := range maxIndexed {
		if !publish(n) {
			t.Fatalf("source %d refused below the cap", n)
		}
	}
	if publish(maxIndexed) {
		t.Fatal("stored a source beyond maxIndexed")
	}
	h.c.index.clearExpired(h.now.Add(republishSources))
	if !publish(maxIndexed) || h.c.index.count != 1 {
		t.Fatalf("count %d after expiry, want room again", h.c.index.count)
	}
}

// A publisher's TAG_PUBLISHINFO and TAG_KADAICHHASHRESULT are not stored,
// as in aMule 3.1.0.
func TestIndexDropsAnswerOnlyTags(t *testing.T) {
	h := buildHarness(t)
	file := selfID
	file[15] ^= 1
	source := kadwire.Entry{ID: userHash, Tags: []wire.Tag{
		{Type: wire.TagUint8, ID: kadwire.TagSourceType, Uint: 1},
		{Type: wire.TagUint32, ID: tagPublishInfo, Uint: 7},
		{Type: wire.TagUint8, ID: tagKadAICHHashResult, Uint: 1},
	}}
	h.c.index.onPublishSources(h.c.id, netip.MustParseAddrPort("10.7.0.1:4672"), kadwire.PublishSourcesReq{FileID: file, Source: source}, h.now)
	for _, tag := range h.c.index.files[file][userHash].tags {
		if tag.ID == tagPublishInfo || tag.ID == tagKadAICHHashResult {
			t.Fatalf("stored tag %#x", tag.ID)
		}
	}
}
