package kad

import (
	"fmt"
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
