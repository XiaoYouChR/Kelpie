package kad

import (
	"fmt"
	"testing"
	"time"
)

// A file that is not wanted for a while, as when its download is stopped
// and run again, keeps its search pace for an hour.
func TestStoppedFileKeepsSearchPace(t *testing.T) {
	for _, test := range []struct {
		name             string
		stopped, resumed int
		want             []time.Duration
	}{
		{"between searches", 10, 20, []time.Duration{time.Minute, 61 * time.Minute}},
		{"over an hour", 10, 71, []time.Duration{time.Minute, 71 * time.Minute, 131 * time.Minute}},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := buildHarness(t)
			h.connect(fileHash, 6)
			var starts []time.Duration
			var last *lookup
			for minute := 1; minute <= 150; minute++ {
				switch minute {
				case 1, test.resumed:
					h.c.setWanted(Wanted{{Hash: fileHash, Size: 1000}}, h.now)
				case test.stopped + 1:
					h.c.setWanted(Wanted{}, h.now)
				}
				h.tick(time.Minute)
				if l := h.c.lookupByTarget(sourceSearch, fileHash); l != nil && l != last {
					starts = append(starts, h.now.Sub(start))
					last = l
				}
			}
			if fmt.Sprint(starts) != fmt.Sprint(test.want) {
				t.Fatalf("searches started at %v, want %v", starts, test.want)
			}
		})
	}
}

// A search cut short by the file leaving the wanted set is made again as
// soon as the file is wanted again, and counts towards the pace.
func TestStoppedSearchIsMadeAgain(t *testing.T) {
	h := buildHarness(t)
	runSearch(t, h)
	first := h.c.lookupByTarget(sourceSearch, fileHash)
	h.c.setWanted(Wanted{}, h.now)
	h.tick(time.Second)
	h.c.setWanted(Wanted{{Hash: fileHash, Size: 1000}}, h.now)
	h.tick(time.Second)
	again := h.c.lookupByTarget(sourceSearch, fileHash)
	if again == nil || again == first {
		t.Fatal("the cut search was not made again")
	}
	searched := h.now
	for h.now.Before(searched.Add(2*reaskSources - time.Minute)) {
		h.tick(time.Minute)
		if l := h.c.lookupByTarget(sourceSearch, fileHash); l != nil && l != again {
			t.Fatalf("searched again %v after the second search", h.now.Sub(searched))
		}
	}
}

// A file shared again is published when its last publish is due again, not
// at once.
func TestStoppedFileKeepsPublishPace(t *testing.T) {
	h := buildHarness(t)
	h.c.isSelfLookupDone = true
	h.c.firewall.acks = firewallOpenAcks
	h.connect(fileHash, 6)
	shared := Wanted{{Hash: fileHash, Size: 5000, IsComplete: true, IsShared: true}}
	h.c.setWanted(shared, h.now)
	h.tick(time.Second)
	first := h.c.lookupByTarget(sourcePublish, fileHash)
	if first == nil {
		t.Fatal("not published")
	}
	published := h.now
	h.c.setWanted(Wanted{}, h.now)
	h.tick(time.Minute)
	h.c.setWanted(shared, h.now)
	var again time.Duration
	for again == 0 && h.now.Before(published.Add(2*republishSources)) {
		// The hourly firewall check would make us firewalled, and unpublished,
		// for lack of answers.
		h.c.firewall.acks = firewallOpenAcks
		h.tick(time.Minute)
		if l := h.c.lookupByTarget(sourcePublish, fileHash); l != nil && l != first {
			again = h.now.Sub(published)
		}
	}
	if again < republishSources || again > republishSources+time.Minute {
		t.Fatalf("published again %v after the first, want %v", again, republishSources)
	}
}
