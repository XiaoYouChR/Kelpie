package engine

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/piece"
)

// A seeder slower than a 180 KB block per meter window still moves Progress
// every second at its own rate, and once it leaves the rate falls to zero.
func TestProgressFollowsASlowSeeder(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		w := buildWorld(t)
		a, b := w.addNode("198.51.100.1"), w.addNode("198.51.100.2")
		a.start()
		b.config.DownloadLimit = 10_000
		b.start()
		f := buildTestFile("slow.bin", int(piece.PartSize), 41)
		a.seed(1, f)
		b.download(2, f, a.endpoint())
		w.waitFor("the first bytes", func() bool {
			p, _ := b.events.progressByRun(2)
			return p.Received > 0
		})
		w.waitUntil(w.clock.Now().Add(10 * time.Second))
		last, _ := b.events.progressByRun(2)
		for range 10 {
			w.waitUntil(w.clock.Now().Add(time.Second))
			p, _ := b.events.progressByRun(2)
			if p.Received <= last.Received || p.DownloadRate < 5_000 || p.DownloadRate > 15_000 {
				t.Fatalf("a second on, received %d at %d B/s, was %d", p.Received, p.DownloadRate, last.Received)
			}
			last = p
		}

		// What the seeder sent before it left still arrives at the limit.
		a.host.Close()
		w.waitUntil(w.clock.Now().Add(2 * time.Minute))
		if p, _ := b.events.progressByRun(2); p.DownloadRate != 0 {
			t.Fatalf("rate %d two minutes after the seeder left", p.DownloadRate)
		}
	})
}
