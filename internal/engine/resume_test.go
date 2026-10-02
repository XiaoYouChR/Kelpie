package engine

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/piece"
)

// A Run stopped and opened again in the same Engine Process goes on with the
// sources the first one knew, without waiting for the server, which is not
// asked for the file again before its reask time. The seeder that was
// sending is asked again once MIN_REQUESTTIME has passed since we asked it,
// at once after a long slot, and not before after a short one.
func TestNextRunKeepsTheSources(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		slot time.Duration
	}{
		{"long slot", minRequestTime},
		{"short slot", time.Minute},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				w := buildWorld(t)
				srv := w.startFakeServer("198.51.100.100")
				a, b := w.addNode("198.51.100.1"), w.addNode("198.51.100.2")
				a.setServer(srv)
				b.setServer(srv)
				b.config.DownloadLimit = 20_000
				a.start()
				b.start()
				f := buildTestFile("again.bin", 2*int(piece.PartSize), 31)
				a.seed(1, f)
				for _, n := range []*node{a, b} {
					w.waitFor("server login", func() bool { return n.events.lastNetwork().IsServerConnected })
				}
				w.waitUntil(w.clock.Now().Add(10 * time.Second))

				b.download(2, f)
				w.waitFor("the seeder to send", func() bool {
					p, _ := b.events.progressByRun(2)
					return p.Received > 0
				})
				asked := traceTimes(b.loadTrace(), "connected", a.endpoint().String())[0]
				w.waitUntil(w.clock.Now().Add(test.slot))
				b.engine.Post(StopCommand{ID: 2})
				requireEndedOK(t, w.waitEnded(b, 2))
				stopped, _ := b.events.progressByRun(2)

				b.download(3, f)
				due := asked.Add(minRequestTime)
				if due.Before(w.clock.Now()) {
					due = w.clock.Now()
				}
				w.waitFor("the next run to receive", func() bool {
					if w.clock.Now().After(due.Add(time.Minute)) {
						t.Fatalf("no data a minute after the seeder was due")
					}
					p, _ := b.events.progressByRun(3)
					return p.Received > stopped.Received
				})
				again := traceTimes(b.loadTrace(), "connected", a.endpoint().String())[1]
				if again.Before(asked.Add(minRequestTime)) {
					t.Fatalf("seeder asked again %v after the first ask", again.Sub(asked))
				}
			})
		})
	}
}

// traceTimes lists when each trace line of event for source was written.
func traceTimes(lines []map[string]any, event, source string) []time.Time {
	var times []time.Time
	for _, line := range lines {
		if line["event"] == event && line["source"] == source {
			times = append(times, time.UnixMilli(int64(line["time"].(float64))))
		}
	}
	return times
}

// A stopped Run's sources are dropped by remove and an hour after the stop.
func TestStoppedSourcesAreDropped(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		w := buildWorld(t)
		b := w.addNode("198.51.100.2")
		b.start()
		removed, expired := buildTestFile("removed.bin", 1000, 32), buildTestFile("expired.bin", 1000, 33)
		b.download(1, removed)
		b.download(2, expired)
		b.engine.Post(StopCommand{ID: 1})
		b.engine.Post(StopCommand{ID: 2})
		w.waitEnded(b, 1)
		w.waitEnded(b, 2)
		b.engine.Post(RemoveCommand{Hash: removed.hash})
		w.advance(stoppedTime - 3*time.Second)
		w.waitUntil(w.clock.Now().Add(2 * time.Second))
		b.close()
		// The hub has stopped, so its map is safe to read.
		if _, ok := b.engine.stopped[removed.hash]; ok || len(b.engine.stopped) != 1 {
			t.Fatalf("kept %d stopped runs before the hour, want only the one not removed", len(b.engine.stopped))
		}

		b.start()
		b.download(3, expired)
		b.engine.Post(StopCommand{ID: 3})
		w.waitEnded(b, 3)
		w.advance(stoppedTime)
		w.waitUntil(w.clock.Now().Add(2 * time.Second))
		b.close()
		if n := len(b.engine.stopped); n != 0 {
			t.Fatalf("kept %d stopped runs after an hour", n)
		}
	})
}
