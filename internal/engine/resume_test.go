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
// sending is asked again at once, as aMule does after a pause. Paused and
// resumed again at once, asking it would count as aggressive: Progress
// tells that it is held, and it is asked once the ask is polite.
func TestNextRunKeepsTheSources(t *testing.T) {
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

		var received int64
		receive := func(id RunID) {
			t.Helper()
			resumed := w.clock.Now()
			w.waitFor("the run to receive", func() bool {
				if w.clock.Now().After(resumed.Add(time.Minute)) {
					t.Fatalf("run %d received nothing for a minute", id)
				}
				p, _ := b.events.progressByRun(id)
				return p.Received > received
			})
		}
		stop := func(id RunID) {
			t.Helper()
			b.engine.Post(StopCommand{ID: id})
			requireEndedOK(t, w.waitEnded(b, id))
			p, _ := b.events.progressByRun(id)
			received = p.Received
		}

		b.download(2, f)
		receive(2)
		w.waitUntil(w.clock.Now().Add(time.Minute))
		stop(2)
		b.download(3, f)
		receive(3)
		asked := traceTimes(b.loadTrace(), "connected", a.endpoint().String())[1]

		stop(3)
		b.download(4, f)
		w.waitUntil(w.clock.Now().Add(10 * time.Second))
		// The slot ask follows the connection by the time the file request
		// takes to be answered.
		const politeGap = 11 * time.Minute
		p, _ := b.events.progressByRun(4)
		held := p.HeldUntil
		if p.HeldSources != 1 || held.Before(asked.Add(politeGap)) || held.After(asked.Add(politeGap+time.Minute)) || p.Received != received {
			t.Fatalf("progress held %d until %v with %d received, want 1 until %v with %d", p.HeldSources, held, p.Received, asked.Add(politeGap), received)
		}
		w.waitUntil(held.Add(-time.Second))
		if p, _ := b.events.progressByRun(4); p.Received != received {
			t.Fatal("the held seeder sent before its ask was polite")
		}
		w.waitUntil(held)
		receive(4)
		if p, _ := b.events.progressByRun(4); p.HeldSources != 0 || !p.HeldUntil.IsZero() {
			t.Fatalf("progress still held %d until %v once asked", p.HeldSources, p.HeldUntil)
		}
	})
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
