package engine

import (
	"testing"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/peer"
	"github.com/XiaoYouChR/Kelpie/internal/piece"
	"github.com/XiaoYouChR/Kelpie/internal/wire"
	"github.com/XiaoYouChR/Kelpie/internal/wire/client"
)

// slotAsks lists the files the peer was asked a slot for, over all its
// connections.
func (p *scriptedPeer) slotAsks() []wire.Hash {
	files, _ := p.loadSlotAsks()
	return files
}

// loadSlotAsks lists the slot asks with the fake-clock time each arrived.
func (p *scriptedPeer) loadSlotAsks() ([]wire.Hash, []time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var files []wire.Hash
	var times []time.Time
	for _, c := range p.conns {
		for i, packet := range c.received {
			if ask, ok := packet.(client.StartUploadRequest); ok {
				files = append(files, ask.Hash)
				times = append(times, c.receivedAt[i])
			}
		}
	}
	return files, times
}

func (p *scriptedPeer) connCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.conns)
}

func (w *world) waitUntil(at time.Time) {
	w.waitFor("time to pass", func() bool { return !w.clock.Now().Before(at) })
}

// Two downloads sharing one source: the source is asked for the first one
// only, and the second waits instead of connecting on its own; when the
// first ends, the second asks when the source's reask is due.
func TestSharedSourceIsAskedForOneFile(t *testing.T) {
	w := buildWorld(t)
	b := w.addNode("198.51.100.2")
	b.start()
	first, second := buildTestFile("first.bin", 300_000, 21), buildTestFile("second.bin", 300_000, 22)
	p := w.addScriptedPeer("198.51.100.5", first)
	p.others = map[wire.Hash]peer.Share{second.hash: {Name: second.name, Size: int64(len(second.data)), Parts: piece.Set{true}}}

	b.download(1, first, p.endpoint())
	w.waitFor("B to queue for the first file", func() bool { return len(p.slotAsks()) == 1 })
	asked := w.clock.Now()
	w.waitFor("the idle connection to close", func() bool {
		return matchTrace(b.loadTrace(), "closed", p.endpoint().String())
	})

	b.download(2, second, p.endpoint())
	w.waitUntil(asked.Add(minRequestTime + time.Minute))
	if got := p.slotAsks(); len(got) != 1 || got[0] != first.hash || p.connCount() != 1 {
		t.Fatalf("asks %v over %d connections, want one ask for the first file", got, p.connCount())
	}

	b.engine.Post(StopCommand{ID: 1})
	w.waitFor("the second file to be asked", func() bool { return len(p.slotAsks()) == 2 })
	if got := p.slotAsks()[1]; got != second.hash {
		t.Fatalf("second ask for %v, want the second file", got)
	}
	// Arrival lags sending by whatever the fake clock advanced while the
	// packet was in flight, so allow a second of it; asking early would be
	// off by minutes, not by steps.
	_, at := p.loadSlotAsks()
	if gap := at[1].Sub(at[0]); gap < fileReaskTime-time.Second {
		t.Fatalf("second file asked %v after the first, before the reask was due", gap)
	}
}

// A source with no part the first download needs is swapped to the second
// one on the same connection.
func TestNoNeededPartsSwapsToAnotherFile(t *testing.T) {
	w := buildWorld(t)
	b := w.addNode("198.51.100.2")
	b.start()
	first, second := buildTestFile("first.bin", int(piece.PartSize)+1000, 23), buildTestFile("second.bin", 300_000, 24)
	p := w.addScriptedPeer("198.51.100.5", second)
	p.others = map[wire.Hash]peer.Share{first.hash: {Name: first.name, Size: int64(len(first.data)), Parts: piece.Set{false, false}}}

	b.download(1, first, p.endpoint())
	b.download(2, second, p.endpoint())
	w.waitFor("a slot ask", func() bool { return len(p.slotAsks()) > 0 })
	w.waitUntil(w.clock.Now().Add(5 * time.Second))
	if got := p.slotAsks(); len(got) != 1 || got[0] != second.hash || p.connCount() != 1 {
		t.Fatalf("asks %v over %d connections, want one for the second file", got, p.connCount())
	}
}
