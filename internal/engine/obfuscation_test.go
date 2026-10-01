package engine

import (
	"bytes"
	"strings"
	"sync"
	"testing"

	"github.com/XiaoYouChR/Kelpie/internal/piece"
)

// lockedBuffer is a packet log the test reads while leaves write it.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// A Kelpie that learns a source through Source Exchange connects to it
// obfuscated, keyed with the user hash the answer carried, and the Kelpie
// on the other side answers the handshake and then the Hello.
//
// C downloads slowly from A and tells B about A; B reaches C through the
// link, which carries no user hash, so that connection stays plain.
func TestExchangedSourceIsObfuscated(t *testing.T) {
	w := buildWorld(t)
	a, b, c := w.addNode("198.51.100.1"), w.addNode("198.51.100.2"), w.addNode("198.51.100.3")
	a.config.RateLimits.Upload = 500_000
	log := &lockedBuffer{}
	b.config.PacketLog = log
	for _, n := range []*node{a, b, c} {
		n.start()
	}
	f := buildTestFile("crypt.bin", 3*int(piece.PartSize), 11)
	a.seed(1, f)
	c.download(2, f, a.endpoint())
	// C shares the file once a part is whole and checked; blocks of the
	// three parts arrive interleaved.
	w.waitFor("C to share a part", func() bool {
		p, _ := c.events.progressByRun(2)
		return p.Received > 2*piece.PartSize+1_000_000
	})
	b.download(3, f, c.endpoint())
	toA := a.endpoint().String()
	w.waitFor("B's Hello answered by A", func() bool {
		return strings.Contains(log.String(), "in  "+toA+" client.HelloAnswer")
	})
	text := log.String()
	if !strings.Contains(text, "open "+toA+" obfuscated=true") || strings.Contains(text, "open "+toA+" obfuscated=false") {
		t.Fatalf("connection to A not obfuscated:\n%s", text)
	}
	if !strings.Contains(text, "open "+c.endpoint().String()+" obfuscated=false") {
		t.Fatalf("the link's source has no user hash and must stay plain:\n%s", text)
	}
}

// A queued downloader reasks a Kelpie seed over UDP obfuscated, keyed with
// the seed's user hash, and the seed answers obfuscated with the rank.
//
// C and D hold A's two slots, all a slow upload gets, so B queues on A.
func TestUDPReaskIsObfuscated(t *testing.T) {
	w := buildWorld(t)
	srv := w.startFakeServer("198.51.100.100")
	a, b := w.addNode("198.51.100.1"), w.addNode("198.51.100.2")
	c, d := w.addNode("198.51.100.3"), w.addNode("198.51.100.4")
	aLog, bLog := &lockedBuffer{}, &lockedBuffer{}
	a.config.PacketLog, b.config.PacketLog = aLog, bLog
	a.config.RateLimits.Upload = 2_000
	for _, n := range []*node{a, b} {
		n.setServer(srv)
		n.start()
		w.waitFor("a HighID", func() bool { return n.events.lastNetwork().IsHighID })
	}
	c.start()
	d.start()
	f := buildTestFile("reask.bin", 3*int(piece.PartSize), 14)
	a.seed(1, f)
	for _, n := range []*node{c, d} {
		n.download(2, f, a.endpoint())
		w.waitFor("a slot on A", func() bool { return matchTrace(n.loadTrace(), "slot", a.endpoint().String()) })
	}

	b.download(2, f, a.endpoint())
	w.waitFor("B to queue on A", func() bool { return countTrace(b.loadTrace(), "queued", a.endpoint().String()) == 1 })
	w.waitFor("B's UDP reask answered", func() bool { return countTrace(b.loadTrace(), "queued", a.endpoint().String()) == 2 })
	toA, toB := "udp out "+a.endpoint().String()+" ", "udp out "+b.endpoint().String()+" "
	if !strings.Contains(bLog.String(), toA+"obfuscated") || strings.Contains(bLog.String(), toA+"client.") {
		t.Fatalf("reask not obfuscated:\n%s", bLog.String())
	}
	if !strings.Contains(aLog.String(), toB+"obfuscated") || strings.Contains(aLog.String(), toB+"client.") {
		t.Fatalf("answer not obfuscated:\n%s", aLog.String())
	}
}

func countTrace(lines []map[string]any, event, source string) int {
	n := 0
	for _, line := range lines {
		if line["event"] == event && line["source"] == source {
			n++
		}
	}
	return n
}
