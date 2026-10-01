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
	a, b, c := w.addNode("10.0.0.1"), w.addNode("10.0.0.2"), w.addNode("10.0.0.3")
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
