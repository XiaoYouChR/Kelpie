package engine

import (
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/aich"
	"github.com/XiaoYouChR/Kelpie/internal/disk"
	"github.com/XiaoYouChR/Kelpie/internal/peer"
	"github.com/XiaoYouChR/Kelpie/internal/piece"
	"github.com/XiaoYouChR/Kelpie/internal/wire"
	"github.com/XiaoYouChR/Kelpie/internal/wire/client"
)

// A seeder whose file went bad in one block after it was hashed sends that
// block corrupted but correct AICH recovery data. The downloader keeps the
// other blocks and fetches only the bad block again; the seeder stays, as
// that block is under aMule's 32% of what it sent.
func TestAICHRepairRedownloadsOneBlock(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		w := buildWorld(t)
		bad, good, b := w.addNode("198.51.100.1"), w.addNode("198.51.100.3"), w.addNode("198.51.100.2")
		bad.start()
		good.start()
		b.start()
		f := buildTestFile("aich.bin", 2_000_000, 11)
		var hasher aich.Hasher
		hasher.Write(f.data)
		root := aich.BuildTree(int64(len(f.data)), hasher.Leaves()).Root()
		bad.seed(1, f)
		good.seed(1, f)
		file, err := bad.disk.Open("/share/aich.bin", disk.Create)
		if err != nil {
			t.Fatal(err)
		}
		file.WriteAt([]byte("garbage"), 4*piece.BlockSize+100)
		file.Close()

		good.host.SetUnreachable(true)
		link := strings.Replace(f.link(bad.endpoint(), good.endpoint()), "|/|sources", "|h="+root.String()+"|/|sources", 1)
		path := "/downloads/aich.bin"
		b.engine.Post(RunCommand{ID: 2, Mode: ModeDownload, Link: link, File: path})
		w.waitFor("progress to keep all but the bad block", func() bool {
			p, _ := b.events.progressByRun(2)
			return p.Received == int64(len(f.data))-piece.BlockSize
		})

		good.host.SetUnreachable(false)
		begin := w.clock.Now()
		for {
			if _, ok := b.events.endedByRun(2); ok {
				break
			}
			if w.clock.Now().Sub(begin) > waitLimit {
				t.Fatal("download never completed from the good seeder")
			}
			w.clock.Advance(time.Minute)
			for range 20 {
				w.advance(step)
			}
		}
		requireEndedOK(t, w.waitEnded(b, 2))
		b.requireData(path, f.data)
		if hasBan(b.loadTrace(), bad.endpoint().String()) {
			t.Fatal("seeder of one bad block among good ones banned")
		}
		w.waitFor("the good seeder to count its upload", func() bool {
			p, _ := good.events.progressByRun(1)
			return p.Uploaded > 0
		})
		if p, _ := good.events.progressByRun(1); p.Uploaded != piece.BlockSize {
			t.Fatalf("good seeder uploaded %d bytes, want one block", p.Uploaded)
		}
	})
}

// A seed resumed from complete Durable State hashes its AICH tree when a
// peer first asks for the root, and answers from then on.
func TestSeedBuildsTreeWhenAsked(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		w := buildWorld(t)
		a := w.addNode("198.51.100.1")
		a.start()
		f := buildTestFile("tree.bin", 1_000_000, 13)
		a.seed(1, f)
		a.close()
		a.start()
		a.seed(2, f)

		p := w.addScriptedPeer("198.51.100.5", f)
		p.open(a)
		w.waitFor("the peer's handshake", func() bool {
			return p.matchConn(0, hasEvent[peer.HandshakeCompleted])
		})
		askRoot := func() {
			p.mu.Lock()
			defer p.mu.Unlock()
			p.perform(p.conns[0], peer.Output{Send: []wire.Packet{client.AICHFileHashRequest{Hash: f.hash}}})
		}
		answers := func() []client.AICHFileHashAnswer {
			p.mu.Lock()
			defer p.mu.Unlock()
			var answers []client.AICHFileHashAnswer
			for _, packet := range p.conns[0].received {
				if answer, ok := packet.(client.AICHFileHashAnswer); ok {
					answers = append(answers, answer)
				}
			}
			return answers
		}
		askRoot()
		settle := w.clock.Now().Add(2 * time.Second)
		w.waitFor("the tree to be hashed", func() bool { return !w.clock.Now().Before(settle) })
		askRoot()
		w.waitFor("the root", func() bool { return len(answers()) > 0 })
		var hasher aich.Hasher
		hasher.Write(f.data)
		got := answers()
		if len(got) != 1 {
			t.Fatalf("%d answers, want only the one after the tree was hashed", len(got))
		}
		if root := aich.BuildTree(int64(len(f.data)), hasher.Leaves()).Root(); got[0].Root != root {
			t.Fatalf("root %s, want %s", got[0].Root, root)
		}
	})
}
