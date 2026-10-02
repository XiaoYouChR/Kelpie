package engine

import (
	"slices"
	"testing"
	"testing/synctest"

	"github.com/XiaoYouChR/Kelpie/internal/piece"
)

// Progress lists a source sending to us and one we are queued on, with the
// client each named in its Hello.
func TestProgressListsSendingAndQueuedSources(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		w := buildWorld(t)
		a, b := w.addNode("198.51.100.1"), w.addNode("198.51.100.2")
		a.config.UploadLimit = 100_000
		a.start()
		b.start()
		f := buildTestFile("table.bin", 3*int(piece.PartSize), 14)
		a.seed(1, f)
		p := w.addScriptedPeer("198.51.100.5", f)
		b.download(2, f, a.endpoint(), p.endpoint())

		var sources []Source
		w.waitFor("a source sending at a rate and a queued one", func() bool {
			progress, _ := b.events.progressByRun(2)
			sources = progress.Sources
			return len(sources) == 2 && sources[0].DownloadRate > 0 && sources[1].Status == "queued"
		})
		sources[0].DownloadRate = 0
		want := []Source{
			{Address: a.endpoint().String(), Software: "Kelpie 0.1.0", Status: "transferring", Channel: "link"},
			{Address: p.endpoint().String(), Software: "Kelpie 0.50.0", Status: "queued", Rank: 5, Channel: "link"},
		}
		if !slices.Equal(sources, want) {
			t.Fatalf("sources %+v, want %+v", sources, want)
		}
	})
}
