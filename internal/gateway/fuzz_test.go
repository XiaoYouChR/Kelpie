package gateway

import (
	"bytes"
	"io"
	"log"
	"os"
	"testing"

	"github.com/XiaoYouChR/Kelpie/internal/engine"
)

func FuzzRun(f *testing.F) {
	for _, name := range []string{"session.in.ndjson", "failed.in.ndjson"} {
		raw, err := os.ReadFile("testdata/" + name)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(raw)
	}
	f.Add([]byte(hello + `{"type":"run","run":3,"mode":"download","link":"ed2k://|file|a|5|31D6CFE0D16AE931B73C59D7E0C089C0|/","file":"/a"}` + "\n"))
	log.SetOutput(io.Discard)
	f.Fuzz(func(t *testing.T, in []byte) {
		eng := &fakeEngine{}
		start, _ := startFake(eng)
		Run(bytes.NewReader(in), io.Discard, "test", start)
		for _, command := range eng.postedCommands() {
			if run, ok := command.(engine.RunCommand); ok && (run.ID <= 0 || run.File == "") {
				t.Fatalf("posted %+v", run)
			}
		}
	})
}
