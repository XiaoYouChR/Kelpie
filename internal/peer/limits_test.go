package peer

import (
	"testing"

	"github.com/XiaoYouChR/Kelpie/internal/piece"
	"github.com/XiaoYouChR/Kelpie/internal/wire"
	"github.com/XiaoYouChR/Kelpie/internal/wire/client"
)

func TestSourceAnswerIsCapped(t *testing.T) {
	l := buildLink(t)
	file, _ := addShare(l.b, 1, piece.BlockSize, false)
	l.run(l.a, l.a.s.Add(file, piece.BlockSize, piece.Set{false}))
	l.run(l.a, l.a.s.RequestSources(file, l.now))
	answer := client.AnswerSources2{Version: client.SourceExchange2Version, Hash: file}
	for i := range 2000 {
		answer.Sources = append(answer.Sources, client.Source{ClientID: 0x05000000 + uint32(i), Port: 4662})
	}
	l.run(l.b, Output{Send: []wire.Packet{answer}})
	if got := len(lastOf[SourcesFound](t, l.a).Sources); got != maxSources {
		t.Fatalf("found %d sources, want %d", got, maxSources)
	}
}

func TestOversizedCompressedPartCloses(t *testing.T) {
	l := buildLink(t)
	size := piece.BlockSize
	file, _ := addShare(l.b, 1, size, true)
	l.run(l.a, l.a.s.Add(file, size, piece.Set{false}))
	l.run(l.a, l.a.s.Start(file))
	l.run(l.b, l.b.s.StartUpload())
	l.run(l.a, l.a.s.Request(file, []piece.Block{{Begin: 0, End: size}}))
	part := client.CompressedPart{Hash: file, PackedSize: 1 << 30, Data: make([]byte, 10240)}
	l.run(l.b, Output{Send: []wire.Packet{part}})
	if l.a.closed != CloseProtocol {
		t.Fatalf("closed %q, want %q", l.a.closed, CloseProtocol)
	}
}
