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
	l.run(l.b, l.b.s.StartUpload())
	l.run(l.a, l.a.s.Request(file, []piece.Block{{Begin: 0, End: size}}))
	part := client.CompressedPart{Hash: file, PackedSize: 1 << 30, Data: make([]byte, 10240)}
	l.run(l.b, Output{Send: []wire.Packet{part}})
	if l.a.closed != closeProtocol {
		t.Fatalf("closed %q, want %q", l.a.closed, closeProtocol)
	}
}

func TestRequestedBlocksAreCapped(t *testing.T) {
	l := buildLink(t)
	size := 100 * int64(1024)
	file, data := addShare(l.b, 1, size, false)
	l.run(l.a, l.a.s.Add(file, size, piece.Set{false}))
	l.run(l.b, l.b.s.StartUpload())
	request := func(first int) {
		p := client.RequestParts{Hash: file}
		for i := range 3 {
			p.Starts[i] = uint32((first + i) * 100)
			p.Ends[i] = p.Starts[i] + 100
		}
		l.run(l.a, Output{Send: []wire.Packet{p}})
	}
	requested := func() []piece.Block {
		var blocks []piece.Block
		for _, r := range eventsOf[BlocksRequested](l.b) {
			blocks = append(blocks, r.Blocks...)
		}
		return blocks
	}
	for i := 0; i < 60; i += 3 {
		request(i)
	}
	if got := len(requested()); got != maxUploadBlocks {
		t.Fatalf("%d blocks requested, want %d", got, maxUploadBlocks)
	}

	for _, b := range requested() {
		l.run(l.b, l.b.s.SendBlock(file, b, data[b.Begin:b.End]))
	}
	for i := 60; i < 120; i += 3 {
		request(i)
	}
	if got := len(requested()); got != 2*maxUploadBlocks {
		t.Fatalf("%d blocks requested after sending, want %d", got, 2*maxUploadBlocks)
	}
	if got := len(l.b.s.up.slot.pending) + len(l.b.s.up.slot.sent); got > 2*maxUploadBlocks {
		t.Fatalf("%d blocks remembered, want at most %d", got, 2*maxUploadBlocks)
	}
}
