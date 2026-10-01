package peer

import (
	"slices"
	"testing"

	"github.com/XiaoYouChR/Kelpie/internal/piece"
	"github.com/XiaoYouChR/Kelpie/internal/wire"
	"github.com/XiaoYouChR/Kelpie/internal/wire/client"
)

func sentOf[T wire.Packet](t *testing.T, l *link) T {
	t.Helper()
	for _, p := range l.sent {
		if v, ok := p.(T); ok {
			return v
		}
	}
	var zero T
	t.Fatalf("no %T in %#v", zero, l.sent)
	return zero
}

func TestFileRequestUsesFileIdentifier(t *testing.T) {
	l := buildLink(t)
	if !l.a.s.Capabilities().HasFileIdentifiers || !l.b.s.Capabilities().HasFileIdentifiers {
		t.Fatal("file identifiers not advertised")
	}
	size := piece.PartSize + 1000
	file, tree := addTreeShare(l.b, size)
	l.run(l.a, l.a.s.Add(file, size, piece.Set{false, false}))

	request := sentOf[client.MultiPacketExt2](t, l)
	if request.File != (client.FileIdentifier{Hash: file, Size: uint64(size)}) {
		t.Fatalf("identifier %+v", request.File)
	}
	for _, r := range request.Requests {
		if _, ok := r.(client.AICHFileHashRequest); ok {
			t.Fatal("asked for the root, which comes in the identifier")
		}
	}
	answer := sentOf[client.MultiPacketAnswerExt2](t, l)
	if answer.File != (client.FileIdentifier{Hash: file, Size: uint64(size), HasRoot: true, Root: tree.Root()}) {
		t.Fatalf("answer identifier %+v", answer.File)
	}
	if sentCount[client.MultiPacketExt](l)+sentCount[client.MultiPacketAnswer](l) != 0 {
		t.Fatal("old multipacket sent to a peer with file identifiers")
	}
	if got := lastOf[RootReceived](t, l.a); got != (RootReceived{File: file, Root: tree.Root()}) {
		t.Fatalf("root %+v", got)
	}
	if st := lastOf[StatusReceived](t, l.a); st.File != file || !st.Parts.IsFull() {
		t.Fatalf("status %+v", st)
	}
}

func TestSourceRequestUsesFileIdentifier(t *testing.T) {
	l := buildLink(t)
	file, _ := addShare(l.b, 1, piece.BlockSize, false)
	l.run(l.a, l.a.s.Add(file, piece.BlockSize, piece.Set{false}))
	l.sent = nil
	l.run(l.a, l.a.s.RequestSources(file, l.now))
	if _, ok := sentOf[client.MultiPacketExt2](t, l).Requests[0].(client.RequestSources2); !ok {
		t.Fatal("no source request")
	}
	if lastOf[SourcesRequested](t, l.b).File != file {
		t.Fatal("request not seen")
	}
}

func TestMismatchedIdentifierIsNoFile(t *testing.T) {
	l := buildLink(t)
	size := piece.PartSize + 1000
	file, _ := addTreeShare(l.b, size)
	for _, id := range []client.FileIdentifier{
		{Hash: file, Size: uint64(size) + 1},
		{Hash: file, HasRoot: true, Root: wire.AICHHash{9}},
	} {
		l.sent = nil
		l.run(l.a, Output{Send: []wire.Packet{client.MultiPacketExt2{File: id, Requests: []wire.Packet{client.SetRequestFileID{Hash: file}}}}})
		if sentOf[client.NoFile](t, l).Hash != file || len(l.sent) != 2 {
			t.Fatalf("%+v answered %#v", id, l.sent)
		}
	}
}

func TestIdentifierWithoutSizeOrRootMatches(t *testing.T) {
	l := buildLink(t)
	size := piece.PartSize + 1000
	file, _ := addTreeShare(l.b, size)
	l.run(l.a, Output{Send: []wire.Packet{client.MultiPacketExt2{
		File:     client.FileIdentifier{Hash: file},
		Requests: []wire.Packet{client.SetRequestFileID{Hash: file}, client.AICHFileHashRequest{Hash: file}},
	}}})
	answer := sentOf[client.MultiPacketAnswerExt2](t, l)
	if len(answer.Answers) != 1 {
		t.Fatalf("answered the AICH request inside Ext2: %+v", answer.Answers)
	}
}

func TestIdentifierAnswerWithWrongSizeCloses(t *testing.T) {
	l := buildLink(t)
	size := piece.PartSize + 1000
	file, _ := addShare(l.b, 1, size, false)
	l.tamper = func(p wire.Packet) wire.Packet {
		if a, ok := p.(client.MultiPacketAnswerExt2); ok {
			a.File.Size++
			return a
		}
		return p
	}
	l.run(l.a, l.a.s.Add(file, size, piece.Set{false, false}))
	if l.a.closed != closeProtocol || len(eventsOf[StatusReceived](l.a)) != 0 {
		t.Fatalf("closed %q, events %#v", l.a.closed, l.a.events)
	}
}

func TestIdentifierRequestWantsMissingTree(t *testing.T) {
	l := buildLink(t)
	size := 3 * piece.BlockSize
	file, _ := addShare(l.b, 1, size, false)
	l.run(l.a, l.a.s.Add(file, size, piece.Set{false}))
	if got := lastOf[TreeWanted](t, l.b); got.File != file {
		t.Fatalf("wanted %+v", got)
	}
	if sentOf[client.MultiPacketAnswerExt2](t, l).File.HasRoot {
		t.Fatal("root without a tree")
	}
}

func TestHashSetRequest2(t *testing.T) {
	l := buildLink(t)
	size := piece.PartSize + 1
	file, _ := addShare(l.b, 1, size, false)
	l.run(l.a, Output{Send: []wire.Packet{client.HashSetRequest2{File: client.FileIdentifier{Hash: file, Size: uint64(size)}, IsMD4Wanted: true, IsAICHWanted: true}}})
	answer := sentOf[client.HashSetAnswer2](t, l)
	if answer.File != (client.FileIdentifier{Hash: file, Size: uint64(size)}) || !slices.Equal(answer.Parts, l.b.shares[file].PartHashes) {
		t.Fatalf("answer %+v", answer)
	}

	l.run(l.a, Output{Send: []wire.Packet{client.HashSetRequest2{File: client.FileIdentifier{Hash: hashOf(7)}, IsMD4Wanted: true}}})
	if l.b.closed != closeProtocol {
		t.Fatalf("closed %q on an unknown file", l.b.closed)
	}
}
