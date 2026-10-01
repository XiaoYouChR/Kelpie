package peer

import (
	"testing"

	"github.com/XiaoYouChR/Kelpie/internal/aich"
	"github.com/XiaoYouChR/Kelpie/internal/piece"
	"github.com/XiaoYouChR/Kelpie/internal/wire"
	"github.com/XiaoYouChR/Kelpie/internal/wire/client"
)

// addTreeShare shares a file of size on e together with its AICH tree.
func addTreeShare(e *side, size int64) (wire.Hash, *aich.Tree) {
	file, data := addShare(e, 1, size, false)
	var hasher aich.Hasher
	hasher.Write(data)
	share := e.shares[file]
	share.Tree = aich.BuildTree(size, hasher.Leaves())
	e.shares[file] = share
	return file, share.Tree
}

func TestRootComesWithFileRequest(t *testing.T) {
	l := buildLink(t)
	size := piece.PartSize + 1000
	file, tree := addTreeShare(l.b, size)
	l.run(l.a, l.a.s.Add(file, size, piece.Set{false, false}))
	if got := lastOf[RootReceived](t, l.a); got != (RootReceived{File: file, Root: tree.Root()}) {
		t.Fatalf("root %+v", got)
	}
	if sentCount[client.AICHFileHashAnswer](l) != 0 {
		t.Fatal("root sent outside the MultiPacketAnswer")
	}
}

func TestMissingTreeIsWanted(t *testing.T) {
	l := buildLink(t)
	size := 3 * piece.BlockSize
	file, _ := addShare(l.b, 1, size, false)
	l.run(l.a, l.a.s.Add(file, size, piece.Set{false}))
	if got := lastOf[TreeWanted](t, l.b); got.File != file {
		t.Fatalf("wanted %+v", got)
	}
	if len(eventsOf[RootReceived](l.a)) != 0 {
		t.Fatal("got a root from a share without a tree")
	}
}

func TestRecoveryRoundTrip(t *testing.T) {
	l := buildLink(t)
	size := 2*piece.PartSize + 1000
	file, tree := addTreeShare(l.b, size)
	l.run(l.a, l.a.s.Add(file, size, piece.Set{false, false, false}))

	l.run(l.a, l.a.s.RequestRecovery(file, 1, tree.Root()))
	got := lastOf[RecoveryReceived](t, l.a)
	if got.File != file || got.Part != 1 || got.Root != tree.Root() {
		t.Fatalf("recovery %+v", got)
	}
	if _, ok := aich.MatchRecovery(tree.Root(), size, 1, got.Entries); !ok {
		t.Fatal("recovery data does not match the root")
	}

	l.run(l.a, l.a.s.RequestRecovery(file, 1, wire.AICHHash{1}))
	if got := lastOf[RecoveryFailed](t, l.a); got.File != file {
		t.Fatalf("failed %+v", got)
	}
	if l.a.closed != "" || l.b.closed != "" {
		t.Fatal("a refused request closed the connection")
	}
}

func TestOneRecoveryRequestAtATime(t *testing.T) {
	l := buildLink(t)
	out := l.a.s.RequestRecovery(hashOf(1), 0, wire.AICHHash{})
	if len(out.Send) != 1 {
		t.Fatalf("first request sent %v", out.Send)
	}
	out = l.a.s.RequestRecovery(hashOf(2), 0, wire.AICHHash{})
	if len(out.Send) != 0 || len(out.Events) != 1 || out.Events[0] != (RecoveryFailed{File: hashOf(2)}) {
		t.Fatalf("second request: %+v", out)
	}
}

func TestUnrequestedRecoveryCloses(t *testing.T) {
	l := buildLink(t)
	l.run(l.b, Output{Send: []wire.Packet{client.AICHAnswer{Hash: hashOf(1)}}})
	if l.a.closed != closeProtocol {
		t.Fatalf("closed = %q", l.a.closed)
	}
}
