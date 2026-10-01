package aich

import (
	"testing"

	"github.com/XiaoYouChR/Kelpie/internal/piece"
	"github.com/XiaoYouChR/Kelpie/internal/wire"
	"github.com/XiaoYouChR/Kelpie/internal/wire/client"
)

// FuzzMatchRecovery checks recovery data from a peer's AICH answer. The size
// and the part are ours, so they stay in range: an eD2k file of at most
// 256 GiB and a part of it.
func FuzzMatchRecovery(f *testing.F) {
	const maxSize = 256 << 30
	size := 3*piece.PartSize + 500_000
	tree := buildTree(buildData(size))
	for part := range piece.PartCount(size) {
		answer := client.AICHAnswer{HasData: true, Part: uint16(part), Root: tree.Root(), Entries: tree.BuildRecovery(part)}
		f.Add(int64(0), uint16(part), answer.Build(nil)[2:])
	}
	long := client.AICHAnswer{HasData: true, Part: 700, HasLongIdents: true, Entries: []client.AICHEntry{{Ident: 0x10000}}}
	f.Add(int64(maxSize), uint16(700), long.Build(nil)[2:])
	f.Fuzz(func(t *testing.T, fileSize int64, part uint16, body []byte) {
		p, err := client.Parse(wire.ProtocolEMule, long.Build(nil)[1], body)
		if err != nil {
			return
		}
		answer := p.(client.AICHAnswer)
		root, total := tree.Root(), size
		if fileSize > 0 {
			root, total = answer.Root, min(fileSize, maxSize)
		}
		index := int(part) % piece.PartCount(total)
		hashes, ok := MatchRecovery(root, total, index, answer.Entries)
		if ok && len(hashes) != piece.BlockCount(total, index) {
			t.Fatalf("%d hashes for %d blocks", len(hashes), piece.BlockCount(total, index))
		}
	})
}
