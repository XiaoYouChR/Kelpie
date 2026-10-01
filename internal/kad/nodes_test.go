package kad

import (
	"encoding/binary"
	"net/netip"
	"os"
	"testing"

	"github.com/XiaoYouChR/Kelpie/internal/wire"
)

func mustHash(s string) wire.Hash {
	h, err := wire.ParseHash(s)
	if err != nil {
		panic(err)
	}
	return h
}

func TestParseNodesReadsShippedFile(t *testing.T) {
	data, err := os.ReadFile("testdata/nodes.dat")
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := ParseNodes(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) < 150 || len(nodes) > 190 {
		t.Fatalf("got %d nodes from a 190-contact file", len(nodes))
	}
	want := Node{
		ID:      mustHash("D3D14E61375B52798EADD3CF6AF38D2C"),
		Addr:    netip.MustParseAddrPort("92.209.217.37:15854"),
		TCPPort: 28006,
		Version: 9,
	}
	if nodes[0] != want {
		t.Fatalf("first node %+v, want %+v", nodes[0], want)
	}
}

func buildNodeEntry(b []byte, n Node, typeOrVersion byte) []byte {
	b = buildID(b, n.ID)
	ip := n.Addr.Addr().As4()
	b = binary.LittleEndian.AppendUint32(b, binary.BigEndian.Uint32(ip[:]))
	b = binary.LittleEndian.AppendUint16(b, n.Addr.Port())
	b = binary.LittleEndian.AppendUint16(b, n.TCPPort)
	return append(b, typeOrVersion)
}

func TestParseNodesVersions(t *testing.T) {
	a := Node{ID: mustHash("0102030405060708090A0B0C0D0E0F10"), Addr: netip.MustParseAddrPort("1.2.3.4:4672"), TCPPort: 4662, Version: 8}
	dead := Node{ID: mustHash("1102030405060708090A0B0C0D0E0F10"), Addr: netip.MustParseAddrPort("1.2.3.5:4672"), TCPPort: 4662}
	noPort := Node{ID: mustHash("2102030405060708090A0B0C0D0E0F10"), Addr: netip.MustParseAddrPort("1.2.3.6:0"), TCPPort: 4662, Version: 8}

	v0 := binary.LittleEndian.AppendUint32(nil, 2)
	v0 = buildNodeEntry(v0, a, 0)
	v0 = buildNodeEntry(v0, dead, 4)

	v1 := binary.LittleEndian.AppendUint32(nil, 0)
	v1 = binary.LittleEndian.AppendUint32(v1, 1)
	v1 = binary.LittleEndian.AppendUint32(v1, 2)
	v1 = buildNodeEntry(v1, a, a.Version)
	v1 = buildNodeEntry(v1, noPort, noPort.Version)

	v2 := binary.LittleEndian.AppendUint32(nil, 0)
	v2 = binary.LittleEndian.AppendUint32(v2, 2)
	v2 = binary.LittleEndian.AppendUint32(v2, 1)
	v2 = append(buildNodeEntry(v2, a, a.Version), make([]byte, 9)...)

	bootstrap := binary.LittleEndian.AppendUint32(nil, 0)
	bootstrap = binary.LittleEndian.AppendUint32(bootstrap, 3)
	bootstrap = binary.LittleEndian.AppendUint32(bootstrap, 1)
	bootstrap = binary.LittleEndian.AppendUint32(bootstrap, 1)
	bootstrap = buildNodeEntry(bootstrap, a, a.Version)

	v3 := binary.LittleEndian.AppendUint32(nil, 0)
	v3 = binary.LittleEndian.AppendUint32(v3, 3)
	v3 = binary.LittleEndian.AppendUint32(v3, 0)
	v3 = binary.LittleEndian.AppendUint32(v3, 1)
	v3 = append(buildNodeEntry(v3, a, a.Version), make([]byte, 9)...)

	withoutVersion := a
	withoutVersion.Version = 0
	for name, tc := range map[string]struct {
		data []byte
		want Node
	}{
		"version 0":           {v0, withoutVersion},
		"version 1":           {v1, a},
		"version 2":           {v2, a},
		"version 3 bootstrap": {bootstrap, a},
		"version 3":           {v3, a},
	} {
		nodes, err := ParseNodes(tc.data)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(nodes) != 1 || nodes[0] != tc.want {
			t.Fatalf("%s: got %+v, want [%+v]", name, nodes, tc.want)
		}
	}
}

func TestParseNodesRejectsGarbage(t *testing.T) {
	for name, data := range map[string][]byte{
		"empty":         nil,
		"short":         {0, 0, 0, 0, 2, 0, 0, 0, 5, 0, 0, 0, 1, 2},
		"version 9":     {0, 0, 0, 0, 9, 0, 0, 0, 1, 0, 0, 0},
		"no contacts":   {0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0},
		"count too big": binary.LittleEndian.AppendUint32(nil, 1000),
	} {
		if _, err := ParseNodes(data); err == nil {
			t.Fatalf("%s: no error", name)
		}
	}
}
