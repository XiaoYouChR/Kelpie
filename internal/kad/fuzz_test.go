package kad

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/wire"
	kadwire "github.com/XiaoYouChR/Kelpie/internal/wire/kad"
)

func FuzzParseNodes(f *testing.F) {
	data, err := os.ReadFile("testdata/nodes.dat")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(data)
	a := Node{ID: fileHash, Addr: netip.MustParseAddrPort("1.2.3.4:4672"), TCPPort: 4662, Version: 8}
	v0 := buildNodeEntry(binary.LittleEndian.AppendUint32(nil, 1), a, 0)
	f.Add(v0)
	v3 := binary.LittleEndian.AppendUint32(nil, 0)
	v3 = binary.LittleEndian.AppendUint32(v3, 3)
	v3 = binary.LittleEndian.AppendUint32(v3, 0)
	v3 = binary.LittleEndian.AppendUint32(v3, 1)
	f.Add(append(buildNodeEntry(v3, a, a.Version), make([]byte, 9)...))
	f.Fuzz(func(t *testing.T, data []byte) {
		ParseNodes(data)
	})
}

// toPacked compresses a Kad datagram's body under 0xE5, as eMule sends
// large answers.
func toPacked(d []byte) []byte {
	var body bytes.Buffer
	zw := zlib.NewWriter(&body)
	zw.Write(d[2:])
	zw.Close()
	return append([]byte{wire.ProtocolKadPacked, d[1]}, body.Bytes()...)
}

// buildDatagrams frames datagrams for FuzzDatagrams: one byte choosing the
// sender among the core's contacts, a uint16 length, the datagram.
func buildDatagrams(packets ...wire.Packet) []byte {
	var b []byte
	for i, p := range packets {
		d := p.Build(nil)
		if i%2 == 1 {
			d = toPacked(d)
		}
		b = append(b, byte(i))
		b = binary.LittleEndian.AppendUint16(b, uint16(len(d)))
		b = append(b, d...)
	}
	return b
}

// FuzzDatagrams feeds datagrams to a core that is connected and searching,
// the way Kad.Run does, ticking between them so lookups and RPCs advance.
func FuzzDatagrams(f *testing.F) {
	near := buildNear(fileHash, 0)
	contact := kadwire.Contact{ID: near.ID, Addr: near.Addr.Addr(), UDPPort: near.Addr.Port(), TCPPort: near.TCPPort, Version: near.Version}
	f.Add(buildDatagrams(
		kadwire.Res{Target: fileHash, Contacts: []kadwire.Contact{contact}},
		kadwire.SearchRes{Source: near.ID, Target: fileHash, Results: []kadwire.Entry{
			buildOpenEntry(userHash, "5.6.7.8", 4662),
			buildFirewalledEntry(userHash, near.ID, netip.MustParseAddrPort("9.9.9.9:4662")),
		}},
		kadwire.BootstrapRes{ID: near.ID, TCPPort: 4662, Version: 9, Contacts: []kadwire.Contact{contact}},
		kadwire.HelloReq{ID: near.ID, TCPPort: 4662, Version: 9},
		kadwire.HelloRes{ID: near.ID, TCPPort: 4662, Version: 9},
		kadwire.Req{SearchType: kadwire.FindNode, Target: fileHash, Receiver: selfID},
		kadwire.PublishSourcesReq{FileID: fileHash, Source: buildOpenEntry(userHash, "5.6.7.8", 4662)},
		kadwire.SearchSourcesReq{Target: fileHash, Size: 1000},
		kadwire.PublishRes{FileID: fileHash, Load: 3},
		kadwire.FirewalledRes{Addr: netip.MustParseAddr("5.6.7.8")},
		kadwire.Ping{},
		kadwire.BootstrapReq{},
	))
	f.Fuzz(func(t *testing.T, data []byte) {
		h := buildHarness(t)
		nodes := h.connect(fileHash, 6)
		clear(h.answering)
		h.c.setWanted(Wanted{Find: []Search{{Hash: fileHash, Size: 1000}}, Publish: []Publish{{Hash: userHash, Size: 1000}}}, h.now)
		h.tick(time.Second)
		for len(data) >= 3 {
			from := nodes[int(data[0])%len(nodes)].Addr
			size := min(int(binary.LittleEndian.Uint16(data[1:3])), len(data)-3)
			datagram := data[3 : 3+size]
			data = data[3+size:]
			if p, ok := parsePacket(datagram); ok {
				h.receive(from, p)
			}
			h.tick(time.Second)
		}
	})
}
