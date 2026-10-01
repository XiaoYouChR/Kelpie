package server

import (
	"testing"

	"github.com/XiaoYouChR/Kelpie/internal/wire"
)

func addSeeds(f *testing.F, packets []wire.Packet) {
	for _, p := range packets {
		f.Add(p.Protocol(), p.Opcode(), p.Build(nil))
	}
}

func FuzzParse(f *testing.F) {
	addSeeds(f, samplePackets())
	f.Fuzz(func(t *testing.T, protocol, opcode byte, body []byte) {
		if p, err := Parse(protocol, opcode, body); err == nil {
			p.Build(nil)
		}
	})
}

func FuzzParseUDP(f *testing.F) {
	addSeeds(f, sampleUDPPackets())
	f.Fuzz(func(t *testing.T, protocol, opcode byte, body []byte) {
		if p, err := ParseUDP(protocol, opcode, body); err == nil {
			p.Build(nil)
		}
	})
}
