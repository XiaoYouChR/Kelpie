package kad

import (
	"testing"
)

func FuzzParse(f *testing.F) {
	for _, p := range samplePackets() {
		f.Add(p.Protocol(), p.Opcode(), p.Build(nil))
	}
	f.Fuzz(func(t *testing.T, protocol, opcode byte, body []byte) {
		if p, err := Parse(protocol, opcode, body); err == nil {
			p.Build(nil)
		}
	})
}
