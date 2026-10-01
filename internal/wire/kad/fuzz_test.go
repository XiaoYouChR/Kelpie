package kad

import (
	"testing"
)

func FuzzParse(f *testing.F) {
	for _, p := range samplePackets() {
		d := p.Build(nil)
		f.Add(d[0], d[1], d[2:])
	}
	f.Fuzz(func(t *testing.T, protocol, opcode byte, body []byte) {
		if p, err := Parse(protocol, opcode, body); err == nil {
			p.Build(nil)
		}
	})
}
