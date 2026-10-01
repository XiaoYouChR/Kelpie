package obfuscation

import (
	"bytes"
	"net/netip"
	"testing"
)

func TestKadDatagramRoundTrip(t *testing.T) {
	nodeID := bytes.Repeat([]byte{0x5A}, 16)
	packet := []byte{0xE4, 0x60}
	d := KadDatagram{Packet: packet, ReceiverKey: 0x11223344, SenderKey: 0x55667788}

	byID := BuildKadDatagram(d, nodeID, 0x00AB1234)
	if len(byID) != 3+kadHeader-3+len(packet) || byID[0]&0x03 != 0 || bytes.Contains(byID, packet) {
		t.Fatalf("datagram by node ID %x", byID)
	}
	got, ok := ParseKadDatagram(byID, nodeID, 0)
	if !ok || !bytes.Equal(got.Packet, packet) || got.ReceiverKey != d.ReceiverKey || got.SenderKey != d.SenderKey {
		t.Fatalf("parsed %+v, %v", got, ok)
	}

	byKey := BuildKadDatagram(d, nil, 0x00AB1234)
	if byKey[0]&0x03 != 0x02 {
		t.Fatalf("receiver key marker %#x", byKey[0])
	}
	if got, ok := ParseKadDatagram(byKey, nodeID, d.ReceiverKey); !ok || !bytes.Equal(got.Packet, packet) {
		t.Fatalf("parsed %+v, %v", got, ok)
	}
	if _, ok := ParseKadDatagram(byKey, nodeID, d.ReceiverKey+1); ok {
		t.Fatal("decrypted with the wrong receiver key")
	}
	if _, ok := ParseKadDatagram(append([]byte{0xE4, 0x60}, make([]byte, 20)...), nodeID, 1); ok {
		t.Fatal("took a plain Kad datagram for an obfuscated one")
	}
}

func TestKadMarkerIsNeverAProtocolByte(t *testing.T) {
	for random := range uint32(256) {
		for _, nodeID := range [][]byte{make([]byte, 16), nil} {
			if b := BuildKadDatagram(KadDatagram{Packet: []byte{1}}, nodeID, random<<16)[0]; matchPlainDatagram(b) {
				t.Fatalf("marker %#x", b)
			}
		}
	}
}

func TestKadVerifyKey(t *testing.T) {
	ip := netip.MustParseAddr("198.51.100.7")
	key := BuildKadVerifyKey(0xCAFEBABE, ip)
	if key == 0 || key != BuildKadVerifyKey(0xCAFEBABE, ip) || key == BuildKadVerifyKey(0xCAFEBABF, ip) ||
		key == BuildKadVerifyKey(0xCAFEBABE, netip.MustParseAddr("198.51.100.8")) {
		t.Fatalf("verify key %#x", key)
	}
}
