package client

import (
	"encoding/binary"

	"github.com/XiaoYouChR/Kelpie/internal/wire"
)

// Kad packets that travel over a client TCP connection (aMule
// include/protocol/kad2/Client2Client/TCP.h).
const (
	opFirewallCheckUDPReq byte = 0xA7
	opKadFirewallAck      byte = 0xA8
)

// FirewallCheckUDPReq is OP_FWCHECKUDPREQ: send a KADEMLIA2_FIREWALLUDP to
// each of the sender's Kad ports, encrypted with Key when it is not zero.
type FirewallCheckUDPReq struct {
	InternPort uint16
	ExternPort uint16
	Key        uint32
}

func (FirewallCheckUDPReq) Protocol() byte { return wire.ProtocolEMule }
func (FirewallCheckUDPReq) Opcode() byte   { return opFirewallCheckUDPReq }
func (p FirewallCheckUDPReq) Build(b []byte) []byte {
	b = binary.LittleEndian.AppendUint16(b, p.InternPort)
	b = binary.LittleEndian.AppendUint16(b, p.ExternPort)
	return binary.LittleEndian.AppendUint32(b, p.Key)
}

// KadFirewallAck is OP_KAD_FWTCPCHECK_ACK: the Kad node we asked to check
// our TCP port reached it.
type KadFirewallAck struct{}

func (KadFirewallAck) Protocol() byte        { return wire.ProtocolEMule }
func (KadFirewallAck) Opcode() byte          { return opKadFirewallAck }
func (KadFirewallAck) Build(b []byte) []byte { return b }
