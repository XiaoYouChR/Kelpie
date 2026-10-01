package engine

import (
	"net/netip"

	"github.com/XiaoYouChR/Kelpie/internal/kad"
	"github.com/XiaoYouChR/Kelpie/internal/wire"
	"github.com/XiaoYouChR/Kelpie/internal/wire/client"
)

// Kad version 7 takes the TCP firewall acknowledgement over TCP
// (ClientList.cpp:590); version 6 is the first that can run a UDP test
// (BaseClient.cpp:2905).
const (
	versionTCPFirewallAck = 7
	versionUDPCheck       = 6
)

// kadCheck is a connection we opened for Kad: to show a node that its TCP
// port is open (udp nil), or to have a client send us a UDP test.
type kadCheck struct {
	kadPort uint16
	udp     *kad.UDPCheck
	isSent  bool
}

func (e *Engine) onKadRequest(r kad.Request) {
	switch r := r.(type) {
	case kad.FirewallCheck:
		e.startFirewallCheck(r)
	case kad.UDPCheck:
		e.startUDPCheck(r)
	case kad.BuddyFound:
		e.onBuddyFound(r)
	case kad.BuddyRequested:
		e.buddy.incoming[r.Addr.Addr()] = incomingBuddy{user: r.UserHash, id: r.BuddyID, added: e.now()}
	case kad.CallbackRequested:
		e.onCallbackRequested(r)
	}
}

// startFirewallCheck is ClientList::RequestTCP: connect to the asker, with
// obfuscation when it supports it, and acknowledge after the handshake.
// aMule also acknowledges over a connection the asker opened, which proves
// nothing about its port; we skip that check instead.
func (e *Engine) startFirewallCheck(r kad.FirewallCheck) {
	if c := e.connByEndpoint(r.Addr); c != nil {
		if c.isOutgoing && c.isHandshaken {
			e.sendFirewallAck(c, r.KadPort)
		}
		return
	}
	if len(e.conns) >= maxConnections {
		return
	}
	var obfuscateFor wire.Hash
	if r.CryptOptions&wire.CryptSupported != 0 {
		obfuscateFor = r.UserHash
	}
	c := e.openConn(r.Addr, false, obfuscateFor, 0)
	e.kadChecks[c.id] = kadCheck{kadPort: r.KadPort}
}

func (e *Engine) sendFirewallAck(c *conn, kadPort uint16) {
	if c.session.Capabilities().KadVersion >= versionTCPFirewallAck {
		e.sendPacket(c, client.KadFirewallAck{}, wire.Hash{}, 0)
		return
	}
	e.kad.RequestFirewallAck(netip.AddrPortFrom(c.remote.Addr(), kadPort))
}

// startUDPCheck is ClientList::DoRequestFirewallCheckUDP: a client we
// already talk to cannot show that strangers reach us.
func (e *Engine) startUDPCheck(r kad.UDPCheck) {
	for _, c := range e.conns {
		if !c.isServer && c.remote.Addr() == r.Addr.Addr() {
			e.kad.SendUDPCheckEnded(kad.UDPCheckEnded{IP: r.Addr.Addr(), IsCancelled: true})
			return
		}
	}
	if len(e.conns) >= maxConnections {
		e.kad.SendUDPCheckEnded(kad.UDPCheckEnded{IP: r.Addr.Addr(), IsCancelled: true})
		return
	}
	c := e.openConn(r.Addr, false, wire.Hash{}, 0)
	e.kadChecks[c.id] = kadCheck{udp: &r}
}

// onKadHandshake runs the Kad check a connection was opened for
// (BaseClient.cpp:1660-1672).
func (e *Engine) onKadHandshake(c *conn) {
	check, ok := e.kadChecks[c.id]
	if !ok {
		return
	}
	if check.udp == nil {
		delete(e.kadChecks, c.id)
		e.sendFirewallAck(c, check.kadPort)
		return
	}
	caps := c.session.Capabilities()
	if caps.KadVersion < versionUDPCheck || caps.KadPort == 0 {
		delete(e.kadChecks, c.id)
		e.kad.SendUDPCheckEnded(kad.UDPCheckEnded{IP: c.remote.Addr(), IsCancelled: true})
		return
	}
	check.isSent = true
	e.kadChecks[c.id] = check
	e.sendPacket(c, client.FirewallCheckUDPReq{InternPort: check.udp.InternPort, ExternPort: check.udp.ExternPort, Key: check.udp.Key}, wire.Hash{}, 0)
}

// onKadConnClosed ends a UDP test whose answer did not come while the
// connection lasted: a failure once the request went out.
func (e *Engine) onKadConnClosed(c *conn) {
	check, ok := e.kadChecks[c.id]
	if !ok {
		return
	}
	delete(e.kadChecks, c.id)
	if check.udp != nil {
		e.kad.SendUDPCheckEnded(kad.UDPCheckEnded{IP: c.remote.Addr(), IsCancelled: !check.isSent})
	}
}

// onKadPacket acts on the Kad packets a peer connection carries. The
// session sees them too, as activity.
func (e *Engine) onKadPacket(c *conn, p wire.Packet) {
	switch p := p.(type) {
	case client.KadFirewallAck:
		if e.kad != nil {
			e.kad.SendFirewallAck(c.remote.Addr())
		}
	case client.FirewallCheckUDPReq:
		if e.kad != nil {
			e.kad.RequestFirewallUDP(kad.FirewallUDP{
				IP: c.remote.Addr(), InternPort: p.InternPort, ExternPort: p.ExternPort, Key: p.Key,
				IsKnown: len(c.files) > 0 || c.isUploading,
			})
		}
	case client.BuddyPing:
		e.onBuddyPing(c)
	case client.BuddyPong:
		e.onBuddyPong(c)
	case client.Callback:
		e.onCallback(p)
	case client.ReaskCallbackTCP:
		e.onReaskCallbackTCP(c, p)
	}
}
