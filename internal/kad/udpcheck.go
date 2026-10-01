package kad

import (
	"net/netip"
	"slices"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/wire"
	kadwire "github.com/XiaoYouChR/Kelpie/internal/wire/kad"
)

// aMule kademlia/kademlia/UDPFirewallTester.h, Prefs.cpp and Kademlia.cpp.
const (
	udpCheckClients  = 2               // UDP_FIREWALLTEST_CLIENTSTOASK
	udpCheckTimeout  = 6 * time.Minute // IsFirewalledUDP: firewalled after 6 min without results
	externPortAsks   = 3               // EXTERNAL_PORT_ASKIPS
	externPortGap    = 15 * time.Second
	versionUDPCheck  = 6 // QueryNextClient: clients up to version 5 cannot test
	versionPingRange = 6 // GetRandomContact(3, 6) for the extern port ping
)

// udpCheck is aMule's CUDPFirewallTester: whether other clients can reach
// our Kad port unasked. Clients that never heard from us over UDP, found
// by a lookup of a random ID, are asked over TCP to send us a test packet;
// one arriving means open, two clients without one mean firewalled.
// Before asking, our external port is learnt from the PONGs of three nodes.
type udpCheck struct {
	isFirewalled     bool
	isLastFirewalled bool
	isVerified       bool
	isTimedOut       bool
	running          int
	finished         int
	started          time.Time
	possible         []Node
	// asked holds every IP asked for a test, true once it answered; aMule
	// keeps it across rechecks so an IP is asked only once.
	asked map[netip.Addr]bool
	// useExternPort is false once a test packet came in on our own port, so
	// that port, not the NAT's, is what others should use.
	useExternPort  bool
	externPort     uint16
	externIPs      []netip.Addr
	externPorts    []uint16
	nextExternPing time.Time
	lookup         *lookup
}

func buildUDPCheck() udpCheck {
	return udpCheck{asked: map[netip.Addr]bool{}, useExternPort: true}
}

func (u *udpCheck) isRunning() bool { return u.finished < udpCheckClients }

// isFirewalledNow is IsFirewalledUDP(true): while a test runs the previous
// verdict stands, unless it timed out.
func (u *udpCheck) isFirewalledNow() bool {
	switch {
	case u.isTimedOut && u.isRunning():
		return true
	case u.isRunning():
		return u.isLastFirewalled
	}
	return u.isFirewalled
}

// isOpen is what a direct callback or serving as a buddy needs: a verdict
// of open that a test confirmed.
func (u *udpCheck) isOpen() bool { return !u.isFirewalledNow() && u.isVerified }

func (u *udpCheck) isFindingExternPort() bool { return len(u.externIPs) < externPortAsks }

// setExternPort is CPrefs::SetExternKadPort: two nodes agreeing on a port
// settle it; three disagreeing make it unreliable.
func (u *udpCheck) setExternPort(port uint16, from netip.Addr) {
	if !u.isFindingExternPort() || slices.Contains(u.externIPs, from) {
		return
	}
	u.externIPs = append(u.externIPs, from)
	if slices.Contains(u.externPorts, port) {
		u.externPort = port
		for u.isFindingExternPort() {
			u.externIPs = append(u.externIPs, netip.Addr{})
		}
		return
	}
	u.externPorts = append(u.externPorts, port)
	if !u.isFindingExternPort() {
		u.externPort = 0
	}
}

// recheckUDP is ReCheckFirewallUDP(false), run with every TCP firewall
// recheck: a new lookup for test clients and a new extern port.
func (c *core) recheckUDP(now time.Time) {
	u := &c.udp
	u.running, u.finished = 0, 0
	u.started = now
	u.isTimedOut = false
	u.isLastFirewalled = u.isFirewalled
	u.externIPs, u.externPorts = nil, nil
	u.possible = nil
	c.cancelLookup(u.lookup)
	u.lookup = c.startLookup(udpCheckLookup, buildRandomID(c.id, 0, 0, c.rng), 0, now)
}

// runUDPCheck runs once a second while Kad is connected.
func (c *core) runUDPCheck(now time.Time) {
	u := &c.udp
	if !u.isTimedOut && u.isRunning() && !u.isFirewalled && !u.isVerified && c.firewall.isFirewalled() &&
		!u.started.IsZero() && now.Sub(u.started) > udpCheckTimeout {
		u.isTimedOut = true
	}
	if !u.isRunning() || !u.isFindingExternPort() || now.Before(u.nextExternPing) {
		return
	}
	u.nextExternPing = now.Add(externPortGap)
	for _, ct := range c.table.closestContacts(buildRandomID(c.id, 0, 0, c.rng), len(c.table.byID), true) {
		if ct.Version >= versionPingRange {
			c.send(ct.Addr, kadwire.Ping{})
			c.rpcs.add(&rpc{kind: rpcPing, node: ct.Node, sent: now})
			return
		}
	}
}

func (c *core) onPong(from netip.AddrPort, p kadwire.Pong) {
	if c.rpcs.match(from, rpcPing, wire.Hash{}) == nil || !c.udp.isFindingExternPort() {
		return
	}
	c.udp.setExternPort(p.UDPPort, from.Addr())
	c.queryUDPCheck()
}

// addUDPCheckClients takes the contacts of a test-client lookup answer.
// They stay out of the routing table: a client we have sent UDP to cannot
// test whether others reach us.
func (c *core) addUDPCheckClients(contacts []kadwire.Contact) {
	for _, ct := range contacts {
		n := Node{ID: ct.ID, Addr: netip.AddrPortFrom(ct.Addr, ct.UDPPort), TCPPort: ct.TCPPort, Version: ct.Version}
		if ct.Version > 1 && matchGoodAddr(n.Addr) && c.udp.isRunning() {
			c.udp.possible = append([]Node{n}, c.udp.possible...)
		}
	}
	c.queryUDPCheck()
}

// queryUDPCheck is QueryNextClient: it asks the next suitable client while
// fewer than two tests ran and our extern port is known.
func (c *core) queryUDPCheck() {
	u := &c.udp
	if !u.isRunning() || u.running+u.finished >= udpCheckClients || u.isFindingExternPort() {
		return
	}
	for len(u.possible) > 0 {
		n := u.possible[0]
		u.possible = u.possible[1:]
		ip := n.Addr.Addr()
		if n.Version < versionUDPCheck || ip == c.publicIP || n.ID == c.id {
			continue
		}
		if _, ok := u.asked[ip]; ok || c.table.hasIP(ip) {
			continue
		}
		u.asked[ip] = false
		u.running++
		c.out.requests = append(c.out.requests, UDPCheck{
			Addr:       netip.AddrPortFrom(ip, n.TCPPort),
			InternPort: c.udpPort,
			ExternPort: u.externPort,
		})
		return
	}
}

// onFirewalledUDP is Process2FirewallUDP: a test packet counts only if it
// was sent to one of our ports.
func (c *core) onFirewalledUDP(from netip.AddrPort, p kadwire.FirewalledUDP) {
	isOurPort := p.Port != 0 && (p.Port == c.udpPort || p.Port == c.udp.externPort)
	c.setUDPCheckResult(from.Addr(), isOurPort && p.ErrorCode == 0, !isOurPort || p.ErrorCode != 0, p.Port)
}

func (c *core) onUDPCheckEnded(e UDPCheckEnded) {
	c.setUDPCheckResult(e.IP, false, e.IsCancelled, 0)
}

// setUDPCheckResult is SetUDPFWCheckResult. A test sends two packets and
// the connection closes later, so only the first word from an IP counts.
func (c *core) setUDPCheckResult(ip netip.Addr, isSucceeded, isCancelled bool, port uint16) {
	u := &c.udp
	isAnswered, ok := u.asked[ip]
	if !ok || isAnswered {
		return
	}
	u.asked[ip] = true
	if !u.isRunning() || u.running == 0 {
		return
	}
	u.running--
	if !isCancelled {
		u.finished++
		if isSucceeded {
			u.started = time.Time{}
			u.isFirewalled, u.isVerified, u.isTimedOut = false, true, false
			u.finished, u.running = udpCheckClients, 0
			u.possible = nil
			c.cancelLookup(u.lookup)
			switch {
			case port == c.udpPort:
				u.useExternPort = false
			case port == u.externPort:
				u.useExternPort = true
			}
			return
		}
		if u.finished >= udpCheckClients {
			u.started = time.Time{}
			u.isFirewalled, u.isVerified, u.isTimedOut = true, true, false
			u.possible = nil
			c.cancelLookup(u.lookup)
			return
		}
	}
	c.queryUDPCheck()
}

// onFirewallUDP answers a client's OP_FWCHECKUDPREQ, as
// CUpDownClient::ProcessFirewallCheckUDPRequest does: one packet to each
// port, flagged when we know the client already.
func (c *core) onFirewallUDP(r FirewallUDP) {
	if !r.IP.Is4() || r.InternPort == 0 {
		return
	}
	var code byte
	if r.IsKnown || c.table.hasIP(r.IP) {
		code = 1
	}
	c.send(netip.AddrPortFrom(r.IP, r.InternPort), kadwire.FirewalledUDP{ErrorCode: code, Port: r.InternPort})
	if r.ExternPort != 0 && r.ExternPort != r.InternPort {
		c.send(netip.AddrPortFrom(r.IP, r.ExternPort), kadwire.FirewalledUDP{ErrorCode: code, Port: r.ExternPort})
	}
}
