// Derived from goed2k dht_tracker.go and kad_node.go.

package kad

import (
	"math/rand/v2"
	"net/netip"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/obfuscation"
	"github.com/XiaoYouChR/Kelpie/internal/wire"
	kadwire "github.com/XiaoYouChR/Kelpie/internal/wire/kad"
)

// eMule opcodes.h and CKademlia::Process.
const (
	fileSearchGap    = time.Second      // KADEMLIAASKTIME: one new source search a second
	maxFileSearches  = 5                // KADEMLIATOTALFILE
	reaskSources     = time.Hour        // KADEMLIAREASKTIME, times the search count...
	maxReaskFactor   = 7                // ...which CPartFile caps at 7 (m_TotalSearchesKad)
	publishGap       = 2 * time.Second  // KADEMLIAPUBLISHTIME
	maxPublishes     = 3                // KADEMLIATOTALSTORESRC
	bootstrapGap     = 2 * time.Second  // CKademlia::Process, while it has no contacts
	selfLookupGap    = 4 * time.Hour    // m_tNextSelfLookup
	bucketRefreshGap = 10 * time.Second // m_bigTimer: one leaf lookup every 10 s...
	bucketLookupGap  = time.Hour        // ...each leaf at most hourly (m_nextBigTimer)
	sparseLeaf       = 2                // CRoutingZone::OnBigTimer: only leaves with GetRemaining() >= K * 0.8
	bucketCheckGap   = time.Minute      // CRoutingZone::OnSmallTimer, per leaf
	contactRecheck   = time.Hour        // CContact::UpdateType: a fresh contact expires in an hour
	firewallCheckGap = time.Hour        // m_tNextFirewallCheck
	firewallChecks   = 4                // KADEMLIAFIREWALLCHECKS
	firewallOpenAcks = 2                // CPrefs::GetFirewalled: two acks mean open
	bootstrapAnswer  = 20               // Process_KADEMLIA2_BOOTSTRAP_REQ returns 20 contacts
	indexCleanupGap  = time.Minute
	// Kad versions 7 and up understand KADEMLIA_FIREWALLED2_REQ
	// (KADEMLIA_VERSION7_49a).
	versionFirewalled2 = 7
)

// datagram is a packet to send. It is obfuscated with nodeID when that is
// set, else with receiverKey when that is set, and sent plain otherwise.
type datagram struct {
	to          netip.AddrPort
	packet      wire.Packet
	nodeID      wire.Hash
	receiverKey uint32
	senderKey   uint32
}

// Kad version 6 is the first that reads obfuscated datagrams
// (KademliaUDPListener.cpp:205).
const versionObfuscation = 6

type output struct {
	datagrams []datagram
	found     []SourcesFound
	requests  []Request
}

type find struct {
	Search
	searches int
	next     time.Time
	lookup   *lookup
}

type publish struct {
	Publish
	next   time.Time
	lookup *lookup
}

// firewall follows eMule's CPrefs: a check round asks up to four nodes to
// connect to our TCP port; two acknowledgements mean we are open. During a
// round the previous round's verdict stands.
type firewall struct {
	isLastFirewalled bool
	responses        int
	acks             int
	asked            map[netip.Addr]bool
	next             time.Time
}

func (f *firewall) isFirewalled() bool {
	if f.acks >= firewallOpenAcks {
		return false
	}
	if f.responses < firewallChecks {
		return f.isLastFirewalled
	}
	return true
}

func (f *firewall) start(now time.Time) {
	f.isLastFirewalled = f.acks < firewallOpenAcks
	f.responses, f.acks = 0, 0
	f.asked = map[netip.Addr]bool{}
	f.next = now.Add(firewallCheckGap)
}

type coreConfig struct {
	ID       wire.Hash
	UserHash wire.Hash
	TCPPort  uint16
	UDPPort  uint16
	// UDPKey is the secret behind our verify keys.
	UDPKey uint32
	Rand   *rand.Rand
}

// core is Kad's protocol state: the routing table, requests in flight,
// lookups, the sources others stored with us, and what the engine wants.
// It does no I/O and keeps no clock; each reaction returns the datagrams to
// send and the sources found.
type core struct {
	id, userHash     wire.Hash
	tcpPort, udpPort uint16
	udpKey           uint32
	rng              *rand.Rand
	// reply is the sender of the packet being handled and the key it asked
	// us to answer with.
	reply struct {
		from netip.AddrPort
		key  uint32
	}
	table    *table
	rpcs     rpcs
	lookups  []*lookup
	index    index
	firewall firewall
	udp      udpCheck
	// publicIP is our address as the last KADEMLIA_FIREWALLED_RES said.
	publicIP    netip.Addr
	seeds       []netip.AddrPort
	isConnected bool
	canPublish  bool
	finds       []*find
	publishes   []*publish

	nextBootstrap    time.Time
	nextSelfLookup   time.Time
	nextRandomLookup time.Time
	nextFileSearch   time.Time
	nextPublish      time.Time
	nextIndexCleanup time.Time

	out output
}

func buildCore(cfg coreConfig, now time.Time) *core {
	return &core{
		id: cfg.ID, userHash: cfg.UserHash, tcpPort: cfg.TCPPort, udpPort: cfg.UDPPort, udpKey: cfg.UDPKey, rng: cfg.Rand,
		table:    buildTable(cfg.ID, now),
		index:    index{files: map[wire.Hash]map[wire.Hash]indexed{}},
		firewall: firewall{isLastFirewalled: true, asked: map[netip.Addr]bool{}},
		udp:      buildUDPCheck(),
	}
}

// addNodes adds bootstrap contacts: they enter the routing table unverified
// and are asked for contacts, one every bootstrapGap, until one answers.
func (c *core) addNodes(nodes []Node, now time.Time) {
	for _, n := range nodes {
		if c.table.add(n, false, now) != nil {
			c.seeds = append(c.seeds, n.Addr)
		}
	}
}

func (c *core) setWanted(w Wanted, now time.Time) {
	finds := map[wire.Hash]*find{}
	for _, f := range c.finds {
		finds[f.Hash] = f
	}
	c.finds = nil
	for _, s := range w.Find {
		f := finds[s.Hash]
		if f == nil {
			f = &find{}
		}
		delete(finds, s.Hash)
		f.Search = s
		c.finds = append(c.finds, f)
	}
	for _, f := range finds {
		c.cancelLookup(f.lookup)
	}
	publishes := map[wire.Hash]*publish{}
	for _, p := range c.publishes {
		publishes[p.Hash] = p
	}
	c.publishes = nil
	for _, p := range w.Publish {
		pub := publishes[p.Hash]
		if pub == nil {
			pub = &publish{}
		}
		delete(publishes, p.Hash)
		pub.Publish = p
		c.publishes = append(c.publishes, pub)
	}
	for _, p := range publishes {
		c.cancelLookup(p.lookup)
	}
}

func (c *core) cancelLookup(l *lookup) {
	if l == nil || l.isDone {
		return
	}
	l.isDone = true
	for i, other := range c.lookups {
		if other == l {
			c.lookups = append(c.lookups[:i], c.lookups[i+1:]...)
			return
		}
	}
}

// requestCallback asks a firewalled source's buddy to make the source
// connect to our TCP port.
func (c *core) requestCallback(cb Callback) output {
	if cb.Buddy.Addr().Is4() {
		// Plain, as aMule sends it: we do not know the buddy's Kad version
		// (BaseClient.cpp:1568).
		c.sendPlain(cb.Buddy, callbackReq{BuddyID: cb.BuddyID, Hash: cb.Hash, TCPPort: c.tcpPort})
	}
	out := c.out
	c.out = output{}
	return out
}

// onFirewallAck counts a node that reached our TCP port, reported over TCP
// (OP_KAD_FWTCPCHECK_ACK, received by the engine) or UDP
// (KADEMLIA_FIREWALLED_ACK_RES). Only nodes we asked count.
func (c *core) onFirewallAck(from netip.Addr) {
	if c.firewall.asked[from] {
		delete(c.firewall.asked, from)
		c.firewall.acks++
	}
}

// onMessage reacts to what the engine sends Kad besides wanted files.
func (c *core) onMessage(m any) output {
	switch m := m.(type) {
	case firewallAck:
		if m.to.Addr().Is4() {
			c.sendPlain(m.to, firewalledAck{})
		}
	case FirewallUDP:
		c.onFirewallUDP(m)
	case UDPCheckEnded:
		c.onUDPCheckEnded(m)
	}
	out := c.out
	c.out = output{}
	return out
}

// buildHello is SendMyDetails (KademliaUDPListener.cpp:114): our UDP port
// is named only once a UDP test chose it over the one our NAT shows.
func (c *core) buildHello() kadwire.Hello {
	h := kadwire.Hello{ID: c.id, TCPPort: c.tcpPort, Version: kadwire.Version}
	if !c.udp.useExternPort {
		h.Tags = []wire.Tag{{Type: wire.TagUint16, ID: kadwire.TagSourceUPort, Uint: uint64(c.udpPort)}}
	}
	return h
}

func (c *core) status() Status {
	return Status{Nodes: c.table.verifiedCount(), IsFirewalled: c.firewall.isFirewalled()}
}

// send obfuscates with the key to's node gave us: the one on the packet we
// answer, or the one its contact last sent. aMule answers with the
// request's sender key and never with the node ID.
func (c *core) send(to netip.AddrPort, p wire.Packet) {
	key := c.reply.key
	if to != c.reply.from {
		key = 0
		if ct := c.table.byAddr[to]; ct != nil {
			key = ct.udpKey
		}
	}
	c.sendKeyed(datagram{to: to, packet: p, receiverKey: key})
}

// sendTo obfuscates with the node's ID when its version reads obfuscation,
// as aMule's requests to contacts do.
func (c *core) sendTo(n Node, p wire.Packet) {
	d := datagram{to: n.Addr, packet: p}
	if ct := c.table.byAddr[n.Addr]; ct != nil {
		d.receiverKey = ct.udpKey
	}
	if n.Version >= versionObfuscation {
		d.nodeID = n.ID
	}
	c.sendKeyed(d)
}

func (c *core) sendKeyed(d datagram) {
	if d.nodeID != (wire.Hash{}) || d.receiverKey != 0 {
		d.senderKey = obfuscation.BuildKadVerifyKey(c.udpKey, d.to.Addr())
	}
	c.out.datagrams = append(c.out.datagrams, d)
}

func (c *core) sendPlain(to netip.AddrPort, p wire.Packet) {
	c.out.datagrams = append(c.out.datagrams, datagram{to: to, packet: p})
}

// onPacket handles a packet from from; senderKey is the key from wants
// answers obfuscated with, 0 for a plain datagram.
func (c *core) onPacket(from netip.AddrPort, p wire.Packet, senderKey uint32, now time.Time) output {
	if from.Addr().Is4() {
		c.reply.from, c.reply.key = from, senderKey
		c.runPacket(from, p, now)
		c.reply.from, c.reply.key = netip.AddrPort{}, 0
		if ct := c.table.byAddr[from]; ct != nil && senderKey != 0 {
			ct.udpKey = senderKey
		}
	}
	out := c.out
	c.out = output{}
	return out
}

func (c *core) runPacket(from netip.AddrPort, p wire.Packet, now time.Time) {
	switch p := p.(type) {
	case kadwire.BootstrapReq:
		c.send(from, kadwire.BootstrapRes{ID: c.id, TCPPort: c.tcpPort, Version: kadwire.Version, Contacts: c.buildContacts(c.id, bootstrapAnswer)})
	case kadwire.BootstrapRes:
		if c.rpcs.match(from, rpcBootstrap, wire.Hash{}) == nil {
			return
		}
		c.table.add(Node{ID: p.ID, Addr: from, TCPPort: p.TCPPort, Version: p.Version}, true, now)
		for _, ct := range p.Contacts {
			c.table.add(Node{ID: ct.ID, Addr: netip.AddrPortFrom(ct.Addr, ct.UDPPort), TCPPort: ct.TCPPort, Version: ct.Version}, false, now)
		}
	case kadwire.HelloReq:
		n := Node{ID: p.ID, Addr: from, TCPPort: p.TCPPort, Version: p.Version}
		c.table.add(n, false, now)
		d := datagram{to: from, packet: kadwire.HelloRes(c.buildHello()), receiverKey: c.reply.key}
		if n.Version >= versionObfuscation {
			d.nodeID = n.ID
		}
		c.sendKeyed(d)
	case kadwire.HelloRes:
		if c.rpcs.match(from, rpcHello, wire.Hash{}) != nil {
			c.table.add(Node{ID: p.ID, Addr: from, TCPPort: p.TCPPort, Version: p.Version}, true, now)
		}
	case kadwire.Req:
		// The receiver ID guards against answering for an ID we no longer
		// have; eMule ignores such requests.
		count := int(p.SearchType & 0x1F)
		if p.Receiver == c.id && count > 0 {
			c.send(from, kadwire.Res{Target: p.Target, Contacts: c.buildContacts(p.Target, min(count, maxRequest))})
		}
	case kadwire.Res:
		c.onRes(from, p, now)
	case kadwire.SearchSourcesReq:
		for _, res := range c.index.buildResults(c.id, p.Target, now) {
			c.send(from, res)
		}
	case kadwire.SearchRes:
		c.onSearchRes(from, p)
	case kadwire.PublishSourcesReq:
		if load, isStored := c.index.onPublishSources(c.id, from, p, now); isStored {
			c.send(from, kadwire.PublishRes{FileID: p.FileID, Load: load})
		}
	case kadwire.PublishRes:
		c.onPublishRes(from, p)
	case kadwire.FirewalledReq:
		c.onFirewallCheck(from, p.TCPPort, p.ID, p.Options)
	case kadwire.LegacyFirewalledReq:
		c.onFirewallCheck(from, p.TCPPort, wire.Hash{}, 0)
	case kadwire.FirewalledRes:
		if c.rpcs.match(from, rpcFirewall, wire.Hash{}) != nil {
			c.firewall.responses++
			c.publicIP = p.Addr
		}
	case kadwire.Ping:
		c.send(from, kadwire.Pong{UDPPort: from.Port()})
	case kadwire.Pong:
		c.onPong(from, p)
	case kadwire.FirewalledUDP:
		c.onFirewalledUDP(from, p)
	case wire.Unknown:
		if p.Op == opFirewalledAck && len(p.Body) == 0 {
			c.onFirewallAck(from.Addr())
		}
	}
}

// onFirewallCheck is ProcessFirewalledRequest and
// ProcessFirewalled2Request (KademliaUDPListener.cpp:1363-1430): we tell
// the node its address at once and have the engine connect to its TCP port.
func (c *core) onFirewallCheck(from netip.AddrPort, tcpPort uint16, user wire.Hash, options byte) {
	if from.Addr() == c.publicIP && tcpPort == c.tcpPort {
		return
	}
	c.send(from, kadwire.FirewalledRes{Addr: from.Addr()})
	c.out.requests = append(c.out.requests, FirewallCheck{
		Addr: netip.AddrPortFrom(from.Addr(), tcpPort), KadPort: from.Port(), UserHash: user, CryptOptions: options,
	})
}

// buildContacts answers a routing query with verified contacts only, so we
// never spread hearsay.
func (c *core) buildContacts(target wire.Hash, n int) []kadwire.Contact {
	var out []kadwire.Contact
	for _, ct := range c.table.closestContacts(target, n, true) {
		out = append(out, kadwire.Contact{ID: ct.ID, Addr: ct.Addr.Addr(), UDPPort: ct.Addr.Port(), TCPPort: ct.TCPPort, Version: ct.Version})
	}
	return out
}

func (c *core) onTick(now time.Time) output {
	for _, r := range c.rpcs.removeExpired(now) {
		if r.kind == rpcHello || r.kind == rpcFind || r.kind == rpcBootstrap {
			c.table.onTimeout(r.node.Addr)
		}
	}
	c.runBucketChecks(now)
	isConnected := c.table.verifiedCount() > 0
	if isConnected && !c.isConnected {
		c.nextSelfLookup = now
		c.firewall.next = now
	}
	c.isConnected = isConnected
	if isConnected {
		c.runMaintenance(now)
		c.runWanted(now)
	} else {
		c.runBootstrap(now)
	}
	c.runLookups(now)
	if !now.Before(c.nextIndexCleanup) {
		c.index.clearExpired(now)
		c.nextIndexCleanup = now.Add(indexCleanupGap)
	}
	out := c.out
	c.out = output{}
	return out
}

func (c *core) runBootstrap(now time.Time) {
	if now.Before(c.nextBootstrap) {
		return
	}
	if len(c.seeds) == 0 {
		for _, n := range c.table.nodes() {
			c.seeds = append(c.seeds, n.Addr)
		}
	}
	if len(c.seeds) == 0 {
		return
	}
	to := c.seeds[0]
	c.seeds = c.seeds[1:]
	c.nextBootstrap = now.Add(bootstrapGap)
	c.send(to, kadwire.BootstrapReq{})
	c.rpcs.add(&rpc{kind: rpcBootstrap, node: Node{Addr: to}, sent: now})
}

// runBucketChecks is CRoutingZone::OnSmallTimer: once a minute per leaf it
// says hello to a contact we have not greeted yet, or to the one we heard
// from longest ago if that was over an hour back. The hello also makes
// the contact add us to its own table.
func (c *core) runBucketChecks(now time.Time) {
	for i := range c.table.buckets {
		b := &c.table.buckets[i]
		var due [maxLeaves]*contact
		var isPopulated [maxLeaves]bool
		for _, ct := range b.contacts {
			isPopulated[ct.leaf] = true
			d := due[ct.leaf]
			switch {
			case d != nil && !d.isHelloed:
			case !ct.isHelloed:
				due[ct.leaf] = ct
			case ct.isVerified && now.Sub(ct.lastSeen) >= contactRecheck && (d == nil || ct.lastSeen.Before(d.lastSeen)):
				due[ct.leaf] = ct
			}
		}
		for leaf := range leafCount(i) {
			if !isPopulated[leaf] || now.Before(b.nextChecks[leaf]) {
				continue
			}
			b.nextChecks[leaf] = now.Add(bucketCheckGap)
			ct := due[leaf]
			if ct == nil || c.rpcs.hasPending(ct.Addr, rpcHello) {
				continue
			}
			ct.isHelloed = true
			c.sendTo(ct.Node, kadwire.HelloReq(c.buildHello()))
			c.rpcs.add(&rpc{kind: rpcHello, node: ct.Node, sent: now})
		}
	}
}

func (c *core) runMaintenance(now time.Time) {
	if !now.Before(c.nextSelfLookup) && c.startLookup(nodeLookup, c.id, 0, now) != nil {
		c.nextSelfLookup = now.Add(selfLookupGap)
	}
	c.runRandomLookups(now)
	c.runFirewallCheck(now)
	c.runUDPCheck(now)
}

// runRandomLookups is CKademlia::Process's big timer: every
// bucketRefreshGap it looks up a random ID in one sparse leaf, so the table
// fills where it is emptiest. eMule's leaves exist down to the zone that
// holds us; buckets past the deepest populated one stand in for it.
func (c *core) runRandomLookups(now time.Time) {
	if now.Before(c.nextRandomLookup) {
		return
	}
	deepest := 0
	for i := range c.table.buckets {
		if len(c.table.buckets[i].contacts) > 0 {
			deepest = i
		}
	}
	for i := range min(deepest+2, len(c.table.buckets)) {
		b := &c.table.buckets[i]
		for leaf := range leafCount(i) {
			if now.Before(b.nextLookups[leaf]) || c.table.leafSize(b, leaf) > sparseLeaf {
				continue
			}
			if c.startLookup(randomLookup, buildRandomID(c.id, i, leaf, c.rng), 0, now) == nil {
				return
			}
			b.nextLookups[leaf] = now.Add(bucketLookupGap)
			c.nextRandomLookup = now.Add(bucketRefreshGap)
			return
		}
	}
}

// runFirewallCheck keeps up to firewallChecks requests out until that many
// nodes have answered. eMule piggybacks them on hello exchanges; we pick
// verified contacts, one a second.
func (c *core) runFirewallCheck(now time.Time) {
	f := &c.firewall
	if !now.Before(f.next) {
		f.start(now)
		c.recheckUDP(now)
	}
	if f.responses+c.rpcs.count(rpcFirewall) >= firewallChecks {
		return
	}
	for _, ct := range c.table.closestContacts(buildRandomID(c.id, 0, 0, c.rng), len(c.table.byID), true) {
		if f.asked[ct.Addr.Addr()] {
			continue
		}
		f.asked[ct.Addr.Addr()] = true
		if ct.Version >= versionFirewalled2 {
			c.send(ct.Addr, kadwire.FirewalledReq{TCPPort: c.tcpPort, ID: c.userHash})
		} else {
			c.send(ct.Addr, kadwire.LegacyFirewalledReq{TCPPort: c.tcpPort})
		}
		c.rpcs.add(&rpc{kind: rpcFirewall, node: ct.Node, sent: now})
		return
	}
}

// runWanted starts at most one source search and one publish a tick, at
// eMule's pace. A publish waits for the first self lookup to finish
// (CSearchManager sets the publish flag then) and for an open firewall
// verdict: a firewalled source needs a buddy, which Kelpie does not have.
func (c *core) runWanted(now time.Time) {
	if !now.Before(c.nextFileSearch) && c.lookupCount(sourceSearch) < maxFileSearches {
		for _, f := range c.finds {
			if (f.lookup != nil && !f.lookup.isDone) || now.Before(f.next) {
				continue
			}
			l := c.startLookup(sourceSearch, f.Hash, uint64(f.Size), now)
			if l == nil {
				break
			}
			f.lookup = l
			f.searches = min(f.searches+1, maxReaskFactor)
			f.next = now.Add(reaskSources * time.Duration(f.searches))
			c.nextFileSearch = now.Add(fileSearchGap)
			break
		}
	}
	if !c.canPublish || c.firewall.isFirewalled() || now.Before(c.nextPublish) || c.lookupCount(sourcePublish) >= maxPublishes {
		return
	}
	c.nextPublish = now.Add(publishGap)
	for _, p := range c.publishes {
		if (p.lookup != nil && !p.lookup.isDone) || now.Before(p.next) {
			continue
		}
		if l := c.startLookup(sourcePublish, p.Hash, uint64(p.Size), now); l != nil {
			p.lookup = l
			p.next = now.Add(republishSources)
		}
		return
	}
}
