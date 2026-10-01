// Derived from goed2k kad_traversal.go, reshaped after eMule's CSearch: a
// lookup walks toward its target with KADEMLIA2_REQ and, once it stalls,
// sends the real request (search or publish) to the closest nodes that
// answered.

package kad

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"slices"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/wire"
	kadwire "github.com/XiaoYouChR/Kelpie/internal/wire/kad"
)

type lookupKind int

const (
	nodeLookup lookupKind = iota
	// randomLookup is eMule's NODE search: it asks one contact at a time
	// and ends with the first answer, whose contacts fill the table.
	randomLookup
	sourceSearch
	sourcePublish
)

// eMule kademlia/kademlia/Defines.h.
const (
	alphaQuery          = 3                 // ALPHA_QUERY
	searchTolerance     = 16777216          // SEARCHTOLERANCE
	lookupStartContacts = 50                // CSearch::Go asks the routing table for 50
	jumpStartQuiet      = 3 * time.Second   // CSearch::JumpStart: no jump start within 3 s of a response
	nodeLifetime        = 45 * time.Second  // SEARCHNODE_LIFETIME
	nodeCompleteTime    = 10 * time.Second  // SEARCHNODECOMP_LIFETIME
	nodeCompleteTotal   = 10                // SEARCHNODECOMP_TOTAL
	fileLifetime        = 45 * time.Second  // SEARCHFILE_LIFETIME
	fileTotal           = 300               // SEARCHFILE_TOTAL
	storeFileLifetime   = 140 * time.Second // SEARCHSTOREFILE_LIFETIME
	storeFileTotal      = 10                // SEARCHSTOREFILE_TOTAL
	// CSearchManager::JumpStart stops a search 20 s before its lifetime
	// ends; CSearch::PrepareToStop then keeps it 15 s for late answers.
	stopMargin  = 20 * time.Second
	stopLinger  = 15 * time.Second
	maxRequest  = 32 // Process_KADEMLIA2_REQ: "Max count is 32"
	maxBySubnet = 2  // CSearch::ProcessResponse: no more than 2 IPs from one /24
)

// Kad versions that understand the Kad2 search and publish requests:
// CSearch::StorePacket checks 3 (0.47b) and SendPublishSourcePacket 4 (0.47c).
const (
	versionSearchSources  = 3
	versionPublishSources = 4
)

type candidate struct {
	Node
	distance    wire.Hash
	isTried     bool
	isResponded bool
}

type lookup struct {
	kind   lookupKind
	target wire.Hash
	size   uint64
	// deadline is when the lookup ends; isStopping lookups send nothing new
	// and only collect late answers.
	created      time.Time
	deadline     time.Time
	isStopping   bool
	isDone       bool
	known        map[wire.Hash]*candidate
	possible     []*candidate
	best         []wire.Hash
	lastResponse time.Time
	answers      int
	sources      map[wire.Hash]bool
}

func (l *lookup) requestCount() byte {
	switch l.kind {
	case sourceSearch:
		return kadwire.FindValue
	case sourcePublish:
		return kadwire.Store
	}
	return kadwire.FindNode
}

func (l *lookup) lifetime() time.Duration {
	switch l.kind {
	case sourceSearch:
		return fileLifetime
	case sourcePublish:
		return storeFileLifetime
	}
	return nodeLifetime
}

func (l *lookup) total() int {
	switch l.kind {
	case sourceSearch:
		return fileTotal
	case sourcePublish:
		return storeFileTotal
	}
	return nodeCompleteTotal
}

// addCandidate keeps possible sorted by distance to the target.
func (l *lookup) addCandidate(n Node) *candidate {
	d := distance(n.ID, l.target)
	if l.known[d] != nil {
		return nil
	}
	c := &candidate{Node: n, distance: d}
	l.known[d] = c
	i, _ := slices.BinarySearchFunc(l.possible, d, func(o *candidate, d wire.Hash) int {
		return bytes.Compare(o.distance[:], d[:])
	})
	l.possible = slices.Insert(l.possible, i, c)
	return c
}

// addBest records d if it is among the alphaQuery best distances seen so
// far, and reports whether it was.
func (l *lookup) addBest(d wire.Hash) bool {
	i, _ := slices.BinarySearchFunc(l.best, d, func(o, d wire.Hash) int { return bytes.Compare(o[:], d[:]) })
	if i >= alphaQuery {
		return false
	}
	l.best = slices.Insert(l.best, i, d)
	l.best = l.best[:min(len(l.best), alphaQuery)]
	return true
}

func (l *lookup) stop(now time.Time) {
	if l.isStopping {
		return
	}
	l.isStopping = true
	l.deadline = now.Add(stopLinger)
}

func matchTolerance(d wire.Hash) bool {
	return binary.BigEndian.Uint32(d[:4]) <= searchTolerance
}

func (c *core) lookupByTarget(kind lookupKind, target wire.Hash) *lookup {
	for _, l := range c.lookups {
		if l.kind == kind && l.target == target {
			return l
		}
	}
	return nil
}

func (c *core) lookupCount(kind lookupKind) int {
	count := 0
	for _, l := range c.lookups {
		if l.kind == kind {
			count++
		}
	}
	return count
}

// startLookup returns nil when the target is already being looked up or
// the routing table has nobody to ask.
func (c *core) startLookup(kind lookupKind, target wire.Hash, size uint64, now time.Time) *lookup {
	if c.lookupByTarget(kind, target) != nil {
		return nil
	}
	contacts := c.table.closestContacts(target, lookupStartContacts, false)
	if len(contacts) == 0 {
		return nil
	}
	l := &lookup{
		kind: kind, target: target, size: size, created: now, lastResponse: now,
		known: map[wire.Hash]*candidate{}, sources: map[wire.Hash]bool{},
	}
	l.deadline = now.Add(l.lifetime())
	for _, ct := range contacts {
		l.addCandidate(ct.Node)
	}
	count := alphaQuery
	if kind == randomLookup {
		count = 1
	}
	for _, cand := range l.possible[:min(count, len(l.possible))] {
		c.sendFind(l, cand, now)
	}
	c.lookups = append(c.lookups, l)
	return l
}

func (c *core) sendFind(l *lookup, cand *candidate, now time.Time) {
	cand.isTried = true
	c.send(cand.Addr, kadwire.Req{SearchType: l.requestCount(), Target: l.target, Receiver: cand.ID})
	c.rpcs.add(&rpc{kind: rpcFind, node: cand.Node, target: l.target, sent: now, lookup: l})
}

func (c *core) onRes(from netip.AddrPort, res kadwire.Res, now time.Time) {
	r := c.rpcs.match(from, rpcFind, res.Target)
	if r == nil {
		return
	}
	l := r.lookup
	// eMule drops answers with more contacts than asked for as malicious.
	if len(res.Contacts) > int(l.requestCount()) {
		return
	}
	c.table.add(Node{ID: r.node.ID, Addr: from, TCPPort: r.node.TCPPort, Version: r.node.Version}, true, now)
	for _, ct := range res.Contacts {
		c.table.add(Node{ID: ct.ID, Addr: netip.AddrPortFrom(ct.Addr, ct.UDPPort), TCPPort: ct.TCPPort, Version: ct.Version}, false, now)
	}
	if l.isDone || l.isStopping {
		return
	}
	if l.kind == randomLookup {
		c.cancelLookup(l)
		return
	}
	l.lastResponse = now
	responder := l.known[distance(r.node.ID, l.target)]
	if responder == nil {
		return
	}
	responder.isResponded = true
	if l.kind == nodeLookup {
		l.answers++
	}
	seenIPs := map[netip.Addr]bool{from.Addr(): true}
	bySubnet := map[netip.Prefix]int{}
	for _, ct := range res.Contacts {
		n := Node{ID: ct.ID, Addr: netip.AddrPortFrom(ct.Addr, ct.UDPPort), TCPPort: ct.TCPPort, Version: ct.Version}
		if n.ID == c.id || !matchGoodAddr(n.Addr) || seenIPs[ct.Addr] {
			continue
		}
		seenIPs[ct.Addr] = true
		// eMule exempts LAN addresses from the subnet limit.
		subnet, _ := ct.Addr.Prefix(24)
		if !ct.Addr.IsPrivate() {
			if bySubnet[subnet] >= maxBySubnet {
				continue
			}
			bySubnet[subnet]++
		}
		cand := l.addCandidate(n)
		if cand == nil {
			continue
		}
		if bytes.Compare(cand.distance[:], responder.distance[:]) < 0 && l.addBest(cand.distance) {
			c.sendFind(l, cand, now)
		}
	}
}

// runJumpStart is eMule's CSearch::JumpStart, run once a second: when the
// walk has gone quiet, it sends the real request to the closest nodes that
// answered and asks the next untried one.
func (c *core) runJumpStart(l *lookup, now time.Time) {
	if now.Sub(l.lastResponse) < jumpStartQuiet {
		return
	}
	if len(l.possible) == 0 {
		l.stop(now)
		return
	}
	for len(l.possible) > 0 {
		cand := l.possible[0]
		if !cand.isTried {
			c.sendFind(l, cand, now)
			return
		}
		if cand.isResponded {
			c.sendAction(l, cand, now)
		}
		l.possible = l.possible[1:]
	}
}

func (c *core) sendAction(l *lookup, cand *candidate, now time.Time) {
	if !matchTolerance(cand.distance) {
		return
	}
	switch l.kind {
	case sourceSearch:
		if cand.Version < versionSearchSources {
			return
		}
		c.send(cand.Addr, kadwire.SearchSourcesReq{Target: l.target, Size: l.size})
		c.rpcs.add(&rpc{kind: rpcSearchSources, node: cand.Node, target: l.target, sent: now, lookup: l})
	case sourcePublish:
		if l.answers > storeFileTotal {
			l.stop(now)
			return
		}
		if cand.Version < versionPublishSources {
			return
		}
		c.send(cand.Addr, kadwire.PublishSourcesReq{FileID: l.target, Source: kadwire.Entry{ID: c.userHash, Tags: c.buildSourceTags(l.size)}})
		c.rpcs.add(&rpc{kind: rpcPublish, node: cand.Node, target: l.target, sent: now, lookup: l})
	}
}

// buildSourceTags describes us as an open source: CSearch::StorePacket for
// STOREFILE when not firewalled. The storing node adds our IP.
func (c *core) buildSourceTags(size uint64) []wire.Tag {
	sourceType := uint64(1)
	if size > oldMaxFileSize {
		sourceType = 4
	}
	sizeTag := wire.Tag{Type: wire.TagUint32, ID: kadwire.TagFileSize, Uint: size}
	if size > 0xFFFFFFFF {
		sizeTag.Type = wire.TagUint64
	}
	return []wire.Tag{
		{Type: wire.TagUint8, ID: kadwire.TagSourceType, Uint: sourceType},
		{Type: wire.TagUint16, ID: kadwire.TagSourcePort, Uint: uint64(c.tcpPort)},
		{Type: wire.TagUint16, ID: kadwire.TagSourceUPort, Uint: uint64(c.udpPort)},
		sizeTag,
	}
}

// oldMaxFileSize is eMule's OLD_MAX_EMULE_FILE_SIZE: larger files are
// published as source type 4 (or 5) so pre-4 GB clients skip them.
const oldMaxFileSize = 4290048000

func (c *core) onSearchRes(from netip.AddrPort, res kadwire.SearchRes) {
	r := c.rpcs.match(from, rpcSearchSources, res.Target)
	if r == nil || r.lookup.isDone {
		return
	}
	l := r.lookup
	var sources []Source
	for _, e := range res.Results {
		if l.answers >= fileTotal {
			break
		}
		s, ok := toSource(e, c.firewall.isFirewalled())
		if !ok || s.UserHash == c.userHash || l.sources[s.UserHash] {
			continue
		}
		l.sources[s.UserHash] = true
		l.answers++
		sources = append(sources, s)
	}
	if len(sources) > 0 {
		c.out.found = append(c.out.found, SourcesFound{Hash: l.target, Sources: sources})
	}
}

func (c *core) onPublishRes(from netip.AddrPort, res kadwire.PublishRes) {
	if r := c.rpcs.match(from, rpcPublish, res.FileID); r != nil && !r.lookup.isDone {
		r.lookup.answers++
	}
}

// runLookups is CSearchManager::JumpStart: it ends lookups past their
// deadline, stops those that have enough answers, and jump-starts the rest.
func (c *core) runLookups(now time.Time) {
	c.lookups = slices.DeleteFunc(c.lookups, func(l *lookup) bool {
		isComplete := l.kind == nodeLookup && now.Sub(l.created) > nodeCompleteTime && l.answers >= nodeCompleteTotal
		if !now.Before(l.deadline) || isComplete {
			l.isDone = true
			if l.kind == nodeLookup && l.target == c.id {
				c.canPublish = true
			}
			return true
		}
		return false
	})
	for _, l := range c.lookups {
		switch {
		case l.isStopping:
		case (l.kind == sourceSearch || l.kind == sourcePublish) && (l.answers >= l.total() || now.After(l.created.Add(l.lifetime()-stopMargin))):
			l.stop(now)
		default:
			c.runJumpStart(l, now)
		}
	}
}
