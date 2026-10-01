// Derived from goed2k kad_routing.go.

package kad

import (
	"bytes"
	"math/rand/v2"
	"net/netip"
	"slices"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/wire"
)

const (
	bucketSize = 10 // K
	// A contact that misses this many checks in a row leaves the table.
	maxFailures = 2
)

type contact struct {
	Node
	// isVerified is set once the contact answered a request of ours.
	isVerified bool
	isHelloed  bool
	failures   int
	lastSeen   time.Time
}

type bucket struct {
	contacts     []*contact
	replacements []*contact
	lastLookup   time.Time
	nextCheck    time.Time
}

// table is a Kademlia routing table: bucket i holds contacts whose ID first
// differs from ours at bit i. Lookups only use the contacts, not the
// replacements, which wait for a contact to fail.
type table struct {
	self    wire.Hash
	buckets [128]bucket
	byID    map[wire.Hash]*contact
	byAddr  map[netip.AddrPort]*contact
}

func buildTable(self wire.Hash, now time.Time) *table {
	t := &table{self: self, byID: map[wire.Hash]*contact{}, byAddr: map[netip.AddrPort]*contact{}}
	for i := range t.buckets {
		t.buckets[i].lastLookup = now
	}
	return t
}

// add inserts or updates a contact. A verified contact is one that just
// answered us; others are hearsay and never move a verified contact to a new
// address.
func (t *table) add(n Node, isVerified bool, now time.Time) *contact {
	if n.ID == t.self || !matchGoodAddr(n.Addr) {
		return nil
	}
	c := t.byID[n.ID]
	if c == nil {
		if other := t.byAddr[n.Addr]; other != nil {
			if !isVerified {
				return nil
			}
			t.remove(other)
		}
		c = &contact{Node: n}
		t.byID[n.ID] = c
		t.byAddr[n.Addr] = c
		t.addToBucket(c, isVerified)
	} else if c.Addr != n.Addr {
		if c.isVerified && !isVerified {
			return c
		}
		if other := t.byAddr[n.Addr]; other != nil {
			t.remove(other)
		}
		delete(t.byAddr, c.Addr)
		c.Addr = n.Addr
		t.byAddr[n.Addr] = c
	}
	if n.TCPPort != 0 {
		c.TCPPort = n.TCPPort
	}
	if n.Version != 0 {
		c.Version = n.Version
	}
	if isVerified {
		c.failures = 0
		c.lastSeen = now
		if !c.isVerified {
			c.isVerified = true
			t.updateBucket(c)
		}
	}
	return c
}

func (t *table) addToBucket(c *contact, isVerified bool) {
	b := &t.buckets[bucketIndex(t.self, c.ID)]
	if len(b.contacts) < bucketSize {
		b.contacts = append(b.contacts, c)
		return
	}
	if isVerified {
		if i := slices.IndexFunc(b.contacts, func(o *contact) bool { return !o.isVerified }); i >= 0 {
			b.replacements = append(b.replacements, b.contacts[i])
			b.contacts[i] = c
			t.removeExcessReplacements(b)
			return
		}
	}
	b.replacements = append(b.replacements, c)
	t.removeExcessReplacements(b)
}

func (t *table) removeExcessReplacements(b *bucket) {
	for len(b.replacements) > bucketSize {
		old := b.replacements[0]
		b.replacements = b.replacements[1:]
		delete(t.byID, old.ID)
		delete(t.byAddr, old.Addr)
	}
}

// updateBucket moves a newly verified replacement into the bucket's contacts if
// there is room or an unverified contact to swap with.
func (t *table) updateBucket(c *contact) {
	b := &t.buckets[bucketIndex(t.self, c.ID)]
	i := slices.Index(b.replacements, c)
	if i < 0 {
		return
	}
	if len(b.contacts) < bucketSize {
		b.replacements = slices.Delete(b.replacements, i, i+1)
		b.contacts = append(b.contacts, c)
		return
	}
	if j := slices.IndexFunc(b.contacts, func(o *contact) bool { return !o.isVerified }); j >= 0 {
		b.replacements[i] = b.contacts[j]
		b.contacts[j] = c
	}
}

// onTimeout records an unanswered request. An unverified contact goes at once; a
// verified one after maxFailures misses, and the best replacement takes its
// place.
func (t *table) onTimeout(addr netip.AddrPort) {
	c := t.byAddr[addr]
	if c == nil {
		return
	}
	c.failures++
	if c.isVerified && c.failures < maxFailures {
		return
	}
	t.remove(c)
}

func (t *table) remove(c *contact) {
	delete(t.byID, c.ID)
	delete(t.byAddr, c.Addr)
	b := &t.buckets[bucketIndex(t.self, c.ID)]
	if i := slices.Index(b.replacements, c); i >= 0 {
		b.replacements = slices.Delete(b.replacements, i, i+1)
		return
	}
	i := slices.Index(b.contacts, c)
	if i < 0 {
		return
	}
	b.contacts = slices.Delete(b.contacts, i, i+1)
	if len(b.replacements) == 0 {
		return
	}
	best := slices.IndexFunc(b.replacements, func(o *contact) bool { return o.isVerified })
	if best < 0 {
		best = len(b.replacements) - 1
	}
	b.contacts = append(b.contacts, b.replacements[best])
	b.replacements = slices.Delete(b.replacements, best, best+1)
}

// closestContacts returns up to n contacts nearest to target, nearest
// first.
func (t *table) closestContacts(target wire.Hash, n int, isVerifiedOnly bool) []*contact {
	var out []*contact
	for i := range t.buckets {
		for _, c := range t.buckets[i].contacts {
			if c.isVerified || !isVerifiedOnly {
				out = append(out, c)
			}
		}
	}
	slices.SortFunc(out, func(a, b *contact) int {
		da, db := distance(a.ID, target), distance(b.ID, target)
		return bytes.Compare(da[:], db[:])
	})
	return out[:min(n, len(out))]
}

func (t *table) verifiedCount() int {
	count := 0
	for i := range t.buckets {
		for _, c := range t.buckets[i].contacts {
			if c.isVerified {
				count++
			}
		}
	}
	return count
}

// nodes lists the bucket contacts, verified ones first, for the Durable
// State.
func (t *table) nodes() []Node {
	var verified, others []Node
	for i := range t.buckets {
		for _, c := range t.buckets[i].contacts {
			if c.isVerified {
				verified = append(verified, c.Node)
			} else {
				others = append(others, c.Node)
			}
		}
	}
	return append(verified, others...)
}

func distance(a, b wire.Hash) wire.Hash {
	var d wire.Hash
	for i := range d {
		d[i] = a[i] ^ b[i]
	}
	return d
}

func bucketIndex(self, id wire.Hash) int {
	d := distance(self, id)
	for i, b := range d {
		for bit := range 8 {
			if b&(0x80>>bit) != 0 {
				return i*8 + bit
			}
		}
	}
	return 127
}

// buildRandomID returns an ID that lands in bucket index of self.
func buildRandomID(self wire.Hash, index int, rng *rand.Rand) wire.Hash {
	var id wire.Hash
	for i := range id {
		id[i] = byte(rng.UintN(256))
	}
	byteIndex, mask := index/8, byte(0x80>>(index%8))
	copy(id[:byteIndex], self[:byteIndex])
	keep := ^(mask<<1 - 1)
	id[byteIndex] = self[byteIndex]&keep | ^self[byteIndex]&mask | id[byteIndex]&(mask-1)
	return id
}
