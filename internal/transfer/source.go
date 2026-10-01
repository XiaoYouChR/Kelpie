package transfer

import (
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/wire"
)

// Timing and limits follow eMule (Opcodes.h, Preferences.cpp, PartFile.cpp,
// DownloadClient.cpp, DeadSourceList.cpp) so Kelpie never asks more often
// than eMule does; the reask interval is aMule's, which is still well above
// the MIN_REQUESTTIME (590 s) below which eMule and aMule count a client as
// aggressive.
const (
	// fileReaskTime is aMule's FILEREASKTIME (include/protocol/ed2k/
	// Constants.h:35), counted from when we last connected to the source or
	// it last told us its rank, with no further connect guard
	// (PartFile.cpp:1604-1621).
	fileReaskTime = 1300 * time.Second
	// udpReaskLead is the window before the TCP reask in which a queued
	// source is reasked with OP_REASKFILEPING instead: aMule tries it once
	// FILEREASKTIME-20000 ms have passed (PartFile.cpp:1594-1601), eMule two
	// minutes before.
	udpReaskLead = 20 * time.Second
	// callbackTimeout is CONNECTION_TIMEOUT, how long a callback may take.
	callbackTimeout = 40 * time.Second
	// deadSourceTime is DeadSourceList.cpp's BLOCKTIME for a file's own list.
	deadSourceTime = 45 * time.Minute

	serverReaskTime       = 15 * time.Minute // SERVERREASKTIME
	globalServerReaskTime = 30 * time.Minute // UDPSERVERREASKTIME
	kadReaskTime          = time.Hour        // KADEMLIAREASKTIME
	// maxKadSearches caps the multiplier of kadReaskTime (m_TotalSearchesKad < 7).
	maxKadSearches = 7

	exchangeReaskSlow = 40 * time.Minute // SOURCECLIENTREASKS
	exchangeReaskFast = 5 * time.Minute  // SOURCECLIENTREASKF
	commonPenalty     = 4                // MINCOMMONPENALTY
	rareFile          = 50               // RARE_FILE

	// maxSources is eMule's MaxSourcesPerFile default.
	maxSources = 400
	// noNeededPurgeTime and noNeededPurgeShare: near the source cap, one
	// source with no part we need is dropped at most every 40 s once the
	// file has 80% of maxSources (aMule PartFile.cpp:1559-1573).
	noNeededPurgeTime  = 40 * time.Second
	noNeededPurgeShare = 0.8
	// maxSourcesSoft is GetMaxSourcePerFileSoft: 9/10 of maxSources, capped
	// at MAX_SOURCES_FILE_SOFT (750). Above it no more sources are asked for.
	maxSourcesSoft = maxSources * 9 / 10
	// maxSourcesUDP is GetMaxSourcePerFileUDP: 3/4 of maxSources, capped at
	// MAX_SOURCES_FILE_UDP (50). Global server and Kad searches stop above it.
	maxSourcesUDP = min(maxSources*3/4, 50)

	// UDP reasks to a source stop once more than 3 were sent and over 30%
	// went unanswered (CUpDownClient::UDPReaskForDownload).
	minUDPReasks      = 3
	maxUDPFailedShare = 0.3
)

type sourceState int

const (
	// stateNew sources are ready to be asked once their reask time comes.
	stateNew sourceState = iota
	// stateWaiting sources are due but the connection budget is spent
	// (eMule's DS_TOOMANYCONNS).
	stateWaiting
	stateConnecting
	// stateAsking sources are connected and have not yet answered with a
	// queue rank or a slot.
	stateAsking
	stateQueued
	stateDownloading
	// stateFailed sources wait out deadSourceTime before they are tried again.
	stateFailed
)

// Source is what a channel says about one source. A HighID source has an
// Endpoint. A LowID source has ClientID and the Server it is connected to. A
// firewalled Kad source has its Buddy and BuddyID. UserHash is zero when the
// channel does not tell it.
type Source struct {
	Endpoint netip.AddrPort
	ClientID uint32
	Server   netip.AddrPort
	Buddy    netip.AddrPort
	BuddyID  wire.Hash
	UserHash wire.Hash
	UDPPort  uint16
	// CanObfuscate: the channel says the source supports protocol
	// obfuscation, which needs its UserHash.
	CanObfuscate bool
	// IsDirectCallback: a firewalled Kad source that takes callback
	// requests itself, at the UDP endpoint in Buddy.
	IsDirectCallback bool
}

// Hello is what a connected peer told us about itself.
type Hello struct {
	// Endpoint is the peer's address with its TCP listen port.
	Endpoint    netip.AddrPort
	ClientID    uint32
	Server      netip.AddrPort
	UserHash    wire.Hash
	UDPPort     uint16
	CanReaskUDP bool
	CanExchange bool
	// CanObfuscate: the Hello's crypt options say the peer supports
	// protocol obfuscation; it replaces what the channel said, as aMule
	// takes it from the Hello (BaseClient.cpp:350, 590).
	CanObfuscate bool
}

// Tick carries what OnTick needs to know about the engine.
type Tick struct {
	Now time.Time
	// ConnectBudget is how many connections and callbacks this Transfer may
	// start now.
	ConnectBudget int
	// Server is the server we are connected to; invalid when none.
	Server netip.AddrPort
	// IsFirewalled is true when peers cannot connect to us (LowID).
	IsFirewalled bool
	IsKadRunning bool
	// PublicIP is our address as the server or peers see it; invalid while
	// unknown. Port is our TCP listen port.
	PublicIP netip.Addr
	Port     uint16
	// LocalAddrs are the addresses of this host's network interfaces.
	LocalAddrs []netip.Addr
}

type source struct {
	key     string
	channel Channel
	Source
	canReaskUDP bool
	canExchange bool

	state       sourceState
	isConnected bool
	// hasAnswered: the connected source answered our file request with its
	// part status, so we asked it for a slot.
	hasAnswered bool
	// isNoNeeded: its last part status had no part we need (aMule
	// DS_NONEEDEDPARTS).
	isNoNeeded bool
	// a4afUntil: until then another Transfer asks this client for a slot,
	// and this one leaves it alone (aMule's A4AF list).
	a4afUntil time.Time
	peer      uint64
	rank      int

	lastAsked       time.Time
	callbackTimeout time.Time
	retryAt         time.Time
	lastExchange    time.Time

	isUDPPending bool
	udpReasks    int
	udpFailed    int

	receivedBytes int64
}

func buildKey(s Source) string {
	switch {
	case s.Buddy.IsValid():
		return "kad:" + s.UserHash.String()
	case s.ClientID != 0:
		return fmt.Sprintf("%d@%s", s.ClientID, s.Server)
	default:
		return s.Endpoint.String()
	}
}

func (t *Transfer) buildTrace(now time.Time, s *source, event Event) TraceEvent {
	return TraceEvent{Time: now, Hash: t.file.Hash, Source: s.key, Event: event}
}

func matchSource(s *source, found Source) bool {
	switch {
	case found.UserHash != (wire.Hash{}) && found.UserHash == s.UserHash:
		return true
	case found.ClientID != 0:
		return found.ClientID == s.ClientID && found.Server == s.Server
	default:
		return found.Endpoint.IsValid() && found.Endpoint == s.Endpoint
	}
}

func (t *Transfer) matchingSource(found Source) *source {
	for _, s := range t.sources {
		if matchSource(s, found) {
			return s
		}
	}
	return nil
}

func (t *Transfer) isBanned(found Source) bool {
	return found.UserHash != (wire.Hash{}) && t.bannedHashes[found.UserHash] ||
		found.Endpoint.IsValid() && t.bannedEndpoints[found.Endpoint]
}

func (t *Transfer) isUsable(found Source) bool {
	switch {
	case found.Buddy.IsValid():
		return found.UserHash != (wire.Hash{}) && isPublic(found.Buddy.Addr())
	case found.ClientID != 0:
		return wire.IsLowID(found.ClientID) && found.Server.IsValid()
	default:
		return found.Endpoint.IsValid() && found.Endpoint.Port() != 0 && isPublic(found.Endpoint.Addr()) && !t.isSelf(found.Endpoint)
	}
}

// isPublic follows aMule's IsGoodIP with FilterLanIPs on
// (NetworkFunctions.cpp:99-151): no "this network" 0/8, loopback, link-local,
// multicast, 240/4 (which holds 255.255.255.255) or private LAN address.
// aMule's other reserved ranges are left out: several, like 39/8, have since
// been allocated.
func isPublic(addr netip.Addr) bool {
	addr = addr.Unmap()
	if addr.Is4() && (addr.As4()[0] == 0 || addr.As4()[0] >= 240) {
		return false
	}
	return addr.IsGlobalUnicast() && !addr.IsPrivate()
}

// isSelf follows aMule CPartFile::CanAddSource (PartFile.cpp:1745-1766):
// while LowID any source at our public IP is ourselves seen through our NAT;
// while HighID it is us only on our own port. A host with a public address
// on an interface, as with most IPv6, is also us there on our own port.
func (t *Transfer) isSelf(endpoint netip.AddrPort) bool {
	addr := endpoint.Addr().Unmap()
	if endpoint.Port() == t.tick.Port && slices.Contains(t.tick.LocalAddrs, addr) {
		return true
	}
	return addr == t.tick.PublicIP.Unmap() && (t.tick.IsFirewalled || endpoint.Port() == t.tick.Port)
}

// OnSourcesFound adds sources from one channel, skipping duplicates, banned
// sources and anything beyond the per-file source cap.
func (t *Transfer) OnSourcesFound(found []Source, channel Channel, now time.Time) []Action {
	if !t.isDownloading() {
		return nil
	}
	var actions []Action
	for _, f := range found {
		actions = append(actions, t.addSource(f, channel, now)...)
	}
	return actions
}

func (t *Transfer) addSource(found Source, channel Channel, now time.Time) []Action {
	// A LowID source can only be reached by a callback, which a firewalled
	// client cannot get (aMule CPartFile::CanAddSource, PartFile.cpp:1769).
	if !t.isUsable(found) || t.isBanned(found) || found.ClientID != 0 && t.tick.IsFirewalled {
		return nil
	}
	if s := t.matchingSource(found); s != nil {
		if s.UserHash == (wire.Hash{}) {
			s.UserHash = found.UserHash
		}
		if s.UDPPort == 0 {
			s.UDPPort = found.UDPPort
		}
		s.CanObfuscate = s.CanObfuscate || found.CanObfuscate
		return nil
	}
	s := t.addNew(found, channel)
	if s == nil {
		return nil
	}
	event := t.buildTrace(now, s, EventFound)
	event.Channel = channel
	return []Action{event}
}

// addNew makes room at the cap by dropping a failed source or one we cannot
// reach; without one, the new source is refused.
func (t *Transfer) addNew(found Source, channel Channel) *source {
	if len(t.sources) >= maxSources {
		i := slices.IndexFunc(t.sources, func(s *source) bool { return !t.isValid(s) })
		if i < 0 {
			return nil
		}
		t.sources = slices.Delete(t.sources, i, i+1)
	}
	s := &source{key: buildKey(found), channel: channel, Source: found}
	t.sources = append(t.sources, s)
	return s
}

func (t *Transfer) removeSource(s *source) {
	t.sources = slices.DeleteFunc(t.sources, func(other *source) bool { return other == s })
}

// validSourceCount counts the sources that the "enough sources" limits may
// rely on: not failed and reachable from where we are now.
func (t *Transfer) validSourceCount() int {
	count := 0
	for _, s := range t.sources {
		if t.isValid(s) {
			count++
		}
	}
	return count
}

func (t *Transfer) isValid(s *source) bool {
	return s.state != stateFailed && (s.isConnected || t.canReach(s))
}

// canReach mirrors requestConnect: callbacks need us reachable, and a server
// callback needs the source on our server.
func (t *Transfer) canReach(s *source) bool {
	switch {
	case s.Buddy.IsValid():
		return !t.tick.IsFirewalled
	case s.ClientID != 0:
		return !t.tick.IsFirewalled && s.Server == t.tick.Server
	default:
		return true
	}
}

// OnConnectFailed reports that a Connect to endpoint did not succeed.
func (t *Transfer) OnConnectFailed(endpoint netip.AddrPort, reason string, now time.Time) []Action {
	for _, s := range t.sources {
		if s.state == stateConnecting && s.Endpoint == endpoint {
			return []Action{t.setFailed(s, reason, now)}
		}
	}
	return nil
}

func (t *Transfer) setFailed(s *source, reason string, now time.Time) TraceEvent {
	s.state = stateFailed
	s.retryAt = now.Add(deadSourceTime)
	event := t.buildTrace(now, s, EventFailed)
	event.Reason = reason
	return event
}

// OnPeerConnected attaches a connection that is about this file, whether we
// opened it, a callback made the source connect, or the peer came on its own.
func (t *Transfer) OnPeerConnected(peer uint64, hello Hello, now time.Time) []Action {
	if !t.isDownloading() {
		return nil
	}
	found := Source{Endpoint: hello.Endpoint, UserHash: hello.UserHash, UDPPort: hello.UDPPort}
	if wire.IsLowID(hello.ClientID) {
		found.ClientID = hello.ClientID
		found.Server = hello.Server
	}
	if t.isBanned(found) {
		return []Action{Close{Peer: peer, Reason: "banned"}}
	}
	s := t.connectedSource(hello)
	var actions []Action
	if s == nil {
		s = t.addNew(found, ChannelIncoming)
		if s == nil {
			return []Action{Close{Peer: peer, Reason: "too many sources"}}
		}
		event := t.buildTrace(now, s, EventFound)
		event.Channel = ChannelIncoming
		actions = append(actions, event)
	}
	if s.isConnected {
		return append(actions, Close{Peer: peer, Reason: "duplicate"})
	}
	t.sources = slices.DeleteFunc(t.sources, func(other *source) bool {
		return other != s && !other.isConnected && hello.UserHash != (wire.Hash{}) && other.UserHash == hello.UserHash
	})

	s.Endpoint = hello.Endpoint
	s.UserHash = hello.UserHash
	s.UDPPort = hello.UDPPort
	s.canReaskUDP = hello.CanReaskUDP
	s.canExchange = hello.CanExchange
	s.CanObfuscate = hello.CanObfuscate
	s.state = stateAsking
	s.isConnected = true
	s.hasAnswered = false
	s.a4afUntil = time.Time{}
	s.lastAsked = now
	s.peer = peer
	t.peers[peer] = s
	t.senders[peer] = s

	event := t.buildTrace(now, s, EventConnected)
	event.IsIPv6 = hello.Endpoint.Addr().Is6() && !hello.Endpoint.Addr().Is4In6()
	actions = append(actions, event)
	if t.isExchangeAllowed(s, now) {
		s.lastExchange = now
		t.lastExchangeAsk = now
		actions = append(actions, RequestSources{Channel: ChannelExchange, Peer: peer})
	}
	return actions
}

func (t *Transfer) connectedSource(hello Hello) *source {
	for _, s := range t.sources {
		if s.state == stateConnecting && s.Endpoint.IsValid() && s.Endpoint == hello.Endpoint {
			return s
		}
	}
	for _, s := range t.sources {
		switch {
		case hello.UserHash != (wire.Hash{}) && s.UserHash == hello.UserHash,
			s.Endpoint.IsValid() && s.Endpoint == hello.Endpoint,
			s.ClientID != 0 && s.ClientID == hello.ClientID && s.Server == hello.Server:
			return s
		}
	}
	return nil
}

// isExchangeAllowed follows CUpDownClient::IsSourceRequestAllowed: rare files
// ask each source every SOURCECLIENTREASKS and the file every
// SOURCECLIENTREASKF; common files wait MINCOMMONPENALTY times longer.
func (t *Transfer) isExchangeAllowed(s *source, now time.Time) bool {
	count := t.validSourceCount()
	if !s.canExchange || count >= maxSourcesSoft {
		return false
	}
	isSourceDue := func(wait time.Duration) bool {
		return s.lastExchange.IsZero() || now.Sub(s.lastExchange) > wait
	}
	isFileDue := func(wait time.Duration) bool {
		return t.lastExchangeAsk.IsZero() || now.Sub(t.lastExchangeAsk) > wait
	}
	return count <= rareFile/5 && isSourceDue(exchangeReaskSlow) ||
		count <= rareFile && isSourceDue(exchangeReaskSlow) && isFileDue(exchangeReaskFast) ||
		isSourceDue(exchangeReaskSlow*commonPenalty) && isFileDue(exchangeReaskFast*commonPenalty)
}

// OnQueued records the queue rank a peer gave us.
func (t *Transfer) OnQueued(peer uint64, rank int, now time.Time) []Action {
	s := t.peers[peer]
	if !t.isDownloading() || s == nil {
		return nil
	}
	var actions []Action
	if s.state == stateDownloading {
		t.picker.Cancel(peer)
		actions = append(actions, t.sendReceived(s, now)...)
	}
	return append(actions, t.setQueued(s, rank, now))
}

func (t *Transfer) setQueued(s *source, rank int, now time.Time) TraceEvent {
	s.state = stateQueued
	s.rank = rank
	s.lastAsked = now
	event := t.buildTrace(now, s, EventQueued)
	event.Rank = rank
	return event
}

// OnReaskAnswered records the OP_REASKACK a source sent to our ReaskUDP.
func (t *Transfer) OnReaskAnswered(endpoint netip.AddrPort, rank int, now time.Time) []Action {
	for _, s := range t.sources {
		if s.isUDPPending && netip.AddrPortFrom(s.Endpoint.Addr(), s.UDPPort) == endpoint {
			s.isUDPPending = false
			return []Action{t.setQueued(s, rank, now)}
		}
	}
	return nil
}

func (t *Transfer) OnSlotGranted(peer uint64, now time.Time) []Action {
	s := t.peers[peer]
	if !t.isDownloading() || s == nil {
		return nil
	}
	s.state = stateDownloading
	s.lastAsked = now
	return []Action{t.buildTrace(now, s, EventSlot)}
}

// OnPeerGone detaches a closed connection. A source that answered our file
// request keeps its place and is reasked a reask interval after we connected,
// even when it closed before telling its queue rank, as a full upload queue
// does; only one that never answered counts as failed (aMule
// CUpDownClient::Disconnected, BaseClient.cpp:1280-1290: DS_ONQUEUE is set as
// soon as OP_STARTUPLOADREQ is sent and is kept, DS_CONNECTED goes to the dead
// list).
func (t *Transfer) OnPeerGone(peer uint64, reason string, now time.Time) []Action {
	s := t.peers[peer]
	if s == nil {
		return nil
	}
	delete(t.peers, peer)
	t.picker.OnPeerGone(peer)
	if peer == t.hashSetPeer {
		t.isHashSetAsked = false
	}
	s.isConnected = false
	actions := append(t.onRecoveryPeerGone(peer, now), t.sendReceived(s, now)...)
	switch {
	case s.state == stateAsking && !s.hasAnswered:
		return append(actions, t.setFailed(s, reason, now))
	case s.state == stateAsking:
		s.state = stateQueued
		s.rank = 0
	case s.state == stateDownloading:
		s.state = stateQueued
		s.rank = 0
		s.lastAsked = now
	}
	event := t.buildTrace(now, s, EventClosed)
	event.Reason = reason
	return append(actions, event)
}

func (t *Transfer) sendReceived(s *source, now time.Time) []Action {
	if s.receivedBytes == 0 {
		return nil
	}
	event := t.buildTrace(now, s, EventReceived)
	event.Bytes = s.receivedBytes
	s.receivedBytes = 0
	return []Action{event}
}

// removeCorrupt closes and forgets a peer that sent corrupt data, and refuses its user
// hash and endpoint from now on.
func (t *Transfer) removeCorrupt(peer uint64, now time.Time) []Action {
	s := t.senders[peer]
	if s == nil {
		return nil
	}
	if s.UserHash != (wire.Hash{}) {
		t.bannedHashes[s.UserHash] = true
	}
	if s.Endpoint.IsValid() {
		t.bannedEndpoints[s.Endpoint] = true
	}
	t.removeSource(s)
	event := t.buildTrace(now, s, EventClosed)
	event.Reason = "banned"
	actions := []Action{event}
	if t.peers[peer] == s {
		delete(t.peers, peer)
		t.picker.OnPeerGone(peer)
		actions = append(actions, Close{Peer: peer, Reason: "corrupt data"})
		actions = append(actions, t.onRecoveryPeerGone(peer, now)...)
	}
	return actions
}

// OnTick runs the timers: source reasks and connections within the budget,
// callback timeouts, source requests, the hash set request and publishing.
func (t *Transfer) OnTick(tick Tick) []Action {
	actions := t.pending
	t.pending = nil
	if !t.isRunning() {
		return actions
	}
	actions = append(actions, t.runPublish(tick.Now)...)
	if t.mode == ModeSeed {
		return actions
	}
	t.tick = tick
	if tick.IsFirewalled {
		t.sources = slices.DeleteFunc(t.sources, func(s *source) bool { return s.ClientID != 0 && !s.isConnected })
	}
	t.purgeNoNeeded(tick.Now)
	budget := tick.ConnectBudget
	for _, s := range slices.Clone(t.sources) {
		actions = append(actions, t.runSource(s, tick, &budget)...)
	}
	actions = append(actions, t.requestSources(tick)...)
	return append(actions, t.requestHashSet()...)
}

// SetA4AF leaves a source to another Transfer until the given time: that
// Transfer is asking the client for a slot, and asking it for this file as
// well would count as aggressive on the client (aMule's A4AF list,
// DownloadQueue.cpp:623-717). Meanwhile the source is neither connected to
// nor reasked. found names the source by user hash or endpoint, and gives it
// the user hash it lacked.
func (t *Transfer) SetA4AF(found Source, until time.Time) {
	for _, s := range t.sources {
		if !matchSource(s, found) {
			continue
		}
		if s.UserHash == (wire.Hash{}) {
			s.UserHash = found.UserHash
		}
		s.a4afUntil = until
		if s.state == stateConnecting || s.state == stateWaiting {
			s.state = stateNew
		}
	}
}

// OnNoNeededParts records that a connected source has no part we still
// need, or gave a slot with nothing left to request.
func (t *Transfer) OnNoNeededParts(peer uint64) {
	if s := t.peers[peer]; t.isDownloading() && s != nil {
		s.isNoNeeded = true
	}
}

func (t *Transfer) purgeNoNeeded(now time.Time) {
	if float64(len(t.sources)) < maxSources*noNeededPurgeShare || now.Sub(t.lastPurge) <= noNeededPurgeTime {
		return
	}
	i := slices.IndexFunc(t.sources, func(s *source) bool { return s.isNoNeeded && !s.isConnected && !now.Before(s.a4afUntil) })
	if i >= 0 {
		t.sources = slices.Delete(t.sources, i, i+1)
		t.lastPurge = now
	}
}

func (t *Transfer) runSource(s *source, tick Tick, budget *int) []Action {
	now := tick.Now
	switch s.state {
	case stateFailed:
		if now.Before(s.retryAt) {
			return nil
		}
		s.state = stateNew
		s.lastAsked = time.Time{}
	case stateConnecting:
		if !s.callbackTimeout.IsZero() && !now.Before(s.callbackTimeout) {
			return []Action{t.setFailed(s, "callback timeout", now)}
		}
		return nil
	case stateAsking, stateDownloading:
		return nil
	}
	if s.isConnected || now.Before(s.a4afUntil) {
		return nil
	}

	// aMule doubles the reask of a source with nothing we need and never
	// UDP-reasks it (PartFile.cpp:1574-1580).
	reaskTime := fileReaskTime
	if s.isNoNeeded {
		reaskTime *= 2
	}
	untilReask := time.Duration(0)
	if !s.lastAsked.IsZero() {
		untilReask = max(0, reaskTime-now.Sub(s.lastAsked))
	}
	if s.state == stateQueued && !s.isNoNeeded && untilReask < udpReaskLead && untilReask > 0 && t.canReaskUDP(s, tick) {
		s.isUDPPending = true
		s.udpReasks++
		return []Action{ReaskUDP{Endpoint: netip.AddrPortFrom(s.Endpoint.Addr(), s.UDPPort), UserHash: s.UserHash, CanObfuscate: s.CanObfuscate}}
	}
	if untilReask > 0 {
		return nil
	}
	if s.isUDPPending {
		s.isUDPPending = false
		s.udpFailed++
	}
	return t.requestConnect(s, tick, budget)
}

func (t *Transfer) canReaskUDP(s *source, tick Tick) bool {
	isReliable := s.udpReasks <= minUDPReasks || float64(s.udpFailed)/float64(s.udpReasks) <= maxUDPFailedShare
	return s.canReaskUDP && s.UDPPort != 0 && s.ClientID == 0 && !s.Buddy.IsValid() &&
		!tick.IsFirewalled && !s.isUDPPending && isReliable
}

func (t *Transfer) requestConnect(s *source, tick Tick, budget *int) []Action {
	if !t.canReach(s) {
		return nil
	}
	var action Action
	switch {
	case s.Buddy.IsValid():
		action = RequestKadCallback{Buddy: s.Buddy, BuddyID: s.BuddyID, IsDirect: s.IsDirectCallback, UserHash: s.UserHash, CanObfuscate: s.CanObfuscate}
	case s.ClientID != 0:
		action = RequestServerCallback{ClientID: s.ClientID}
	default:
		action = Connect{Endpoint: s.Endpoint, UserHash: s.UserHash, CanObfuscate: s.CanObfuscate}
	}
	if *budget <= 0 {
		s.state = stateWaiting
		return nil
	}
	*budget--
	s.state = stateConnecting
	s.callbackTimeout = time.Time{}
	if _, isConnect := action.(Connect); !isConnect {
		s.callbackTimeout = tick.Now.Add(callbackTimeout)
	}
	return []Action{action}
}

func (t *Transfer) requestSources(tick Tick) []Action {
	now := tick.Now
	count := t.validSourceCount()
	var actions []Action
	if tick.Server.IsValid() && count < maxSourcesSoft &&
		(tick.Server != t.lastServer || t.lastServerAsk.IsZero() || now.Sub(t.lastServerAsk) > serverReaskTime) {
		t.lastServer = tick.Server
		t.lastServerAsk = now
		actions = append(actions, RequestSources{Channel: ChannelServer})
	}
	if tick.Server.IsValid() && count < maxSourcesUDP &&
		(t.lastGlobalAsk.IsZero() || now.Sub(t.lastGlobalAsk) > globalServerReaskTime) {
		t.lastGlobalAsk = now
		actions = append(actions, RequestSources{Channel: ChannelGlobalServer})
	}
	if tick.IsKadRunning && count < maxSourcesUDP && !now.Before(t.nextKadAsk) {
		t.kadSearches = min(t.kadSearches+1, maxKadSearches)
		t.nextKadAsk = now.Add(kadReaskTime * time.Duration(t.kadSearches))
		actions = append(actions, RequestSources{Channel: ChannelKad})
	}
	return actions
}
