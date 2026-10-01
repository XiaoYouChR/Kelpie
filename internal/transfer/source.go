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
// than eMule does.
const (
	fileReaskTime = 29 * time.Minute // FILEREASKTIME
	// minRequestTime is MIN_REQUESTTIME, the reask time of a source that
	// is not on a queue (DS_NONE in GetTimeUntilReask).
	minRequestTime = 10 * time.Minute
	// connectRetryTime is the 20*60*1000 guard in CPartFile::Process: a
	// source is not reconnected within 20 minutes of the last attempt.
	connectRetryTime = 20 * time.Minute
	// udpReaskLead is the window before the TCP reask in which
	// CPartFile::Process tries OP_REASKFILEPING instead.
	udpReaskLead = 2 * time.Minute
	// udpReaskLast is CPartFile::Process's lower bound: no UDP reask within
	// one second of the TCP reask.
	udpReaskLast = time.Second
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
}

type source struct {
	key     string
	channel Channel
	Source
	canReaskUDP bool
	canExchange bool

	state       sourceState
	isConnected bool
	peer        uint64
	rank        int

	lastAsked       time.Time
	lastConnect     time.Time
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

func isUsable(found Source) bool {
	switch {
	case found.Buddy.IsValid():
		return found.UserHash != (wire.Hash{})
	case found.ClientID != 0:
		return wire.IsLowID(found.ClientID) && found.Server.IsValid()
	default:
		return found.Endpoint.IsValid() && found.Endpoint.Port() != 0
	}
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
	if !isUsable(found) || t.isBanned(found) {
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

// addNew makes room at the cap by dropping a failed source; without
// one, the new source is refused.
func (t *Transfer) addNew(found Source, channel Channel) *source {
	if len(t.sources) >= maxSources {
		i := slices.IndexFunc(t.sources, func(s *source) bool { return s.state == stateFailed })
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

func (t *Transfer) validSourceCount() int {
	count := 0
	for _, s := range t.sources {
		if s.state != stateFailed {
			count++
		}
	}
	return count
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
	s.state = stateAsking
	s.isConnected = true
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

// OnPeerGone detaches a closed connection. A queued source keeps its place
// and is reasked later; one that never answered counts as failed.
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
	actions := t.sendReceived(s, now)
	switch s.state {
	case stateAsking:
		return append(actions, t.setFailed(s, reason, now))
	case stateDownloading:
		s.state = stateNew
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
	budget := tick.ConnectBudget
	for _, s := range slices.Clone(t.sources) {
		actions = append(actions, t.runSource(s, tick, &budget)...)
	}
	actions = append(actions, t.requestSources(tick)...)
	return append(actions, t.requestHashSet()...)
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
	if s.isConnected {
		return nil
	}

	reaskTime := minRequestTime
	if s.state == stateQueued {
		reaskTime = fileReaskTime
	}
	untilReask := time.Duration(0)
	if !s.lastAsked.IsZero() {
		untilReask = max(0, reaskTime-now.Sub(s.lastAsked))
	}
	hasConnectGap := s.lastConnect.IsZero() || now.Sub(s.lastConnect) > connectRetryTime
	if !hasConnectGap {
		return nil
	}
	if s.state == stateQueued && untilReask < udpReaskLead && untilReask > udpReaskLast && t.canReaskUDP(s, tick) {
		s.isUDPPending = true
		s.udpReasks++
		return []Action{ReaskUDP{Endpoint: netip.AddrPortFrom(s.Endpoint.Addr(), s.UDPPort)}}
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
	var action Action
	switch {
	case s.Buddy.IsValid():
		if tick.IsFirewalled {
			return nil
		}
		action = RequestKadCallback{Buddy: s.Buddy, BuddyID: s.BuddyID}
	case s.ClientID != 0:
		if tick.IsFirewalled || s.Server != tick.Server {
			return nil
		}
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
	s.lastConnect = tick.Now
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
