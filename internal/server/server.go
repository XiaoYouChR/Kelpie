package server

import (
	"cmp"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/wire"
	packet "github.com/XiaoYouChR/Kelpie/internal/wire/server"
)

// eMule's timing and limits; names are eMule's (Opcodes.h unless noted).
const (
	connectTimeout = 25 * time.Second // CONSERVTIMEOUT, covers connect and login
	passRetryTime  = 30 * time.Second // CS_RETRYCONNECTTIME (sockets.h)
	maxFailures    = 10               // MAX_SERVERFAILCOUNT
	// maxAttempts follows aMule's TryAnotherConnectionrequest
	// (ServerConnect.cpp): two servers at once unless SafeServerConnect,
	// which is off by default; the first to log in wins.
	maxAttempts = 2

	sourceReaskTime     = 15 * time.Minute            // SERVERREASKTIME
	sourceFilesPerFrame = 15                          // iMaxFilesPerTcpFrame (DownloadQueue.cpp)
	sourceFrameTime     = 15 * (16 + 4) * time.Second // m_dwNextTCPSrcReq (DownloadQueue.cpp)
	offerTime           = time.Minute                 // ED2KREPUBLISHTIME
	maxOfferFiles       = 200                         // SendListToServer limit (SharedFileList.cpp)
	dnsSolveTime        = 30 * time.Minute            // DNS_SOLVE_TIME (aMule AsyncDNS.h)
	largeFileSize       = 4290048000                  // OLD_MAX_EMULE_FILE_SIZE
	edonkeyVersion      = 0x3C                        // EDONKEYVERSION
	// CapSupportCrypt makes the server answer with OP_FOUNDSOURCES_OBFU,
	// which carries the user hash an obfuscated connection needs.
	loginFlags = packet.CapZlib | packet.CapNewTags | packet.CapUnicode | packet.CapLargeFiles |
		packet.CapSupportCrypt | packet.CapRequestCrypt
	// cryptSupported is the CryptOptions bit for "supports obfuscation".
	cryptSupported byte = 0x01

	// keepAliveTime stands in for eMule's ServerKeepAliveTimeout, which is
	// off by default; an idle seeding Engine Process would otherwise lose
	// the connection to NAT timeouts. 20 minutes is far below eMule's own
	// source-request traffic on the same connection.
	keepAliveTime = 20 * time.Minute
)

// compatibleClient is Kelpie's id in CT_EMULE_VERSION. eMule and aMule
// assign 0-6, 0x0A, 0x14, 0x28, 0x32-0x36, 0x44, 0x98 and 0xFF (SO_*);
// 0x4B ('K') is unassigned.
const compatibleClient = 0x4B

// Config is what the login needs about us.
type Config struct {
	UserHash wire.Hash
	Port     uint16
	// Version is the Engine Process version, such as "v0.1.0".
	Version string
}

// Wanted is one file the engine shares or downloads, passed on every tick.
// Incomplete files are searched for sources; shared files are offered to
// the connected server.
type Wanted struct {
	File       wire.Hash
	Size       uint64
	Name       string
	IsComplete bool
	IsShared   bool
}

// Source is one peer a server named for a file. A LowID source has no
// Endpoint and is reachable only by RequestCallback through Server.
type Source struct {
	Endpoint netip.AddrPort
	ClientID uint32
	IsLowID  bool
	Server   netip.AddrPort
	UserHash wire.Hash
	// CanObfuscate: the source supports protocol obfuscation; obfuscation
	// aware servers tell it along with the user hash it needs.
	CanObfuscate bool
}

// Datagram is one UDP packet for a server's UDP port.
type Datagram struct {
	To     netip.AddrPort
	Packet wire.Packet
}

// Output is what the engine must do, in field order: close server
// connections, open new ones, send to the server at To, connect to peers
// that asked for a callback, and resolve host names, each answered with
// OnResolved. A server connection is named by the server's
// endpoint, even when dialled on its obfuscation port; reports about a
// closed one are ignored.
type Output struct {
	Close        []netip.AddrPort
	Connect      []Dial
	To           netip.AddrPort
	Send         []wire.Packet
	SendUDP      []Datagram
	ConnectPeers []Callback
	Resolve      []string
	Events       []Event
}

// Dial is a server connection to open. A non-zero ObfuscationPort means
// dialling that port and obfuscating the connection.
type Dial struct {
	Server          netip.AddrPort
	ObfuscationPort uint16
}

// Callback is a peer that asked, through the server, for us to connect.
// Obfuscation-aware servers pass on its crypt options and user hash, as
// aMule's OP_CALLBACKREQUESTED handling (ServerSocket.cpp) uses them.
type Callback struct {
	Endpoint     netip.AddrPort
	UserHash     wire.Hash
	CanObfuscate bool
}

type Event interface{ isEvent() }

// SourcesFound comes from the connected server, or from another server
// over UDP when IsGlobal.
type SourcesFound struct {
	File     wire.Hash
	Sources  []Source
	IsGlobal bool
}

// IDChanged reports the id the connected server gave us.
type IDChanged struct {
	Server   netip.AddrPort
	ClientID uint32
}

type MessageReceived struct{ Text string }

// CallbackFailed says the server could not reach the LowID peer of the
// last RequestCallback.
type CallbackFailed struct{}

func (SourcesFound) isEvent()    {}
func (IDChanged) isEvent()       {}
func (MessageReceived) isEvent() {}
func (CallbackFailed) isEvent()  {}

// listed is an Entry with what this process learned about it.
type listed struct {
	Entry
	// isDead marks a server that left a status ping unanswered until its
	// next turn; it is not pinged again. It is still asked for sources, as
	// aMule does: some servers answer source requests but not pings.
	isDead    bool
	challenge uint32
	pingedAt  time.Time
	// searchedAt is when the server was last asked for sources over UDP.
	searchedAt time.Time
	// tcpFlags are from the server's last OP_IDCHANGE.
	tcpFlags uint32
	// resolvedAt is when the answer for Host came; isResolving while it
	// is awaited.
	resolvedAt  time.Time
	isResolving bool
}

// isResolved: a server listed by host name has an address.
func (l *listed) isResolved() bool { return l.Endpoint.Addr().IsValid() }

// canObfuscateTCP is aMule's SupportsObfuscationTCP (Server.h:146).
func (l *listed) canObfuscateTCP() bool {
	return l.TCPObfuscationPort != 0 && (l.UDPFlags&packet.UDPFlagTCPObfuscation != 0 || l.tcpFlags&packet.FlagTCPObfuscation != 0)
}

// attempt is a server connection that has not logged in yet.
type attempt struct {
	server *listed
	since  time.Time
}

// Server owns the server list, the connection attempts and the one
// logged-in server connection.
type Server struct {
	config  Config
	servers []*listed
	wanted  []Wanted

	attempts []attempt
	// current is the server we are logged in to.
	current *listed
	tried   map[*listed]bool
	retryAt time.Time
	// isPlainPass is aMule's !m_bTryObfuscated: a pass first tries only
	// servers that obfuscate, then all of them plain.
	isPlainPass bool
	clientID    uint32
	tcpFlags    uint32
	lastSent    time.Time

	askedAt         map[wire.Hash]time.Time
	nextSourceFrame time.Time
	offered         map[wire.Hash]bool
	nextOffer       time.Time

	udp udpSearch
}

// BuildServer takes the entries of every server list; a server listed twice,
// by endpoint or by host name and port, keeps its first entry.
func BuildServer(config Config, entries []Entry) *Server {
	s := &Server{
		config:  config,
		tried:   map[*listed]bool{},
		askedAt: map[wire.Hash]time.Time{},
		offered: map[wire.Hash]bool{},
	}
	type key struct {
		host     string
		endpoint netip.AddrPort
	}
	seen := map[key]bool{}
	for _, e := range entries {
		k := key{e.Host, e.Endpoint}
		if seen[k] {
			continue
		}
		seen[k] = true
		s.servers = append(s.servers, &listed{Entry: e})
	}
	return s
}

func (s *Server) IsServerConnected() bool { return s.current != nil }

func (s *Server) IsHighID() bool { return s.IsServerConnected() && !wire.IsLowID(s.clientID) }

// ClientID is the id the connected server gave us; 0 while not logged in.
func (s *Server) ClientID() uint32 {
	if !s.IsServerConnected() {
		return 0
	}
	return s.clientID
}

func (s *Server) OnTick(now time.Time, wanted []Wanted) Output {
	s.wanted = wanted
	var out Output
	for _, a := range slices.Clone(s.attempts) {
		if now.Sub(a.since) > connectTimeout {
			out.Close = append(out.Close, a.server.Endpoint)
			s.setFailed(a.server.Endpoint)
		}
	}
	s.runResolve(now, &out)
	s.runConnect(now, &out)
	if s.current != nil {
		s.runSession(now, &out)
		s.runStats(now, &out)
		s.runSearch(now, &out)
	}
	return out
}

func (s *Server) OnConnected(server netip.AddrPort, now time.Time) Output {
	if s.attemptIndex(server) < 0 {
		return Output{}
	}
	login := packet.Login{
		UserHash:     s.config.UserHash,
		Port:         s.config.Port,
		Name:         "Kelpie",
		Version:      edonkeyVersion,
		Flags:        loginFlags,
		EmuleVersion: toEmuleVersion(s.config.Version),
	}
	return Output{To: server, Send: []wire.Packet{login}}
}

func (s *Server) OnConnectFailed(server netip.AddrPort, now time.Time) Output {
	if s.attemptIndex(server) < 0 {
		return Output{}
	}
	s.setFailed(server)
	var out Output
	s.runConnect(now, &out)
	return out
}

// OnDisconnected handles the end of a server connection at any stage.
// Losing a server before login counts against it; losing it afterwards
// moves on to the next server, as eMule's reconnect does.
func (s *Server) OnDisconnected(server netip.AddrPort, now time.Time) Output {
	switch {
	case s.current != nil && s.current.Endpoint == server:
		s.tried[s.current] = true
		s.current = nil
	case s.attemptIndex(server) >= 0:
		s.setFailed(server)
	default:
		return Output{}
	}
	var out Output
	s.runConnect(now, &out)
	return out
}

// OnResolved takes the address host resolved to; an invalid addr means
// the lookup failed, and the old address, if any, stays. A server in use
// keeps its address until the next lookup.
func (s *Server) OnResolved(host string, addr netip.Addr, now time.Time) Output {
	for _, l := range s.servers {
		if l.Host != host || !l.isResolving {
			continue
		}
		l.isResolving = false
		l.resolvedAt = now
		endpoint := netip.AddrPortFrom(addr, l.Endpoint.Port())
		isInUse := l == s.current || slices.ContainsFunc(s.attempts, func(a attempt) bool { return a.server == l })
		if isUsable(endpoint) && !isInUse && s.serverByEndpoint(endpoint) == nil {
			l.Endpoint = endpoint
		}
	}
	var out Output
	s.runConnect(now, &out)
	return out
}

// runResolve looks host names up again every DNS_SOLVE_TIME, as aMule does
// before UDP packets (ServerUDPSocket.cpp:420-450); aMule also looks one up
// before each connection, which Kelpie folds into the same cycle: a server
// is not connected while its lookup is out.
func (s *Server) runResolve(now time.Time, out *Output) {
	for _, l := range s.servers {
		isFresh := !l.resolvedAt.IsZero() && now.Sub(l.resolvedAt) < dnsSolveTime
		if l.Host == "" || l.isResolving || isFresh || l == s.current {
			continue
		}
		l.isResolving = true
		if !slices.Contains(out.Resolve, l.Host) {
			out.Resolve = append(out.Resolve, l.Host)
		}
	}
}

func (s *Server) serverByEndpoint(endpoint netip.AddrPort) *listed {
	for _, l := range s.servers {
		if l.Endpoint == endpoint {
			return l
		}
	}
	return nil
}

// OnPacket takes a packet from the server at from, logged in or still
// logging in.
func (s *Server) OnPacket(from netip.AddrPort, p wire.Packet, now time.Time) Output {
	var out Output
	sender := s.current
	if i := s.attemptIndex(from); i >= 0 {
		sender = s.attempts[i].server
	}
	if sender == nil || sender.Endpoint != from {
		return out
	}
	switch p := p.(type) {
	case packet.IDChange:
		s.onIDChange(sender, p, now, &out)
	case packet.ServerMessage:
		out.Events = append(out.Events, MessageReceived{Text: p.Text})
	case packet.ServerStatus:
		sender.Users, sender.Files = p.Users, p.Files
	case packet.ServerIdent:
		if p.Name != "" {
			sender.Name, sender.Description = p.Name, p.Description
		}
	}
	if sender != s.current {
		return out
	}
	switch p := p.(type) {
	case packet.FoundSources:
		s.onFoundSources(p.Hash, p.Sources, &out)
	case packet.FoundSourcesObfu:
		s.onFoundSources(p.Hash, p.Sources, &out)
	case packet.CallbackRequested:
		if p.Addr.IsValid() && p.Addr.Port() != 0 {
			out.ConnectPeers = append(out.ConnectPeers, Callback{
				Endpoint:     p.Addr,
				UserHash:     p.UserHash,
				CanObfuscate: p.CryptOptions&cryptSupported != 0 && p.UserHash != wire.Hash{},
			})
		}
	case packet.CallbackRequestedIPv6:
		if p.Addr.IsValid() && p.Addr.Port() != 0 {
			out.ConnectPeers = append(out.ConnectPeers, Callback{Endpoint: p.Addr})
		}
	case packet.CallbackFailed:
		out.Events = append(out.Events, CallbackFailed{})
	}
	return out
}

// RequestCallback asks the connected server to have a LowID source connect
// to us. It is possible only when we are HighID and the source came from
// the server we are connected to.
func (s *Server) RequestCallback(source Source, now time.Time) (Output, bool) {
	if !s.IsHighID() || !source.IsLowID || source.Server != s.current.Endpoint {
		return Output{}, false
	}
	s.lastSent = now
	return Output{To: s.current.Endpoint, Send: []wire.Packet{packet.CallbackRequest{ClientID: source.ClientID}}}, true
}

// onIDChange logs in to the first attempt that gets an id and closes the
// other one, which aMule's StopConnectionTry does without counting a
// failure.
func (s *Server) onIDChange(sender *listed, p packet.IDChange, now time.Time, out *Output) {
	if p.ClientID == 0 {
		return
	}
	// aMule keeps both for the next connection (ServerSocket.cpp:262, 289-296).
	sender.tcpFlags = p.Flags
	if p.ObfuscationPort != 0 {
		sender.TCPObfuscationPort = uint16(p.ObfuscationPort)
	}
	if sender != s.current {
		for _, a := range s.attempts {
			if a.server != sender {
				out.Close = append(out.Close, a.server.Endpoint)
			}
		}
		s.attempts = nil
		s.current = sender
		s.current.Failures = 0
		s.lastSent = now
		clear(s.tried)
		clear(s.offered)
		s.nextSourceFrame = now
		s.nextOffer = now
	}
	s.clientID, s.tcpFlags = p.ClientID, p.Flags
	out.Events = append(out.Events, IDChanged{Server: s.current.Endpoint, ClientID: p.ClientID})
	s.runSession(now, out)
}

func (s *Server) onFoundSources(file wire.Hash, found []packet.Source, out *Output) {
	if !s.isWanted(file) {
		return
	}
	var sources []Source
	for _, f := range found {
		src, ok := s.toSource(f, s.current.Endpoint)
		if ok && (!src.IsLowID || !wire.IsLowID(s.clientID)) {
			sources = append(sources, src)
		}
	}
	if len(sources) > 0 {
		out.Events = append(out.Events, SourcesFound{File: file, Sources: sources})
	}
}

func (s *Server) toSource(f packet.Source, server netip.AddrPort) (Source, bool) {
	src := Source{
		ClientID:     f.ClientID,
		Server:       server,
		UserHash:     f.UserHash,
		CanObfuscate: f.CryptOptions&cryptSupported != 0 && f.CryptOptions&packet.CryptHasUserHash != 0,
	}
	switch {
	case f.Port == 0 || f.ClientID == 0:
		return src, false
	case f.ClientID == wire.IPv6Sentinel:
		src.Endpoint = netip.AddrPortFrom(f.IPv6, f.Port)
		return src, f.IPv6.IsValid()
	case wire.IsLowID(f.ClientID):
		src.IsLowID = true
		return src, true
	case f.ClientID == s.clientID && f.Port == s.config.Port:
		return src, false
	}
	src.Endpoint = netip.AddrPortFrom(wire.ToAddr(f.ClientID), f.Port)
	return src, true
}

func (s *Server) isWanted(file wire.Hash) bool {
	return slices.ContainsFunc(s.wanted, func(w Wanted) bool { return w.File == file && !w.IsComplete })
}

func (s *Server) attemptIndex(server netip.AddrPort) int {
	return slices.IndexFunc(s.attempts, func(a attempt) bool { return a.server.Endpoint == server })
}

func (s *Server) setFailed(server netip.AddrPort) {
	i := s.attemptIndex(server)
	s.attempts[i].server.Failures++
	s.attempts = slices.Delete(s.attempts, i, i+1)
}

// runConnect keeps maxAttempts servers of the current pass in flight. A
// pass tries every server once, best first. As in aMule
// (ServerConnect.cpp:54-88), the first pass tries only servers that
// obfuscate, on their obfuscation port when they have one, and "another
// pass without obfuscation" follows at once. When the plain pass runs out
// and no attempt is left, eMule waits CS_RETRYCONNECTTIME so a short list
// is not hammered.
func (s *Server) runConnect(now time.Time, out *Output) {
	if s.current != nil || now.Before(s.retryAt) {
		return
	}
	for len(s.attempts) < maxAttempts {
		next := s.nextServer()
		switch {
		case next == nil && len(s.attempts) > 0:
			return
		case next == nil && !s.isPlainPass:
			s.isPlainPass = true
			clear(s.tried)
			continue
		case next == nil:
			if len(s.tried) > 0 {
				s.isPlainPass = false
				clear(s.tried)
				s.retryAt = now.Add(passRetryTime)
			}
			return
		}
		s.tried[next] = true
		s.attempts = append(s.attempts, attempt{server: next, since: now})
		dial := Dial{Server: next.Endpoint}
		if !s.isPlainPass && next.canObfuscateTCP() {
			dial.ObfuscationPort = next.TCPObfuscationPort
		}
		out.Connect = append(out.Connect, dial)
	}
}

// nextServer prefers high preference, then fewer failures, then more users
// and files: a bigger server knows more sources. An obfuscated pass skips
// servers that support neither TCP nor UDP obfuscation, as aMule's
// GetNextServer does (ServerList.cpp:580-596).
func (s *Server) nextServer() *listed {
	var best *listed
	for _, l := range s.servers {
		canObfuscate := l.canObfuscateTCP() || l.UDPFlags&packet.UDPFlagUDPObfuscation != 0
		if s.tried[l] || l.Failures >= maxFailures || !l.isResolved() || l.isResolving || (!s.isPlainPass && !canObfuscate) {
			continue
		}
		if best == nil || isBetter(l, best) {
			best = l
		}
	}
	return best
}

func isBetter(a, b *listed) bool {
	rank := func(p Preference) int {
		switch p {
		case PreferenceHigh:
			return 0
		case PreferenceLow:
			return 2
		}
		return 1
	}
	return cmp.Or(
		cmp.Compare(rank(a.Preference), rank(b.Preference)),
		cmp.Compare(a.Failures, b.Failures),
		cmp.Compare(b.Users, a.Users),
		cmp.Compare(b.Files, a.Files),
	) < 0
}

func (s *Server) runSession(now time.Time, out *Output) {
	out.To = s.current.Endpoint
	n := len(out.Send)
	s.runSourceRequests(now, out)
	s.runOffer(now, out)
	if len(out.Send) == n && now.Sub(s.lastSent) >= keepAliveTime {
		// eMule's keep-alive is an empty OP_OFFERFILES.
		out.Send = append(out.Send, packet.OfferFiles{})
	}
	if len(out.Send) > n {
		s.lastSent = now
	}
}

// runSourceRequests sends one frame of up to 15 OP_GETSOURCES, longest
// waiting file first, and no file more often than SERVERREASKTIME. The
// per-file times survive reconnects, as in eMule.
func (s *Server) runSourceRequests(now time.Time, out *Output) {
	if now.Before(s.nextSourceFrame) {
		return
	}
	var due []Wanted
	for _, w := range s.wanted {
		at, isAsked := s.askedAt[w.File]
		if w.IsComplete || (isAsked && now.Sub(at) < sourceReaskTime) || !s.canTCP(w.Size) {
			continue
		}
		due = append(due, w)
	}
	if len(due) == 0 {
		return
	}
	slices.SortStableFunc(due, func(a, b Wanted) int { return s.askedAt[a.File].Compare(s.askedAt[b.File]) })
	for _, w := range due[:min(len(due), sourceFilesPerFrame)] {
		request := packet.GetSources{Hash: w.File, Size: w.Size}
		if s.tcpFlags&packet.FlagTCPObfuscation != 0 {
			out.Send = append(out.Send, packet.GetSourcesObfu(request))
		} else {
			out.Send = append(out.Send, request)
		}
		s.askedAt[w.File] = now
	}
	s.nextSourceFrame = now.Add(sourceFrameTime)
}

// runOffer publishes shared files the server has not seen in this
// connection, at most once per ED2KREPUBLISHTIME and capped like eMule's
// SendListToServer. A file offered while partial is offered again once
// complete.
func (s *Server) runOffer(now time.Time, out *Output) {
	if now.Before(s.nextOffer) {
		return
	}
	limit := maxOfferFiles
	if soft := int(s.current.SoftFiles); soft > 0 && soft < limit {
		limit = soft
	}
	var files []packet.OfferedFile
	for _, w := range s.wanted {
		if len(files) == limit {
			break
		}
		wasComplete, isOffered := s.offered[w.File]
		if !w.IsShared || (isOffered && wasComplete == w.IsComplete) || !s.canTCP(w.Size) {
			continue
		}
		files = append(files, s.toOffered(w))
		s.offered[w.File] = w.IsComplete
	}
	if len(files) == 0 {
		return
	}
	out.Send = append(out.Send, packet.OfferFiles{Files: files})
	s.nextOffer = now.Add(offerTime)
}

func (s *Server) toOffered(w Wanted) packet.OfferedFile {
	f := packet.OfferedFile{Hash: w.File}
	switch {
	case s.tcpFlags&packet.FlagCompression != 0 && w.IsComplete:
		f.ClientID, f.Port = packet.CompleteID, packet.CompletePort
	case s.tcpFlags&packet.FlagCompression != 0:
		f.ClientID, f.Port = packet.IncompleteID, packet.IncompletePort
	case !wire.IsLowID(s.clientID):
		f.ClientID, f.Port = s.clientID, s.config.Port
	}
	f.Tags = []wire.Tag{
		{Type: wire.TagString, ID: packet.FileName, String: w.Name},
		{Type: wire.TagUint32, ID: packet.FileSize, Uint: w.Size & 0xFFFFFFFF},
	}
	if w.Size > 0xFFFFFFFF {
		f.Tags = append(f.Tags, wire.Tag{Type: wire.TagUint32, ID: packet.FileSizeHi, Uint: w.Size >> 32})
	}
	return f
}

func (s *Server) canTCP(size uint64) bool {
	return size <= largeFileSize || s.tcpFlags&packet.FlagLargeFiles != 0
}

// toEmuleVersion packs "v1.2.3" into CT_EMULE_VERSION: compatible client,
// then major, minor and update in 7, 7 and 3 bits.
func toEmuleVersion(version string) uint32 {
	var parts [3]uint32
	for i, part := range strings.SplitN(strings.TrimPrefix(version, "v"), ".", 3) {
		for _, r := range part {
			if r < '0' || r > '9' {
				break
			}
			parts[i] = parts[i]*10 + uint32(r-'0')
		}
	}
	return compatibleClient<<24 | (parts[0]&0x7F)<<17 | (parts[1]&0x7F)<<10 | (parts[2]&0x07)<<7
}
