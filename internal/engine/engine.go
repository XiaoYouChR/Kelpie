// Package engine is the Engine hub actor (ADR-0005). One goroutine owns the
// runs and their transfers, the peer sessions, the upload queue, credits and
// the server connection, and performs the I/O their state machines ask for.
// Every other goroutine is a stateless leaf: per connection a reader and a
// writer, the disk workers, the trace writer and the store saver. Kad is the
// other hub.
package engine

import (
	"context"
	crand "crypto/rand"
	"errors"
	"fmt"
	"log"
	"maps"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/clock"
	"github.com/XiaoYouChR/Kelpie/internal/disk"
	"github.com/XiaoYouChR/Kelpie/internal/identity"
	"github.com/XiaoYouChR/Kelpie/internal/kad"
	"github.com/XiaoYouChR/Kelpie/internal/nat"
	"github.com/XiaoYouChR/Kelpie/internal/server"
	"github.com/XiaoYouChR/Kelpie/internal/store"
	"github.com/XiaoYouChR/Kelpie/internal/transport"
	"github.com/XiaoYouChR/Kelpie/internal/upload"
	"github.com/XiaoYouChR/Kelpie/internal/wire"
)

// Ports are the engine's only ways out: sockets, files, time and randomness,
// and the host's interface addresses as they were at start.
type Ports struct {
	Transport  transport.Transport
	Disk       disk.Disk
	Clock      clock.Clock
	Rand       *rand.Rand
	LocalAddrs []netip.Addr
}

const (
	// tickInterval follows upload.Queue, which wants a tick about every
	// 100 ms as eMule runs CUploadQueue::Process; everything else ticks once
	// a second.
	tickInterval   = 100 * time.Millisecond
	secondInterval = time.Second
	saveInterval   = time.Minute
	// eMule's MaxConnections and MaxConperFive defaults.
	maxConnections      = 500
	maxNewConnections   = 20
	newConnectionWindow = 5 * time.Second
	connectTimeout      = 40 * time.Second // CONNECTION_TIMEOUT
	// pipeline is how many blocks a download keeps requested from one peer;
	// eMule asks for three ranges per OP_REQUESTPARTS.
	pipeline    = 3
	diskWorkers = 4
	// openPortTries bounds the search for a port free for both TCP and UDP
	// when the caller asks for any port.
	openPortTries = 8
	natTimeout    = 10 * time.Second
)

// capacities size every channel the hub sends on or receives from. Tests set
// them all to one to check that no send blocks the hub (ADR-0005).
type capacities struct {
	inbox  int
	writer int
	disk   int
	trace  int
}

var defaultCapacities = capacities{inbox: 256, writer: 64, disk: 16, trace: 256}

// openNAT maps the listening ports on the gateway; nil skips UPnP.
type openNAT func(ctx context.Context, tcpPort, udpPort int) (func(context.Context) error, netip.Addr, error)

type Engine struct {
	config Config
	ports  Ports
	events Events
	caps   capacities

	inbox   chan any
	ctx     context.Context
	cancel  context.CancelFunc
	leaves  sync.WaitGroup
	hubDone chan struct{}

	closeOnce sync.Once
	closeErr  error

	// packetLog is nil unless Config.PacketLog is set; leaves write to it.
	packetLog *log.Logger

	// The limiters are shared memory, safe from any goroutine (ADR-0005).
	downloadLimiter *transport.Limiter
	uploadLimiter   *transport.Limiter

	// Everything below is owned by the hub goroutine.
	state     store.State
	self      identity.Self
	ledger    *identity.Ledger
	queue     *upload.Queue
	server    *server.Server
	kad       *kad.Kad
	kadCancel context.CancelFunc
	kadDone   chan struct{}
	kadStatus kad.Status
	kadID     wire.Hash
	buddy     buddy
	listener  transport.Listener
	udp       transport.PacketConn
	tcpPort   int
	udpPort   int
	saves     chan store.State
	saverDone chan struct{}
	trace     *leafQueue[traceLine]
	disk      *leafQueue[diskJob]
	unmapNAT  func(context.Context) error
	// directCallbacks holds when each IP last asked us for a direct
	// callback.
	directCallbacks map[netip.Addr]time.Time

	serverAddr netip.AddrPort
	publicIP   netip.Addr
	mappedIP   netip.Addr
	network    Network
	hasNetwork bool

	nextConn        uint64
	conns           map[uint64]*conn
	runs            map[RunID]*run
	runByHash       map[wire.Hash]*run
	runList         []*run
	sourceUsers     map[wire.Hash]map[wire.Hash]bool
	sourceLowIDs    map[lowIDKey]map[wire.Hash]bool
	uploadEndpoints map[uploadKey]uploadTarget
	a4afClients     map[wire.Hash]*a4afClient
	kadChecks       map[uint64]kadCheck
	recentConnects  []time.Time
	budgetCursor    int
	lastSecond      time.Time
	lastSave        time.Time
}

type lowIDKey struct {
	clientID uint32
	server   netip.AddrPort
}

type uploadKey struct {
	user wire.Hash
	ip   netip.Addr
}

// Start runs an Engine on the real network, disk and clock.
func Start(config Config, events Events) (*Engine, error) {
	var seed [32]byte
	crand.Read(seed[:])
	ports := Ports{
		Transport:  transport.Real{},
		Disk:       disk.Real{},
		Clock:      clock.Real{},
		Rand:       rand.New(rand.NewChaCha8(seed)),
		LocalAddrs: probeLocalAddrs(),
	}
	var mapPorts openNAT
	if config.EnableUPnP {
		mapPorts = func(ctx context.Context, tcpPort, udpPort int) (func(context.Context) error, netip.Addr, error) {
			return nat.Open(ctx, tcpPort, udpPort, "Kelpie")
		}
	}
	return build(config, ports, events, defaultCapacities, mapPorts)
}

// probeLocalAddrs lists the host's interface addresses; without them only
// the public IP tells our own sources apart, so a failure is just logged.
func probeLocalAddrs() []netip.Addr {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Printf("engine: interface addresses: %v", err)
		return nil
	}
	var local []netip.Addr
	for _, a := range addrs {
		if prefix, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(prefix.IP); ok {
				local = append(local, ip.Unmap())
			}
		}
	}
	return local
}

// Build runs an Engine on the given ports; tests pass fakes. UPnP is never
// attempted.
func Build(config Config, ports Ports, events Events) (*Engine, error) {
	return build(config, ports, events, defaultCapacities, nil)
}

func build(config Config, ports Ports, events Events, caps capacities, mapPorts openNAT) (*Engine, error) {
	state, err := store.Load(config.DataFolder)
	if err != nil {
		return nil, toStartFailed(err)
	}
	self, err := loadSelf(config.DataFolder, &state)
	if err != nil {
		return nil, toStartFailed(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	e := &Engine{
		config:          config,
		ports:           ports,
		events:          events,
		caps:            caps,
		inbox:           make(chan any, caps.inbox),
		ctx:             ctx,
		cancel:          cancel,
		hubDone:         make(chan struct{}),
		downloadLimiter: transport.BuildLimiter(ports.Clock, config.RateLimits.Download),
		uploadLimiter:   transport.BuildLimiter(ports.Clock, config.RateLimits.Upload),
		state:           state,
		self:            self,
		ledger:          identity.BuildLedger(toCredits(state.Credits), ports.Clock.Now()),
		saves:           make(chan store.State, 1),
		saverDone:       make(chan struct{}),
		disk:            buildLeafQueue[diskJob](caps.disk),
		conns:           map[uint64]*conn{},
		runs:            map[RunID]*run{},
		runByHash:       map[wire.Hash]*run{},
		sourceUsers:     map[wire.Hash]map[wire.Hash]bool{},
		sourceLowIDs:    map[lowIDKey]map[wire.Hash]bool{},
		uploadEndpoints: map[uploadKey]uploadTarget{},
		a4afClients:     map[wire.Hash]*a4afClient{},
		kadChecks:       map[uint64]kadCheck{},
		buddy:           buddy{incoming: map[netip.Addr]incomingBuddy{}},
		directCallbacks: map[netip.Addr]time.Time{},
	}
	if config.PacketLog != nil {
		e.packetLog = log.New(config.PacketLog, "packet ", log.Lmicroseconds)
		e.ports.Transport = udpLogTransport{Transport: ports.Transport, log: e.packetLog, clock: ports.Clock}
	}
	e.queue = upload.BuildQueue(e.ledger.Ratio, e.ledger.TrustByUser, func(wire.Hash, netip.Addr) bool { return false })
	e.queue.SetRate(config.RateLimits.Upload)
	if err := e.openSockets(); err != nil {
		cancel()
		return nil, toStartFailed(err)
	}
	if config.TraceFile != "" {
		file, err := os.OpenFile(config.TraceFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
		if err != nil {
			e.closeSockets()
			cancel()
			return nil, toStartFailed(err)
		}
		e.trace = buildLeafQueue[traceLine](caps.trace)
		e.startLeaf(func() { e.runTraceWriter(file, e.trace.items) })
	}
	e.server = server.BuildServer(server.Config{
		UserHash: self.UserHash,
		Port:     uint16(e.tcpPort),
		Version:  config.Version,
	}, updateLearned(loadServerLists(config.ServerLists), state.Servers))
	if config.EnableKad {
		e.startKad(loadNodeLists(config.NodeLists))
	}

	now := ports.Clock.Now()
	e.lastSecond, e.lastSave = now, now
	for range diskWorkers {
		e.startLeaf(func() { e.runDiskWorker(e.disk.items) })
	}
	go e.runSaver()
	e.startLeaf(e.runAcceptor)
	if e.udp != nil {
		e.startLeaf(e.runUDPReader)
	}
	if mapPorts != nil {
		e.startLeaf(func() { e.runNAT(mapPorts) })
	}
	e.refreshNetwork()
	go e.run()
	return e, nil
}

func toStartFailed(err error) *Error {
	return &Error{Code: CodeStartFailed, Message: err.Error()}
}

// loadSelf creates our identity on first start and saves it at once, so a
// crash before the first periodic save cannot change who we are.
func loadSelf(folder string, state *store.State) (identity.Self, error) {
	if state.Identity.UserHash != (wire.Hash{}) && len(state.Identity.PrivateKey) > 0 {
		return identity.LoadSelf(state.Identity.UserHash, state.Identity.PrivateKey)
	}
	self, err := identity.CreateSelf()
	if err != nil {
		return identity.Self{}, err
	}
	if state.Identity.UserHash != (wire.Hash{}) {
		self, err = identity.LoadSelf(state.Identity.UserHash, self.PrivateKey())
		if err != nil {
			return identity.Self{}, err
		}
	}
	state.Identity = store.Identity{UserHash: self.UserHash, PrivateKey: self.PrivateKey()}
	return self, store.Save(folder, *state)
}

func toCredits(credits map[wire.Hash]store.Credit) []identity.Credit {
	var list []identity.Credit
	for user, c := range credits {
		list = append(list, identity.Credit{User: user, Uploaded: c.Uploaded, Downloaded: c.Downloaded, PublicKey: c.PublicKey, LastSeen: c.LastSeen})
	}
	return list
}

// loadServerLists merges every list; a list that cannot be read is skipped,
// since the others still find servers.
func loadServerLists(paths []string) []server.Entry {
	var entries []server.Entry
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err == nil {
			var list []server.Entry
			list, err = server.ParseMet(data)
			entries = append(entries, list...)
		}
		if err != nil {
			log.Printf("engine: skip server list %s: %v", path, err)
		}
	}
	return entries
}

func loadNodeLists(paths []string) []kad.Node {
	var nodes []kad.Node
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err == nil {
			var list []kad.Node
			list, err = kad.ParseNodes(data)
			nodes = append(nodes, list...)
		}
		if err != nil {
			log.Printf("engine: skip node list %s: %v", path, err)
		}
	}
	return nodes
}

// openSockets binds TCP and UDP to one port number. With Kad, Kad owns the
// UDP socket, so it is only probed here to fail Start synchronously.
func (e *Engine) openSockets() error {
	tries := 1
	if e.config.Port == 0 {
		tries = openPortTries
	}
	var err error
	for range tries {
		var listener transport.Listener
		listener, err = e.ports.Transport.OpenListener(e.config.Port)
		if err != nil {
			return err
		}
		var udp transport.PacketConn
		udp, err = e.ports.Transport.OpenUDP(listener.Port())
		if err != nil {
			listener.Close()
			continue
		}
		e.listener, e.tcpPort, e.udpPort = listener, listener.Port(), udp.Port()
		if e.config.EnableKad {
			udp.Close()
		} else {
			e.udp = udp
		}
		return nil
	}
	return err
}

func (e *Engine) closeSockets() {
	e.listener.Close()
	if e.udp != nil {
		e.udp.Close()
	}
}

func (e *Engine) startKad(nodes []kad.Node) {
	random := e.ports.Rand
	e.kad = kad.BuildKad(kad.Config{
		Transport: e.ports.Transport,
		Clock:     e.ports.Clock,
		Port:      e.udpPort,
		TCPPort:   uint16(e.tcpPort),
		UserHash:  e.self.UserHash,
		State:     e.state.Kad,
		Nodes:     nodes,
		Rand:      rand.New(rand.NewPCG(random.Uint64(), random.Uint64())),
	})
	e.kadStatus = kad.Status{IsFirewalled: true}
	e.kadID = e.kad.State().ID
	ctx, cancel := context.WithCancel(e.ctx)
	e.kadCancel = cancel
	e.kadDone = make(chan struct{})
	go func() {
		defer close(e.kadDone)
		if err := e.kad.Run(ctx); err != nil {
			log.Printf("engine: kad: %v", err)
		}
	}()
}

func (e *Engine) startLeaf(f func()) {
	e.leaves.Add(1)
	go func() {
		defer e.leaves.Done()
		f()
	}()
}

// post is how a leaf hands the hub a message. It may block: that is the
// backpressure ADR-0005 allows. It gives up once ctx ends.
func (e *Engine) send(ctx context.Context, m any) bool {
	select {
	case e.inbox <- m:
		return true
	case <-ctx.Done():
		return false
	}
}

// Post hands a command to the hub.
func (e *Engine) Post(command Command) {
	e.send(e.ctx, commandPosted{command})
}

// Close ends every open run, saves Durable State, closes the sockets and
// waits for every goroutine.
func (e *Engine) Close() error {
	e.closeOnce.Do(func() {
		reply := make(chan error, 1)
		select {
		case e.inbox <- closeRequested{reply}:
			e.closeErr = <-reply
		case <-e.hubDone:
		}
		e.cancel()
		e.leaves.Wait()
	})
	return e.closeErr
}

// Messages from leaves to the hub.
type (
	commandPosted  struct{ command Command }
	closeRequested struct{ reply chan<- error }
	connAccepted   struct{ conn net.Conn }
	connOpened     struct {
		id   uint64
		conn net.Conn
		err  error
	}
	packetReceived struct {
		id     uint64
		packet wire.Packet
	}
	connClosed struct {
		id  uint64
		err error
	}
	packetSent struct {
		id      uint64
		file    wire.Hash
		payload int64
	}
	traceWritten     struct{}
	datagramReceived struct {
		from netip.AddrPort
		data []byte
	}
	natOpened struct {
		unmap func(context.Context) error
		ip    netip.Addr
		err   error
	}
)

// leafQueue is how the hub sends to a leaf without ever blocking: it puts
// at most credit items on the channel, which has room for all of them, and
// keeps the rest until the leaf reports one done.
type leafQueue[T any] struct {
	items   chan T
	credit  int
	backlog []T
}

func buildLeafQueue[T any](capacity int) *leafQueue[T] {
	return &leafQueue[T]{items: make(chan T, capacity), credit: capacity}
}

func (q *leafQueue[T]) send(item T) {
	if q.credit > 0 && len(q.backlog) == 0 {
		q.credit--
		q.items <- item
		return
	}
	q.backlog = append(q.backlog, item)
}

func (q *leafQueue[T]) onDone() {
	q.credit++
	if len(q.backlog) > 0 {
		item := q.backlog[0]
		q.backlog = q.backlog[1:]
		q.credit--
		q.items <- item
	}
}

func (e *Engine) now() time.Time { return e.ports.Clock.Now() }

func (e *Engine) run() {
	defer close(e.hubDone)
	ticker := e.ports.Clock.CreateTicker(tickInterval)
	defer ticker.Stop()
	var found <-chan kad.SourcesFound
	var received <-chan kad.Datagram
	var statuses <-chan kad.Status
	var requests <-chan kad.Request
	if e.kad != nil {
		found, received, statuses, requests = e.kad.Found(), e.kad.Received(), e.kad.Statuses(), e.kad.Requests()
	}
	for {
		select {
		case m := <-e.inbox:
			if request, ok := m.(closeRequested); ok {
				request.reply <- e.stop()
				return
			}
			e.onMessage(m)
		case <-ticker.C():
			e.onTick()
		case f := <-found:
			e.onKadSources(f)
		case d := <-received:
			e.onDatagram(d.Addr, d.Data)
		case s := <-statuses:
			e.kadStatus = s
		case r := <-requests:
			e.onKadRequest(r)
		}
		e.refreshRuns()
		e.refreshNetwork()
	}
}

func (e *Engine) onMessage(m any) {
	switch m := m.(type) {
	case commandPosted:
		e.onCommand(m.command)
	case connAccepted:
		e.onConnAccepted(m.conn)
	case connOpened:
		e.onConnOpened(m)
	case packetReceived:
		e.onPacket(m.id, m.packet)
	case connClosed:
		if c := e.conns[m.id]; c != nil {
			e.closeConn(c, toReason(m.err))
		}
	case packetSent:
		e.onPacketSent(m)
	case diskDone:
		e.onDiskDone(m)
	case traceWritten:
		e.trace.onDone()
	case datagramReceived:
		e.onDatagram(m.from, m.data)
	case natOpened:
		e.onNATOpened(m)
	case hostResolved:
		e.runServer(e.server.OnResolved(m.host, m.addr, e.now()))
	}
}

func (e *Engine) onTick() {
	now := e.now()
	e.runQueueActions(e.queue.OnTick(now))
	if now.Sub(e.lastSecond) < secondInterval {
		return
	}
	e.lastSecond = now
	for _, c := range e.sortedConns() {
		if c.session != nil && !c.isClosed {
			e.runSession(c, c.session.OnTick(now))
		}
	}
	e.runTransfers(now)
	e.refreshUploadEndpoints()
	e.refreshKnownSources()
	e.refreshAsked()
	e.refreshA4AF()
	e.runServer(e.server.OnTick(now, e.buildServerWanted()))
	e.runBuddy(now)
	if e.kad != nil {
		e.kad.SetWanted(e.buildKadWanted())
	}
	for _, r := range e.runList {
		e.refreshProgress(r, false)
	}
	if now.Sub(e.lastSave) >= saveInterval {
		e.lastSave = now
		e.ledger.RemoveIdle(now)
		e.requestSave()
	}
}

func (e *Engine) refreshNetwork() {
	network := Network{
		IsServerConnected: e.server.IsServerConnected(),
		IsHighID:          e.server.IsHighID(),
	}
	network.IsBehindCarrierNat = !network.IsHighID && matchCarrierNAT(e.mappedIP, e.publicIP)
	if e.kad != nil {
		network.IsKadFirewalled = e.kadStatus.IsFirewalled
		network.KadNodes = e.kadStatus.Nodes
	}
	if e.hasNetwork && network == e.network {
		return
	}
	e.hasNetwork = true
	e.network = network
	e.events.SetNetwork(network)
}

// isFirewalled is whether peers cannot connect to us: neither the server nor
// Kad says we are reachable.
func (e *Engine) isFirewalled() bool {
	return !e.server.IsHighID() && (e.kad == nil || e.kadStatus.IsFirewalled)
}

func (e *Engine) runNAT(mapPorts openNAT) {
	ctx, cancel := context.WithTimeout(e.ctx, natTimeout)
	unmap, ip, err := mapPorts(ctx, e.tcpPort, e.udpPort)
	cancel()
	if !e.send(e.ctx, natOpened{unmap, ip, err}) && err == nil {
		e.closeNAT(unmap)
	}
}

func (e *Engine) onNATOpened(m natOpened) {
	if m.err != nil {
		log.Printf("engine: upnp: %v", m.err)
		return
	}
	e.unmapNAT = m.unmap
	e.mappedIP = m.ip
	if isPublicIPv4(m.ip) && !e.publicIP.IsValid() && !e.server.IsHighID() {
		e.publicIP = m.ip
	}
}

// sharedAddressSpace is RFC 6598's range for carrier-grade NAT.
var sharedAddressSpace = netip.MustParsePrefix("100.64.0.0/10")

// matchCarrierNAT is the rule in docs/protocol.md "network": the gateway that
// mapped our ports has a non-public external address, or peers see us at
// another address, so another NAT sits above it. Without a mapping it cannot
// tell.
func matchCarrierNAT(mapped, public netip.Addr) bool {
	if !mapped.Is4() || mapped.IsUnspecified() {
		return false
	}
	return !isPublicIPv4(mapped) || public.IsValid() && public != mapped
}

func isPublicIPv4(addr netip.Addr) bool {
	return addr.Is4() && addr.IsGlobalUnicast() && !addr.IsPrivate() &&
		!sharedAddressSpace.Contains(addr) && addr.As4()[0] != 0 && addr.As4()[0] < 240
}

func (e *Engine) closeNAT(unmap func(context.Context) error) {
	ctx, cancel := context.WithTimeout(context.Background(), natTimeout)
	defer cancel()
	if err := unmap(ctx); err != nil {
		log.Printf("engine: upnp unmap: %v", err)
	}
}

// stop is the hub's last step: end every run, then save and close
// everything it owns.
func (e *Engine) stop() error {
	for _, r := range append([]*run(nil), e.runList...) {
		e.stopRun(r, nil)
	}
	if e.unmapNAT != nil {
		e.closeNAT(e.unmapNAT)
	}
	for _, c := range e.sortedConns() {
		e.closeConn(c, "engine closed")
	}
	e.closeSockets()
	if e.kad != nil {
		e.kadCancel()
		<-e.kadDone
	}
	close(e.saves)
	<-e.saverDone
	return store.Save(e.config.DataFolder, e.buildState())
}

// requestSave hands the newest state to the saver, replacing one it has not
// taken yet.
func (e *Engine) requestSave() {
	state := e.buildState()
	for {
		select {
		case e.saves <- state:
			return
		default:
		}
		select {
		case <-e.saves:
		default:
		}
	}
}

func (e *Engine) runSaver() {
	defer close(e.saverDone)
	for state := range e.saves {
		if err := store.Save(e.config.DataFolder, state); err != nil {
			log.Printf("engine: save state: %v", err)
		}
	}
}

func (e *Engine) buildState() store.State {
	state := store.State{
		Identity:  e.state.Identity,
		Kad:       e.state.Kad,
		Credits:   map[wire.Hash]store.Credit{},
		Transfers: maps.Clone(e.state.Transfers),
	}
	if e.kad != nil {
		state.Kad = e.kad.State()
	}
	for _, c := range e.ledger.ToCredits() {
		state.Credits[c.User] = store.Credit{Uploaded: c.Uploaded, Downloaded: c.Downloaded, PublicKey: c.PublicKey, LastSeen: c.LastSeen}
	}
	for _, r := range e.runList {
		if r.transfer != nil {
			state.Transfers[r.file.Hash] = r.transfer.ToState()
		}
	}
	state.Servers = toStoreServers(e.server.Entries())
	return state
}

func toReason(err error) string {
	switch {
	case err == nil:
		return "closed"
	case errors.Is(err, net.ErrClosed):
		return "closed"
	default:
		return fmt.Sprint(err)
	}
}
