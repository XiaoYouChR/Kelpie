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
	"io"
	"log"
	"maps"
	"math"
	"math/rand/v2"
	"net"
	"net/netip"
	"runtime"
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

// seams are the engine's only ways out: sockets, files, time and randomness.
type seams struct {
	Transport transport.Transport
	Disk      disk.Disk
	Clock     clock.Clock
	Rand      *rand.Rand
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
	diskWorkers         = 4
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
	ports  seams
	events Events
	caps   capacities

	inbox  chan any
	ctx    context.Context
	cancel context.CancelFunc
	// leaves counts the leaf goroutines, so Close returns once all are gone.
	leaves sync.WaitGroup

	// closeOnce makes a second Close return the first one's result: once the
	// hub has stopped, its buffered inbox would still take a closeRequested
	// that nobody answers. The hub stops only on a closeRequested, since a
	// panic exits the Engine Process (ADR-0005).
	closeOnce sync.Once
	closeErr  error

	// lastStats is when logStats last wrote to packetLog.
	lastStats time.Time
	// packetLog is nil unless Config.PacketLog is set; leaves write to it.
	packetLog *log.Logger

	// The limiters are shared memory, safe from any goroutine (ADR-0005).
	downloadLimiter *rateLimiter
	uploadLimiter   *rateLimiter

	// Everything below is owned by the hub goroutine.
	state  store.State
	self   identity.Self
	ledger *identity.Ledger
	queue  *upload.Queue
	server *server.Server
	kad    *kad.Kad
	// stopKad cancels Kad and returns its last state; false if Run failed.
	stopKad   func() (kad.State, bool)
	kadStatus kad.Status
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

	publicIP netip.Addr
	mappedIP netip.Addr
	// network is the Network last reported.
	network Network

	nextConn uint64
	conns    map[uint64]*conn
	// runs are the open runs in the order they started; runByHash indexes
	// them.
	runs            []*run
	runByHash       map[wire.Hash]*run
	uploadEndpoints map[uploadKey]uploadTarget
	a4afClients     map[wire.Hash]*a4afClient
	recentConnects  []time.Time
	budgetCursor    int
	lastSecond      time.Time
	lastSave        time.Time
}

type uploadKey struct {
	user wire.Hash
	ip   netip.Addr
}

// Start runs an Engine on the real network, disk and clock.
func Start(config Config, events Events) (*Engine, error) {
	var seed [32]byte
	crand.Read(seed[:])
	ports := seams{
		Transport: transport.Real{},
		Disk:      disk.Real{},
		Clock:     clock.Real{},
		Rand:      rand.New(rand.NewChaCha8(seed)),
	}
	var mapPorts openNAT
	if config.EnableUPnP {
		mapPorts = func(ctx context.Context, tcpPort, udpPort int) (func(context.Context) error, netip.Addr, error) {
			return nat.Open(ctx, tcpPort, udpPort, "Kelpie")
		}
	}
	return build(config, ports, events, defaultCapacities, mapPorts)
}

func build(config Config, ports seams, events Events, caps capacities, mapPorts openNAT) (*Engine, error) {
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
		downloadLimiter: buildRateLimiter(ports.Clock, config.RateLimits.Download),
		uploadLimiter:   buildRateLimiter(ports.Clock, config.RateLimits.Upload),
		state:           state,
		self:            self,
		ledger:          identity.BuildLedger(toCredits(state.Credits), ports.Clock.Now()),
		saves:           make(chan store.State, 1),
		saverDone:       make(chan struct{}),
		disk:            buildLeafQueue[diskJob](caps.disk),
		conns:           map[uint64]*conn{},
		runByHash:       map[wire.Hash]*run{},
		uploadEndpoints: map[uploadKey]uploadTarget{},
		a4afClients:     map[wire.Hash]*a4afClient{},
		buddy:           buddy{incoming: map[netip.Addr]incomingBuddy{}},
		directCallbacks: map[netip.Addr]time.Time{},
	}
	if config.PacketLog != nil {
		e.packetLog = log.New(config.PacketLog, "packet ", log.Lmicroseconds)
		e.ports.Transport = udpLogTransport{Transport: ports.Transport, log: e.packetLog, clock: ports.Clock}
	}
	e.queue = upload.BuildQueue(e.ledger.Ratio, e.ledger.TrustByUser, func(file wire.Hash) bool {
		r := e.runByHash[file]
		return r != nil && r.transfer != nil
	})
	e.queue.SetRate(config.RateLimits.Upload)
	if err := e.start(mapPorts); err != nil {
		cancel()
		return nil, toStartFailed(err)
	}
	return e, nil
}

// start opens the sockets and the trace file, then starts the leaves, Kad
// and the hub.
func (e *Engine) start(mapPorts openNAT) error {
	if err := e.openSockets(); err != nil {
		return err
	}
	if e.config.TraceFile != "" {
		file, end, err := openTrace(e.ports.Disk, e.config.TraceFile)
		if err != nil {
			e.closeSockets()
			return err
		}
		e.trace = buildLeafQueue[traceLine](e.caps.trace)
		e.startLeaf(func() { e.runTraceWriter(file, end, e.trace.items) })
	}
	e.server = server.BuildServer(server.Config{
		UserHash: e.self.UserHash,
		Port:     uint16(e.tcpPort),
		Version:  e.config.Version,
		Random:   e.ports.Rand,
	}, updateLearned(loadLists(e.ports.Disk, e.config.ServerLists, server.ParseMet), e.state.Servers))
	if e.config.EnableKad {
		e.startKad(loadLists(e.ports.Disk, e.config.NodeLists, kad.ParseNodes))
	}

	now := e.now()
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
	e.network = e.buildNetwork()
	e.events.SetNetwork(e.network)
	go e.run()
	return nil
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

// loadLists merges every server or node list; a list that cannot be read is
// skipped, since the others still find servers and nodes.
func loadLists[T any](d disk.Disk, paths []string, parse func([]byte) ([]T, error)) []T {
	var entries []T
	for _, path := range paths {
		data, err := loadFile(d, path)
		if err == nil {
			var list []T
			list, err = parse(data)
			entries = append(entries, list...)
		}
		if err != nil {
			log.Printf("engine: skip list %s: %v", path, err)
		}
	}
	return entries
}

func loadFile(d disk.Disk, path string) ([]byte, error) {
	file, err := d.Open(path, disk.Read)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(io.NewSectionReader(file, 0, math.MaxInt64))
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
	ctx, cancel := context.WithCancel(e.ctx)
	done := make(chan kad.State, 1)
	go func() {
		defer close(done)
		state, err := e.kad.Run(ctx)
		if err != nil {
			log.Printf("engine: kad: %v", err)
			return
		}
		done <- state
	}()
	e.stopKad = func() (kad.State, bool) {
		cancel()
		state, ok := <-done
		return state, ok
	}
}

func (e *Engine) startLeaf(f func()) {
	e.leaves.Add(1)
	go func() {
		defer e.leaves.Done()
		f()
	}()
}

// send is how a leaf hands the hub a message. It may block: that is the
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
		e.inbox <- closeRequested{reply}
		e.closeErr = <-reply
		e.cancel()
		e.leaves.Wait()
	})
	return e.closeErr
}

// Messages from leaves to the hub.
type (
	commandPosted  struct{ command Command }
	closeRequested struct{ reply chan<- error }
	connAccepted   struct {
		conn   net.Conn
		remote netip.AddrPort
	}
	connOpened struct {
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
	ticker := e.ports.Clock.CreateTicker(tickInterval)
	defer ticker.Stop()
	var kadEvents <-chan kad.Event
	if e.kad != nil {
		kadEvents = e.kad.Events()
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
		case m := <-kadEvents:
			e.onKadMessage(m)
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
		e.onConnAccepted(m)
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
	if e.packetLog != nil && now.Sub(e.lastStats) >= time.Minute {
		e.lastStats = now
		e.logStats()
	}
	for _, c := range e.sortedConns() {
		if c.session != nil && !c.isClosed {
			e.runSession(c, c.session.OnTick(now))
		}
	}
	e.runTransfers(now)
	e.refreshUploadEndpoints()
	e.refreshAsked()
	e.refreshA4AF()
	serverWanted, kadWanted := e.buildWanted()
	e.runServer(e.server.OnTick(now, serverWanted, e.publicIP))
	e.runBuddy(now)
	if e.kad != nil {
		e.kad.Post(kadWanted)
	}
	for _, r := range e.runs {
		e.refreshProgress(r, false)
	}
	if now.Sub(e.lastSave) >= saveInterval {
		e.lastSave = now
		e.ledger.RemoveIdle(now)
		e.requestSave()
	}
}

// refreshNetwork reports a changed Network.
func (e *Engine) refreshNetwork() {
	if network := e.buildNetwork(); network != e.network {
		e.network = network
		e.events.SetNetwork(network)
	}
}

// buildNetwork is the Network now; without Kad, kadStatus stays zero.
func (e *Engine) buildNetwork() Network {
	_, clientID := e.server.Login()
	network := Network{
		IsServerConnected: clientID != 0,
		IsHighID:          !wire.IsLowID(clientID),
		IsKadFirewalled:   e.kadStatus.IsFirewalled,
		KadNodes:          e.kadStatus.Nodes,
	}
	network.IsBehindCarrierNat = !network.IsHighID && matchCarrierNAT(e.mappedIP, e.publicIP)
	return network
}

// isFirewalled is whether peers cannot connect to us: neither the server nor
// Kad says we are reachable.
func (e *Engine) isFirewalled() bool {
	_, clientID := e.server.Login()
	return wire.IsLowID(clientID) && (e.kad == nil || e.kadStatus.IsFirewalled)
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
	if _, clientID := e.server.Login(); isPublicIPv4(m.ip) && !e.publicIP.IsValid() && wire.IsLowID(clientID) {
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
	return addr.Is4() && wire.IsPublic(addr) && !sharedAddressSpace.Contains(addr)
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
	for _, r := range append([]*run(nil), e.runs...) {
		e.stopRun(r, nil)
	}
	if unmap := e.unmapNAT; unmap != nil {
		e.startLeaf(func() { e.closeNAT(unmap) })
	}
	for _, c := range e.sortedConns() {
		e.closeConn(c, "engine closed")
	}
	e.closeSockets()
	if e.kad != nil {
		if s, ok := e.stopKad(); ok {
			e.state.Kad = store.Kad(s)
		}
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
	for _, c := range e.ledger.ToCredits() {
		state.Credits[c.User] = store.Credit{Uploaded: c.Uploaded, Downloaded: c.Downloaded, PublicKey: c.PublicKey, LastSeen: c.LastSeen}
	}
	for _, r := range e.runs {
		if r.transfer != nil {
			state.Transfers[r.file.Hash] = store.Transfer(r.transfer.ToState())
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

// logStats writes the process's goroutine and heap counts, so a long run
// shows whether either grows.
func (e *Engine) logStats() {
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	e.packetLog.Printf("stats goroutines=%d heap=%d conns=%d runs=%d",
		runtime.NumGoroutine(), memory.HeapAlloc, len(e.conns), len(e.runs))
}
