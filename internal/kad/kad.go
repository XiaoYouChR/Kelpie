// Package kad is the Kad actor (ADR-0005): it owns the routing table, the
// UDP socket and Kad's timers, finds sources for the files the engine wants
// and publishes us as a source. Kad is IPv4 only.
//
// eMule serves Kad and eD2k UDP (reasks, server UDP) on one port, so Kad
// owns that socket for both. Datagrams whose first byte is not a Kad
// protocol byte (0xE4, 0xE5) go to the engine through Received; the engine
// sends its own datagrams through Send. Kad datagrams may be obfuscated
// (obfuscation.ParseKadDatagram); a datagram Kad cannot read either way,
// such as an obfuscated eD2k one, is forwarded unchanged. Servers start
// obfuscated datagrams with any byte but 0xE3 (aMule
// EncryptedDatagramSocket.cpp:451), so about 1 in 128 of them looks like
// Kad and is lost here; aMule keeps server UDP on a socket of its own.
//
// Every method other than Run is safe to call from another goroutine and
// never blocks: inputs and outputs drop when full, as a hub's sends to the
// other hub must (ADR-0005). SetWanted, SetBuddy and Statuses hold only
// the latest value.
package kad

import (
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"math/rand/v2"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/clock"
	"github.com/XiaoYouChR/Kelpie/internal/obfuscation"
	"github.com/XiaoYouChR/Kelpie/internal/store"
	"github.com/XiaoYouChR/Kelpie/internal/transport"
	"github.com/XiaoYouChR/Kelpie/internal/wire"
	kadwire "github.com/XiaoYouChR/Kelpie/internal/wire/kad"
)

const (
	tickInterval = time.Second // SEARCH_JUMPSTART
	queueSize    = 64
	maxDatagram  = 65536
)

type Config struct {
	Transport transport.Transport
	Clock     clock.Clock
	// Port is the UDP port shared by Kad and eD2k UDP; 0 picks one.
	Port     int
	TCPPort  uint16
	UserHash wire.Hash
	// State is the persisted Kad state; a zero ID makes a new one.
	State store.Kad
	// Nodes are bootstrap contacts, as ParseNodes reads them.
	Nodes []Node
	// Rand drives random lookup targets; nil seeds one from crypto/rand.
	Rand *rand.Rand
}

// Datagram is a non-Kad UDP datagram: received from Addr, or to send to
// Addr.
type Datagram struct {
	Addr netip.AddrPort
	Data []byte
}

type Kad struct {
	cfg       Config
	wanted    chan Wanted
	buddies   chan Buddy
	sends     chan Datagram
	callbacks chan Callback
	acks      chan netip.Addr
	inbox     chan any
	found     chan SourcesFound
	requests  chan Request
	received  chan Datagram
	statuses  chan Status
	state     atomic.Pointer[store.Kad]
}

func BuildKad(cfg Config) *Kad {
	if cfg.State.ID == (wire.Hash{}) {
		crand.Read(cfg.State.ID[:])
	}
	for cfg.State.UDPKey == 0 {
		var key [4]byte
		crand.Read(key[:])
		cfg.State.UDPKey = binary.LittleEndian.Uint32(key[:])
	}
	if cfg.Rand == nil {
		var seed [32]byte
		crand.Read(seed[:])
		cfg.Rand = rand.New(rand.NewChaCha8(seed))
	}
	k := &Kad{
		cfg:       cfg,
		wanted:    make(chan Wanted, 1),
		buddies:   make(chan Buddy, 1),
		sends:     make(chan Datagram, queueSize),
		callbacks: make(chan Callback, queueSize),
		acks:      make(chan netip.Addr, queueSize),
		inbox:     make(chan any, queueSize),
		found:     make(chan SourcesFound, queueSize),
		requests:  make(chan Request, queueSize),
		received:  make(chan Datagram, queueSize),
		statuses:  make(chan Status, 1),
	}
	state := store.Kad{ID: cfg.State.ID, IsFirewalled: true, UDPKey: cfg.State.UDPKey, Nodes: cfg.State.Nodes}
	k.state.Store(&state)
	return k
}

// SetWanted replaces the set of files to search and publish.
func (k *Kad) SetWanted(w Wanted) {
	for {
		select {
		case k.wanted <- w:
			return
		default:
		}
		select {
		case <-k.wanted:
		default:
		}
	}
}

// SetBuddy replaces what Kad knows of the engine's buddy link.
func (k *Kad) SetBuddy(b Buddy) {
	for {
		select {
		case k.buddies <- b:
			return
		default:
		}
		select {
		case <-k.buddies:
		default:
		}
	}
}

// Send queues an engine datagram for the shared UDP socket.
func (k *Kad) Send(d Datagram) {
	select {
	case k.sends <- d:
	default:
	}
}

// RequestCallback asks a firewalled source's buddy to have the source
// connect to our TCP port.
func (k *Kad) RequestCallback(cb Callback) {
	select {
	case k.callbacks <- cb:
	default:
	}
}

// SendFirewallAck reports an OP_KAD_FWTCPCHECK_ACK the engine received over
// TCP from from.
func (k *Kad) SendFirewallAck(from netip.Addr) {
	select {
	case k.acks <- from.Unmap():
	default:
	}
}

// RequestFirewallAck asks Kad to tell a node older than Kad version 7,
// at its Kad endpoint to, that we reached its TCP port.
func (k *Kad) RequestFirewallAck(to netip.AddrPort) { k.post(firewallAck{to}) }

// RequestFirewallUDP asks Kad to answer a client's OP_FWCHECKUDPREQ.
func (k *Kad) RequestFirewallUDP(r FirewallUDP) { k.post(r) }

func (k *Kad) SendUDPCheckEnded(e UDPCheckEnded) { k.post(e) }

func (k *Kad) post(m any) {
	select {
	case k.inbox <- m:
	default:
	}
}

func (k *Kad) Found() <-chan SourcesFound { return k.found }

func (k *Kad) Requests() <-chan Request { return k.requests }

func (k *Kad) Received() <-chan Datagram { return k.received }

func (k *Kad) Statuses() <-chan Status { return k.statuses }

// State is the Kad part of the Durable State as of the last tick.
func (k *Kad) State() store.Kad { return *k.state.Load() }

// Run serves Kad until ctx ends. It fails only if the UDP socket cannot be
// opened.
func (k *Kad) Run(ctx context.Context) error {
	conn, err := k.cfg.Transport.OpenUDP(k.cfg.Port)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	reads := make(chan Datagram)
	var reader sync.WaitGroup
	reader.Add(1)
	go func() {
		defer reader.Done()
		runReader(ctx, conn, reads)
	}()
	defer func() {
		cancel()
		conn.Close()
		reader.Wait()
	}()

	now := k.cfg.Clock.Now()
	c := buildCore(coreConfig{
		ID: k.cfg.State.ID, UserHash: k.cfg.UserHash, TCPPort: k.cfg.TCPPort,
		UDPPort: uint16(conn.Port()), UDPKey: k.cfg.State.UDPKey, Rand: k.cfg.Rand,
	}, now)
	for _, n := range k.cfg.State.Nodes {
		c.addNodes([]Node{toNode(n)}, now)
	}
	c.addNodes(k.cfg.Nodes, now)
	ticker := k.cfg.Clock.CreateTicker(tickInterval)
	defer ticker.Stop()

	var lastStatus Status
	k.setStatus(c.status())
	for {
		var out output
		isTick := false
		select {
		case <-ctx.Done():
			k.saveState(c)
			return nil
		case d := <-reads:
			if p, keys, isKad := c.parseDatagram(d); isKad {
				if p != nil {
					out = c.onPacket(d.Addr, p, keys, k.cfg.Clock.Now())
				}
			} else {
				select {
				case k.received <- d:
				default:
				}
			}
		case <-ticker.C():
			out = c.onTick(k.cfg.Clock.Now())
			isTick = true
		case w := <-k.wanted:
			c.setWanted(w, k.cfg.Clock.Now())
		case b := <-k.buddies:
			c.setBuddy(b)
		case d := <-k.sends:
			conn.WriteTo(d.Data, d.Addr)
		case cb := <-k.callbacks:
			out = c.requestCallback(cb)
		case from := <-k.acks:
			c.onFirewallAck(from)
		case m := <-k.inbox:
			out = c.onMessage(m)
		}
		for _, d := range out.datagrams {
			conn.WriteTo(c.buildDatagram(d), d.to)
		}
		for _, f := range out.found {
			select {
			case k.found <- f:
			default:
			}
		}
		for _, r := range out.requests {
			select {
			case k.requests <- r:
			default:
			}
		}
		if status := c.status(); status != lastStatus {
			lastStatus = status
			k.setStatus(status)
		}
		if isTick {
			k.saveState(c)
		}
	}
}

func runReader(ctx context.Context, conn transport.PacketConn, reads chan<- Datagram) {
	buf := make([]byte, maxDatagram)
	for {
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		select {
		case reads <- Datagram{Addr: from, Data: append([]byte(nil), buf[:n]...)}:
		case <-ctx.Done():
			return
		}
	}
}

func (k *Kad) setStatus(s Status) {
	select {
	case <-k.statuses:
	default:
	}
	k.statuses <- s
}

func (k *Kad) saveState(c *core) {
	state := store.Kad{ID: c.id, IsFirewalled: c.firewall.isFirewalled(), UDPKey: c.udpKey}
	for _, n := range c.table.nodes() {
		state.Nodes = append(state.Nodes, toStoreNode(n))
	}
	k.state.Store(&state)
}

// buildDatagram is a datagram's wire form, obfuscated as d asks.
func (c *core) buildDatagram(d datagram) []byte {
	data := wire.BuildPacketDatagram(nil, d.packet)
	if d.nodeID == (wire.Hash{}) && d.receiverKey == 0 {
		return data
	}
	var nodeID []byte
	if d.nodeID != (wire.Hash{}) {
		nodeID = buildID(nil, d.nodeID)
	}
	return obfuscation.BuildKadDatagram(obfuscation.KadDatagram{Packet: data, ReceiverKey: d.receiverKey, SenderKey: d.senderKey}, nodeID, c.rng.Uint32())
}

// parseDatagram reads a plain or obfuscated Kad datagram. isKad is false
// for datagrams that belong to the engine; p is nil for a Kad datagram that
// does not decode.
func (c *core) parseDatagram(d Datagram) (p wire.Packet, k keys, isKad bool) {
	data := d.Data
	if len(data) == 0 {
		return nil, keys{}, false
	}
	if data[0] != wire.ProtocolKad && data[0] != wire.ProtocolKadPacked {
		kd, ok := obfuscation.ParseKadDatagram(data, buildID(nil, c.id), obfuscation.BuildKadVerifyKey(c.udpKey, d.Addr.Addr()))
		if !ok || (kd.Packet[0] != wire.ProtocolKad && kd.Packet[0] != wire.ProtocolKadPacked) {
			return nil, keys{}, false
		}
		data, k = kd.Packet, keys{sender: kd.SenderKey, receiver: kd.ReceiverKey}
	}
	p, ok := parsePacket(data)
	if !ok {
		return nil, keys{}, true
	}
	return p, k, true
}

// parsePacket decodes a Kad datagram, inflating 0xE5 packets.
func parsePacket(data []byte) (wire.Packet, bool) {
	frame, err := wire.ParseDatagram(data)
	if err != nil {
		return nil, false
	}
	p, err := kadwire.Parse(frame.Protocol, frame.Opcode, frame.Body)
	return p, err == nil
}
