package engine

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"maps"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/kad"
	"github.com/XiaoYouChR/Kelpie/internal/obfuscation"
	"github.com/XiaoYouChR/Kelpie/internal/peer"
	"github.com/XiaoYouChR/Kelpie/internal/piece"
	"github.com/XiaoYouChR/Kelpie/internal/transfer"
	"github.com/XiaoYouChR/Kelpie/internal/transport"
	"github.com/XiaoYouChR/Kelpie/internal/upload"
	"github.com/XiaoYouChR/Kelpie/internal/wire"
	"github.com/XiaoYouChR/Kelpie/internal/wire/client"
	serverwire "github.com/XiaoYouChR/Kelpie/internal/wire/server"
)

// opKadFirewallAck is OP_KAD_FWTCPCHECK_ACK, which a Kad node checking our
// TCP port sends over the connection it opened; wire/client leaves it
// undecoded.
const opKadFirewallAck byte = 0xA8

// conn is one TCP connection: to a peer, or to the server.
type conn struct {
	id           uint64
	ctx          context.Context
	cancel       context.CancelFunc
	net          net.Conn
	remote       netip.AddrPort
	isServer     bool
	isOutgoing   bool
	isObfuscated bool
	out          *leafQueue[outItem]
	session      *peer.Session
	// files are the downloads this connection serves, in the order they
	// were added; the first one is the started one.
	files []wire.Hash
	// uploadFile is the file the peer queued for with us, and uploadParts
	// what it said it has of it, for answering Source Exchange.
	uploadFile   wire.Hash
	uploadParts  piece.Set
	isHandshaken bool
	isUploading  bool
	isClosed     bool
}

// outItem is one packet for a writer. Payload counts upload data, for the
// queue, the transfer and the ledger once it is written.
type outItem struct {
	packet  wire.Packet
	file    wire.Hash
	payload int64
}

func (e *Engine) addConn(remote netip.AddrPort, isServer, isOutgoing bool) *conn {
	e.nextConn++
	ctx, cancel := context.WithCancel(e.ctx)
	c := &conn{
		id:         e.nextConn,
		ctx:        ctx,
		cancel:     cancel,
		remote:     netip.AddrPortFrom(remote.Addr().Unmap(), remote.Port()),
		isServer:   isServer,
		isOutgoing: isOutgoing,
		out:        buildLeafQueue[outItem](e.caps.writer),
	}
	e.conns[c.id] = c
	return c
}

// openConn dials remote from a leaf; the hub learns the result from
// connOpened. A non-zero obfuscateFor is the peer's user hash, and the
// connection is obfuscated with it. A server connection with a non-zero
// obfuscationPort is dialled on that port and obfuscated by key agreement.
func (e *Engine) openConn(remote netip.AddrPort, isServer bool, obfuscateFor wire.Hash, obfuscationPort uint16) *conn {
	c := e.addConn(remote, isServer, true)
	c.isObfuscated = obfuscateFor != wire.Hash{} || obfuscationPort != 0
	if !isServer {
		e.recentConnects = append(e.recentConnects, e.now())
	}
	keyPart := [4]byte(binary.LittleEndian.AppendUint32(nil, e.ports.Rand.Uint32()))
	var secret [16]byte
	binary.LittleEndian.PutUint64(secret[:8], e.ports.Rand.Uint64())
	binary.LittleEndian.PutUint64(secret[8:], e.ports.Rand.Uint64())
	dial := c.remote
	if obfuscationPort != 0 {
		dial = netip.AddrPortFrom(c.remote.Addr(), obfuscationPort)
	}
	if e.packetLog != nil {
		e.packetLog.Printf("open %s obfuscated=%t", dial, c.isObfuscated)
	}
	e.startLeaf(func() {
		ctx, cancel := context.WithTimeout(c.ctx, connectTimeout)
		netConn, err := e.ports.Transport.OpenTCP(ctx, dial)
		cancel()
		switch {
		case err != nil:
		case obfuscationPort != 0:
			netConn, err = openObfuscated(netConn, func(c net.Conn) (*obfuscation.Conn, error) {
				return obfuscation.OpenServer(c, secret, keyPart[0])
			})
		case obfuscateFor != wire.Hash{}:
			netConn, err = openObfuscated(netConn, func(c net.Conn) (*obfuscation.Conn, error) {
				return obfuscation.OpenOutgoing(c, obfuscateFor, keyPart)
			})
		}
		if !e.send(c.ctx, connOpened{c.id, netConn, err}) && netConn != nil {
			netConn.Close()
		}
	})
	return c
}

func openObfuscated(netConn net.Conn, open func(net.Conn) (*obfuscation.Conn, error)) (net.Conn, error) {
	netConn.SetDeadline(time.Now().Add(connectTimeout))
	obfuscated, err := open(netConn)
	if err != nil {
		netConn.Close()
		return nil, err
	}
	netConn.SetDeadline(time.Time{})
	return obfuscated, nil
}

// uploadTarget is how to reach a peer waiting in our upload queue once its
// slot comes.
type uploadTarget struct {
	endpoint     netip.AddrPort
	canObfuscate bool
}

// refreshUploadEndpoints forgets peers that are neither connected nor known
// to the upload queue: nothing will ask to reach them.
func (e *Engine) refreshUploadEndpoints() {
	connected := map[uploadKey]bool{}
	for _, c := range e.conns {
		if c.isHandshaken {
			connected[uploadKey{c.session.UserHash(), c.remote.Addr()}] = true
		}
	}
	maps.DeleteFunc(e.uploadEndpoints, func(k uploadKey, _ uploadTarget) bool {
		return !connected[k] && !e.queue.HasPeer(k.user, k.ip)
	})
}

func (e *Engine) runAcceptor() {
	self := e.self.UserHash
	for {
		netConn, err := e.listener.Accept()
		if err != nil {
			return
		}
		e.startLeaf(func() { e.runIncoming(netConn, self) })
	}
}

// runIncoming waits for an accepted connection's first bytes, which tell
// whether the peer obfuscates, before the hub sees the connection.
func (e *Engine) runIncoming(netConn net.Conn, self wire.Hash) {
	netConn.SetDeadline(time.Now().Add(connectTimeout))
	conn, err := obfuscation.OpenIncoming(netConn, self)
	if err != nil {
		netConn.Close()
		return
	}
	netConn.SetDeadline(time.Time{})
	if !e.send(e.ctx, connAccepted{conn}) {
		netConn.Close()
	}
}

func (e *Engine) onConnAccepted(netConn net.Conn) {
	addr, ok := netConn.RemoteAddr().(*net.TCPAddr)
	if !ok || len(e.conns) >= maxConnections {
		netConn.Close()
		return
	}
	c := e.addConn(addr.AddrPort(), false, false)
	c.net = netConn
	e.startConnLeaves(c)
	c.session = peer.BuildIncoming(e.buildPeerConfig(), c.remote, e.now())
}

func (e *Engine) onConnOpened(m connOpened) {
	c := e.conns[m.id]
	if c == nil {
		if m.conn != nil {
			m.conn.Close()
		}
		return
	}
	if m.err != nil {
		e.closeConn(c, toReason(m.err))
		return
	}
	c.net = m.conn
	e.startConnLeaves(c)
	if c.isServer {
		e.runServer(e.server.OnConnected(c.remote, e.now()))
		return
	}
	session, out := peer.BuildOutgoing(e.buildPeerConfig(), c.remote, e.now())
	c.session = session
	e.runSession(c, out)
	for _, h := range c.files {
		if r := e.runByHash[h]; r != nil {
			e.addSessionFile(c, r)
		}
	}
	e.startFirstFile(c)
}

func (e *Engine) startConnLeaves(c *conn) {
	parse := client.Parse
	limiterIn, limiterOut := e.downloadLimiter, e.uploadLimiter
	if c.isServer {
		parse = serverwire.Parse
		limiterIn, limiterOut = nil, nil
	}
	e.startLeaf(func() { e.runReader(c.ctx, c.id, c.remote, c.net, parse, limiterIn) })
	e.startLeaf(func() { e.runWriter(c.ctx, c.id, c.remote, c.net, c.out.items, limiterOut) })
}

func (e *Engine) buildPeerConfig() peer.Config {
	cfg := peer.Config{
		Self:     e.self,
		Version:  e.config.Version,
		ClientID: e.server.ClientID(),
		PublicIP: e.publicIP,
		Port:     uint16(e.tcpPort),
		UDPPort:  uint16(e.udpPort),
		Server:   e.serverAddr,
		Pipeline: pipeline,
		Random:   e.ports.Rand,
	}
	if e.kad != nil {
		cfg.KadPort = uint16(e.udpPort)
		cfg.KadVersion = kadVersion
	}
	return cfg
}

// countingReader counts the bytes of each frame for the rate limiter.
type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(b []byte) (int, error) {
	n, err := c.r.Read(b)
	c.n += n
	return n, err
}

// runReader is a connection's reader leaf: it decodes frames and posts
// them, blocking while the hub is busy so that TCP pushes back.
func (e *Engine) runReader(ctx context.Context, id uint64, remote netip.AddrPort, netConn net.Conn, parse func(protocol, opcode byte, body []byte) (wire.Packet, error), limiter *transport.Limiter) {
	r := &countingReader{r: bufio.NewReaderSize(netConn, 64<<10)}
	for {
		frame, err := wire.ParseFrameFrom(r)
		if err == nil && limiter != nil {
			err = limiter.WaitN(ctx, r.n)
		}
		r.n = 0
		var p wire.Packet
		if err == nil {
			p, err = parse(frame.Protocol, frame.Opcode, frame.Body)
		}
		if err != nil {
			e.send(ctx, connClosed{id, err})
			return
		}
		if e.packetLog != nil {
			e.packetLog.Printf("in  %s %s %d", remote, toPacketName(p), len(frame.Body))
		}
		if !e.send(ctx, packetReceived{id, p}) {
			return
		}
	}
}

// runWriter is a connection's writer leaf. It reports each written packet
// so the hub can count credit and uploaded bytes.
func (e *Engine) runWriter(ctx context.Context, id uint64, remote netip.AddrPort, netConn net.Conn, items <-chan outItem, limiter *transport.Limiter) {
	var buf []byte
	for {
		var item outItem
		var ok bool
		select {
		case item, ok = <-items:
		case <-ctx.Done():
			return
		}
		if !ok {
			return
		}
		buf = wire.BuildPacket(buf[:0], item.packet)
		if limiter != nil && limiter.WaitN(ctx, len(buf)) != nil {
			return
		}
		if _, err := netConn.Write(buf); err != nil {
			netConn.Close()
			return
		}
		if e.packetLog != nil {
			e.packetLog.Printf("out %s %s %d", remote, toPacketName(item.packet), len(buf)-wire.HeaderSize)
		}
		if !e.send(ctx, packetSent{id, item.file, item.payload}) {
			return
		}
	}
}

func (e *Engine) sendPacket(c *conn, p wire.Packet, file wire.Hash, payload int64) {
	if !c.isClosed {
		c.out.send(outItem{p, file, payload})
	}
}

func (e *Engine) onPacketSent(m packetSent) {
	c := e.conns[m.id]
	if c == nil {
		return
	}
	c.out.onDone()
	now := e.now()
	if c.session != nil {
		c.session.OnSent(now)
	}
	if m.payload == 0 {
		return
	}
	e.queue.OnSent(c.id, m.payload)
	if r := e.runByHash[m.file]; r != nil && r.transfer != nil {
		r.transfer.OnUploaded(m.payload, now)
	}
	if c.session != nil {
		e.ledger.OnTransferred(c.session.UserHash(), c.remote.Addr(), m.payload, 0)
	}
}

// closeConn closes c at once and tells everyone who used it. A closed
// server connection is reported to the server only when the server did not
// ask for the close itself.
func (e *Engine) closeConn(c *conn, reason string) {
	if c.isClosed {
		return
	}
	c.isClosed = true
	if e.packetLog != nil {
		e.packetLog.Printf("close %s obfuscated=%t %s", c.remote, c.isObfuscated, reason)
	}
	delete(e.conns, c.id)
	c.cancel()
	if c.net != nil {
		c.net.Close()
	}
	close(c.out.items)
	now := e.now()
	if c.isServer {
		if c.remote == e.serverAddr {
			e.serverAddr = netip.AddrPort{}
		}
		if c.net == nil {
			e.runServer(e.server.OnConnectFailed(c.remote, now))
		} else {
			e.runServer(e.server.OnDisconnected(c.remote, now))
		}
		return
	}
	e.queue.OnConnectionGone(c.id)
	if c.session != nil && c.isHandshaken {
		for _, event := range c.session.Stop().Events {
			e.onPeerEvent(c, event)
		}
	}
	for _, h := range c.files {
		r := e.runByHash[h]
		if r == nil || r.transfer == nil {
			continue
		}
		if c.isHandshaken {
			e.runTransferActions(r, r.transfer.OnPeerGone(c.id, reason, now))
		} else if c.isOutgoing {
			e.runTransferActions(r, r.transfer.OnConnectFailed(c.remote, reason, now))
		}
	}
	c.files = nil
}

func (e *Engine) sortedConns() []*conn {
	conns := make([]*conn, 0, len(e.conns))
	for _, id := range slices.Sorted(maps.Keys(e.conns)) {
		conns = append(conns, e.conns[id])
	}
	return conns
}

func (e *Engine) connByEndpoint(endpoint netip.AddrPort) *conn {
	for _, c := range e.sortedConns() {
		if c.isServer {
			continue
		}
		if c.isOutgoing && c.remote == endpoint || c.isHandshaken && c.endpoint() == endpoint {
			return c
		}
	}
	return nil
}

// endpoint is the peer's address with its listening port, as its hello said.
func (c *conn) endpoint() netip.AddrPort {
	return netip.AddrPortFrom(c.remote.Addr(), c.session.Capabilities().Port)
}

func (e *Engine) onPacket(id uint64, p wire.Packet) {
	c := e.conns[id]
	if c == nil {
		return
	}
	if c.isServer {
		e.runServer(e.server.OnPacket(c.remote, p, e.now()))
		return
	}
	if u, ok := p.(wire.Unknown); ok && u.Proto == wire.ProtocolEMule && u.Op == opKadFirewallAck {
		if e.kad != nil {
			e.kad.SendFirewallAck(c.remote.Addr())
		}
		return
	}
	e.runSession(c, c.session.OnPacket(p, e.shareByHash, e.now()))
}

// runSession performs a session's Output in its documented order.
func (e *Engine) runSession(c *conn, out peer.Output) {
	if c.isClosed {
		return
	}
	for _, p := range out.Send {
		e.sendPacket(c, p, wire.Hash{}, 0)
	}
	for _, event := range out.Events {
		if c.isClosed {
			return
		}
		e.onPeerEvent(c, event)
	}
	if out.Close != "" {
		e.closeConn(c, string(out.Close))
	}
}

func (e *Engine) onPeerEvent(c *conn, event peer.Event) {
	now := e.now()
	switch ev := event.(type) {
	case peer.HandshakeCompleted:
		e.ledger.OnHello(ev.UserHash, now)
		e.onHandshake(c, ev)
	case peer.Identified:
		e.onIdentified(c, ev)
	case peer.IdentityFailed:
		e.ledger.OnIdentityFailed(ev.UserHash)
	case peer.StatusReceived:
		if r := e.downloadByHash(ev.File); r != nil {
			r.transfer.OnPeerParts(c.id, ev.Parts)
		}
	case peer.HashSetReceived:
		if r := e.downloadByHash(ev.File); r != nil {
			e.runTransferActions(r, r.transfer.OnHashSet(c.id, ev.Hashes))
			e.refreshShare(r)
		}
	case peer.FileRejected:
		e.removeFile(c, ev.File, "no file")
	case peer.Queued:
		if r := e.downloadByHash(ev.File); r != nil {
			e.runTransferActions(r, r.transfer.OnQueued(c.id, int(ev.Rank), now))
		}
	case peer.SlotGranted:
		e.onSlotGranted(c, ev.File)
	case peer.SlotRevoked:
		if r := e.downloadByHash(ev.File); r != nil {
			e.runTransferActions(r, r.transfer.OnQueued(c.id, 0, now))
		}
	case peer.BlocksWanted:
		if r := e.downloadByHash(ev.File); r != nil {
			e.runSession(c, c.session.Request(ev.File, r.transfer.Request(c.id, ev.Count)))
		}
	case peer.BlockReceived:
		e.ledger.OnTransferred(c.session.UserHash(), c.remote.Addr(), 0, int64(len(ev.Data)))
		if r := e.downloadByHash(ev.File); r != nil {
			e.runTransferActions(r, r.transfer.OnBlockReceived(c.id, ev.Block, ev.Data, now))
		}
	case peer.UploadRequested:
		if r := e.downloadByHash(ev.File); r != nil && e.isReaskDue(r, c.session.UserHash()) {
			e.addFile(c, r)
		}
		c.uploadFile, c.uploadParts = ev.File, ev.Parts
		e.runQueueActions(e.queue.OnRequest(c.id, toUploadPeer(c), ev.File, now))
	case peer.BlocksRequested:
		e.onBlocksRequested(c, ev)
	case peer.UploadCancelled:
		c.isUploading = false
		c.uploadFile = wire.Hash{}
		e.queue.OnConnectionGone(c.id)
	case peer.SourcesRequested:
		e.runSession(c, c.session.SendSources(ev.File, e.buildPeerSources(ev.File, c, ev.Parts)))
	case peer.SourcesFound:
		if r := e.downloadByHash(ev.File); r != nil {
			e.addSources(r, toExchangeSources(ev.Sources), transfer.ChannelExchange)
		}
	}
}

func (e *Engine) onHandshake(c *conn, ev peer.HandshakeCompleted) {
	c.isHandshaken = true
	caps := c.session.Capabilities()
	if ev.YourIP.Is4() && !e.server.IsHighID() {
		e.publicIP = ev.YourIP
	}
	if caps.Port != 0 {
		e.uploadEndpoints[uploadKey{ev.UserHash, c.remote.Addr()}] = uploadTarget{c.endpoint(), caps.CryptOptions&peer.CryptSupported != 0}
	}
	for _, h := range slices.Clone(c.files) {
		if r := e.downloadByHash(h); r != nil && !c.isClosed {
			e.addTransferPeer(c, r)
		}
	}
	if !c.isOutgoing {
		for _, h := range e.matchKnownSource(ev.UserHash, caps) {
			if r := e.runByHash[h]; !c.isClosed && e.isReaskDue(r, ev.UserHash) {
				e.addFile(c, r)
			}
		}
	}
	e.startFirstFile(c)
	if !c.isClosed {
		e.runQueueActions(e.queue.OnConnected(c.id, toUploadPeer(c), e.now()))
	}
}

// isReaskDue tells whether a connection the peer opened may carry our file
// request for r. aMule sends it on an incoming connection only when it was
// about to ask that source anyway (BaseClient.cpp:1688-1702); asking again
// within MIN_REQUESTTIME gets us banned as aggressive
// (ClientTCPSocket.cpp:539).
func (e *Engine) isReaskDue(r *run, user wire.Hash) bool {
	asked, ok := r.asked[user]
	return !ok || e.now().Sub(asked) >= fileReaskTime
}

// addTransferPeer tells a download that a handshaken connection serves it.
func (e *Engine) addTransferPeer(c *conn, r *run) {
	user := c.session.UserHash()
	r.asked[user] = e.now()
	e.addKnownSource(r.file.Hash, transfer.Source{UserHash: user})
	caps := c.session.Capabilities()
	hello := transfer.Hello{
		Endpoint:    c.endpoint(),
		ClientID:    caps.ClientID,
		Server:      caps.Server,
		UserHash:    user,
		UDPPort:     caps.UDPPort,
		CanReaskUDP: caps.UDPVersion > 0 && caps.UDPPort != 0,
		CanExchange: caps.HasSourceExchange2,
	}
	e.runTransferActions(r, r.transfer.OnPeerConnected(c.id, hello, e.now()))
}

// addFile makes c serve download r: right away on a handshaken
// connection, or once the handshake completes.
func (e *Engine) addFile(c *conn, r *run) {
	h := r.file.Hash
	if slices.Contains(c.files, h) {
		return
	}
	c.files = append(c.files, h)
	if c.session == nil {
		return
	}
	e.addSessionFile(c, r)
	if c.isHandshaken && !c.isClosed {
		e.addTransferPeer(c, r)
	}
	e.startFirstFile(c)
}

func (e *Engine) addSessionFile(c *conn, r *run) {
	e.runSession(c, c.session.Add(r.file.Hash, r.file.Size, r.share.Parts))
}

// removeFile stops c serving download h and tells the transfer.
func (e *Engine) removeFile(c *conn, h wire.Hash, reason string) {
	i := slices.Index(c.files, h)
	if i < 0 {
		return
	}
	c.files = slices.Delete(c.files, i, i+1)
	if c.session != nil {
		e.runSession(c, c.session.Remove(h))
		e.startFirstFile(c)
	}
	if r := e.downloadByHash(h); r != nil && c.isHandshaken {
		e.runTransferActions(r, r.transfer.OnPeerGone(c.id, reason, e.now()))
	}
}

// startFirstFile asks for a slot for the oldest download on c; eD2k grants
// slots per client, so one file is asked for at a time.
func (e *Engine) startFirstFile(c *conn) {
	if len(c.files) > 0 && c.session != nil && !c.isClosed {
		e.runSession(c, c.session.Start(c.files[0]))
	}
}

// onSlotGranted handles a grant that may arrive before the peer said which
// file it is for: then it is for a download that knows this peer.
func (e *Engine) onSlotGranted(c *conn, file wire.Hash) {
	if file == (wire.Hash{}) {
		for _, h := range e.matchKnownSource(c.session.UserHash(), c.session.Capabilities()) {
			e.addFile(c, e.runByHash[h])
		}
		if len(c.files) == 0 || c.isClosed {
			return
		}
		file = c.files[0]
	}
	if r := e.downloadByHash(file); r != nil {
		e.runTransferActions(r, r.transfer.OnSlotGranted(c.id, e.now()))
	}
}

func (e *Engine) onIdentified(c *conn, ev peer.Identified) {
	stored := e.ledger.PublicKeyByUser(ev.UserHash)
	if stored != nil && !bytes.Equal(stored, ev.PublicKey) {
		e.ledger.OnIdentityFailed(ev.UserHash)
		return
	}
	if stored == nil {
		e.ledger.OnKeyReceived(ev.UserHash, ev.PublicKey)
	}
	e.ledger.OnIdentified(ev.UserHash, c.remote.Addr())
}

func (e *Engine) onBlocksRequested(c *conn, ev peer.BlocksRequested) {
	r := e.runByHash[ev.File]
	if r == nil || r.transfer == nil {
		return
	}
	for _, block := range ev.Blocks {
		if r.share.Parts.Count() == 0 || !r.share.Parts[block.Part()] || !r.share.Parts[piece.Block{Begin: block.End - 1}.Part()] {
			continue
		}
		e.sendDiskJob(diskJob{kind: jobRead, run: r.id, file: r.handle, block: block, conn: c.id, hash: ev.File})
	}
}

func (e *Engine) onBlockRead(c *conn, file wire.Hash, block piece.Block, data []byte) {
	out := c.session.SendBlock(file, block, data)
	for _, p := range out.Send {
		e.sendPacket(c, p, file, toPayload(p))
	}
}

func toPayload(p wire.Packet) int64 {
	switch p := p.(type) {
	case client.SendingPart:
		return int64(len(p.Data))
	case client.SendingPart64:
		return int64(len(p.Data))
	case client.CompressedPart:
		return int64(len(p.Data))
	case client.CompressedPart64:
		return int64(len(p.Data))
	}
	return 0
}

func toUploadPeer(c *conn) upload.Peer {
	caps := c.session.Capabilities()
	return upload.Peer{
		User:        c.session.UserHash(),
		IP:          c.remote.Addr(),
		UDPPort:     caps.UDPPort,
		IsLowID:     wire.IsLowID(caps.ClientID),
		MuleVersion: caps.MuleVersion,
	}
}

func (e *Engine) runQueueActions(actions []upload.Action) {
	for _, action := range actions {
		switch a := action.(type) {
		case upload.Grant:
			if c := e.conns[a.Conn]; c != nil && c.session != nil {
				c.isUploading = true
				e.runSession(c, c.session.StartUpload())
			}
		case upload.Revoke:
			if c := e.conns[a.Conn]; c != nil && c.session != nil {
				c.isUploading = false
				e.runSession(c, c.session.StopUpload())
			}
		case upload.SendRank:
			if c := e.conns[a.Conn]; c != nil && c.session != nil {
				e.runSession(c, c.session.SendQueueRank(uint32(a.Rank)))
			}
		case upload.Connect:
			target, ok := e.uploadEndpoints[uploadKey{a.Peer.User, a.Peer.IP}]
			if ok && e.connByEndpoint(target.endpoint) == nil && len(e.conns) < maxConnections {
				var obfuscateFor wire.Hash
				if target.canObfuscate {
					obfuscateFor = a.Peer.User
				}
				e.openConn(target.endpoint, false, obfuscateFor, 0)
			}
		}
	}
}

// buildPeerSources answers Source Exchange, other than with the peer asking.
// For a download these are its connected sources; a seed, like aMule's
// CKnownFile::CreateSrcInfoPacket (KnownFile.cpp:1038-1110), names the HighID
// peers queued or downloading the file from us that have a part the asker
// lacks.
func (e *Engine) buildPeerSources(file wire.Hash, asking *conn, askerParts piece.Set) []peer.Source {
	r := e.runByHash[file]
	isSeed := r != nil && r.mode == ModeSeed
	var sources []peer.Source
	for _, c := range e.sortedConns() {
		if c == asking || !c.isHandshaken {
			continue
		}
		caps := c.session.Capabilities()
		isLowID := caps.ClientID != 0 && wire.IsLowID(caps.ClientID)
		if isSeed && (c.uploadFile != file || isLowID || !matchNeededSource(c.uploadParts, askerParts)) ||
			!isSeed && !slices.Contains(c.files, file) {
			continue
		}
		src := peer.Source{Port: caps.Port, UserHash: c.session.UserHash(), IPv6: caps.IPv6, CryptOptions: caps.CryptOptions}
		switch {
		case !wire.IsLowID(caps.ClientID) && c.remote.Addr().Is4():
			src.IPv4 = c.remote.Addr()
		case caps.ClientID != 0 && caps.Server.IsValid():
			src.LowID, src.Server = caps.ClientID, caps.Server
		case c.remote.Addr().Is4():
			src.IPv4 = c.remote.Addr()
		}
		sources = append(sources, src)
	}
	return sources
}

// matchNeededSource follows aMule: a source whose parts are unknown is sent
// on hope, one whose parts are known must have a part the asker lacks, or any
// part when the asker did not tell its own.
func matchNeededSource(source, asker piece.Set) bool {
	if source == nil {
		return true
	}
	for i, has := range source {
		if has && (i >= len(asker) || !asker[i]) {
			return true
		}
	}
	return false
}

func toExchangeSources(found []peer.Source) []transfer.Source {
	var sources []transfer.Source
	for _, f := range found {
		src := transfer.Source{UserHash: f.UserHash, CanObfuscate: f.CanObfuscate()}
		switch {
		case f.LowID != 0:
			src.ClientID, src.Server = f.LowID, f.Server
		case f.IPv4.IsValid():
			src.Endpoint = netip.AddrPortFrom(f.IPv4, f.Port)
		case f.IPv6.IsValid():
			src.Endpoint = netip.AddrPortFrom(f.IPv6, f.Port)
		}
		sources = append(sources, src)
	}
	return sources
}

func toKadSources(found []kad.Source) []transfer.Source {
	var sources []transfer.Source
	for _, f := range found {
		src := transfer.Source{UserHash: f.UserHash, UDPPort: f.UDPPort, CanObfuscate: f.CanObfuscate()}
		if f.IsFirewalled() {
			src.Buddy, src.BuddyID = f.Buddy, f.BuddyID
		} else {
			src.Endpoint = f.Addr
		}
		sources = append(sources, src)
	}
	return sources
}

// toPacketName is the packet's Go type, which names its opcode, with the
// protocol and opcode bytes for packets no family decodes.
func toPacketName(p wire.Packet) string {
	if u, ok := p.(wire.Unknown); ok {
		return fmt.Sprintf("unknown(%#02x,%#02x)", u.Proto, u.Op)
	}
	return fmt.Sprintf("%T", p)
}
