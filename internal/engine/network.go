package engine

import (
	"context"
	"log"
	"net/netip"
	"slices"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/kad"
	"github.com/XiaoYouChR/Kelpie/internal/obfuscation"
	"github.com/XiaoYouChR/Kelpie/internal/peer"
	"github.com/XiaoYouChR/Kelpie/internal/server"
	"github.com/XiaoYouChR/Kelpie/internal/store"
	"github.com/XiaoYouChR/Kelpie/internal/transfer"
	"github.com/XiaoYouChR/Kelpie/internal/upload"
	"github.com/XiaoYouChR/Kelpie/internal/wire"
	"github.com/XiaoYouChR/Kelpie/internal/wire/client"
	kadwire "github.com/XiaoYouChR/Kelpie/internal/wire/kad"
	serverwire "github.com/XiaoYouChR/Kelpie/internal/wire/server"
)

const (
	kadVersion    = kadwire.Version
	maxDatagram   = 65536
	lookupTimeout = 30 * time.Second
)

// hostResolved is a server host name's IPv4 address; invalid when the
// lookup failed.
type hostResolved struct {
	host string
	addr netip.Addr
}

// runServer performs the server's actions in order.
func (e *Engine) runServer(actions []server.Action) {
	for _, action := range actions {
		switch a := action.(type) {
		case server.Close:
			if c := e.serverConnByEndpoint(a.Server); c != nil {
				e.closeConn(c, "server closed")
			}
		case server.Dial:
			e.openConn(a.Server, true, wire.Hash{}, a.ObfuscationPort)
		case server.Send:
			if c := e.serverConnByEndpoint(a.To); c != nil {
				e.sendPacket(c, a.Packet, wire.Hash{}, 0)
			}
		case server.Datagram:
			data := wire.BuildPacketDatagram(nil, a.Packet)
			if a.Key != 0 {
				data = obfuscation.BuildServerDatagram(data, a.Key, e.ports.Rand.Uint32())
			}
			e.sendDatagram(a.To, data)
		case server.Callback:
			if e.connByEndpoint(a.Endpoint) == nil && len(e.conns) < maxConnections {
				canObfuscate := a.CanObfuscate && !e.hasOtherUser(a.Endpoint, a.UserHash)
				e.openPeerConn(a.Endpoint, a.UserHash, canObfuscate)
			}
		case server.Resolve:
			e.startLeaf(func() { e.runLookup(a.Host) })
		case server.SourcesFound:
			channel := transfer.ChannelServer
			if a.IsGlobal {
				channel = transfer.ChannelGlobalServer
			}
			if r := e.downloadByHash(a.File); r != nil {
				e.runTransferActions(r, r.transfer.OnSourcesFound(toServerSources(a.Sources), channel, e.now()))
			}
		case server.IDChanged:
			if !wire.IsLowID(a.ClientID) {
				e.publicIP = wire.ToAddr(a.ClientID)
			}
		case server.MessageReceived:
			log.Printf("engine: server message: %s", a.Text)
		}
	}
}

// runLookup is a leaf that resolves a server's host name.
func (e *Engine) runLookup(host string) {
	ctx, cancel := context.WithTimeout(e.ctx, lookupTimeout)
	addrs, err := e.ports.Transport.LookupHost(ctx, host)
	cancel()
	var addr netip.Addr
	if err == nil && len(addrs) > 0 {
		addr = addrs[0]
	} else {
		log.Printf("engine: server host %s: %v", host, err)
	}
	e.send(e.ctx, hostResolved{host, addr})
}

// updateLearned puts what an earlier Engine Process learned about each
// listed server back on its entry; names and preferences stay as the lists
// say. A saved server no list names any more is forgotten: Kelpie learns
// servers only from the caller's lists.
func updateLearned(entries []server.Entry, saved []store.Server) []server.Entry {
	for i, e := range entries {
		j := slices.IndexFunc(saved, func(s store.Server) bool {
			if e.Host != "" {
				return s.Host == e.Host && s.Port == e.Endpoint.Port()
			}
			return s.Host == "" && s.Endpoint == e.Endpoint
		})
		if j < 0 {
			continue
		}
		s := saved[j]
		entries[i].Failures, entries[i].Ping, entries[i].PingedAt = s.Failures, s.Ping, s.PingedAt
		entries[i].Users, entries[i].Files, entries[i].SoftFiles = s.Users, s.Files, s.SoftFiles
		entries[i].UDPFlags = s.UDPFlags
		entries[i].TCPObfuscationPort, entries[i].UDPObfuscationPort = s.TCPObfuscationPort, s.UDPObfuscationPort
	}
	return entries
}

func toStoreServers(entries []server.Entry) []store.Server {
	var servers []store.Server
	for _, e := range entries {
		s := store.Server{
			Endpoint:           e.Endpoint,
			Failures:           e.Failures,
			Ping:               e.Ping,
			Users:              e.Users,
			Files:              e.Files,
			SoftFiles:          e.SoftFiles,
			UDPFlags:           e.UDPFlags,
			TCPObfuscationPort: e.TCPObfuscationPort,
			UDPObfuscationPort: e.UDPObfuscationPort,
			PingedAt:           e.PingedAt,
		}
		if e.Host != "" {
			s.Endpoint, s.Host, s.Port = netip.AddrPort{}, e.Host, e.Endpoint.Port()
		}
		servers = append(servers, s)
	}
	return servers
}

// hasOtherUser tells whether a Hello from endpoint named a user other than
// user. aMule then connects plain, since it cannot tell which hash is true
// (ServerSocket.cpp:527-536).
func (e *Engine) hasOtherUser(endpoint netip.AddrPort, user wire.Hash) bool {
	hasOther := false
	for key, target := range e.uploadEndpoints {
		if target.endpoint != endpoint {
			continue
		}
		if key.user == user {
			return false
		}
		hasOther = true
	}
	return hasOther
}

func (e *Engine) serverConnByEndpoint(addr netip.AddrPort) *conn {
	for _, c := range e.conns {
		if c.isServer && c.remote == addr {
			return c
		}
	}
	return nil
}

func toServerSources(found []server.Source) []transfer.Source {
	var sources []transfer.Source
	for _, f := range found {
		src := transfer.Source{Endpoint: f.Endpoint, UserHash: f.UserHash, CanObfuscate: f.CanObfuscate}
		if f.IsLowID {
			src = transfer.Source{ClientID: f.ClientID, Server: f.Server, UserHash: f.UserHash}
		}
		sources = append(sources, src)
	}
	return sources
}

func (e *Engine) requestServerCallback(clientID uint32) {
	e.runServer(e.server.RequestCallback(clientID, e.now()))
}

func toKadCallback(a transfer.RequestKadCallback, file wire.Hash) kad.Callback {
	return kad.Callback{Buddy: a.Buddy, BuddyID: a.BuddyID, Hash: file}
}

// buildServerWanted lists every running Transfer: incomplete ones are
// searched until they have enough sources, those with verified parts are
// offered. The source count is the last Progress, at most a second old.
func (e *Engine) buildServerWanted() []server.Wanted {
	var wanted []server.Wanted
	for _, r := range e.runs {
		if r.transfer == nil {
			continue
		}
		wanted = append(wanted, server.Wanted{
			File:       r.file.Hash,
			Size:       uint64(r.file.Size),
			Name:       r.file.Name,
			IsComplete: r.share.Parts.IsFull(),
			IsShared:   r.share.Parts.Count() > 0,
			Sources:    r.progress.Peers,
		})
	}
	return wanted
}

// buildKadWanted is the whole set Kad searches and publishes; Kad paces its
// own searches, so it is sent every second.
func (e *Engine) buildKadWanted() kad.Wanted {
	var wanted kad.Wanted
	for _, r := range e.runs {
		if r.transfer == nil {
			continue
		}
		if r.mode == ModeDownload {
			wanted.Find = append(wanted.Find, kad.Search{Hash: r.file.Hash, Size: r.file.Size, Sources: r.progress.Peers})
		}
		if r.share.Parts.Count() > 0 {
			wanted.Publish = append(wanted.Publish, kad.Publish{Hash: r.file.Hash, Size: r.file.Size})
		}
	}
	return wanted
}

func (e *Engine) onKadSources(found kad.SourcesFound) {
	if r := e.downloadByHash(found.Hash); r != nil {
		e.runTransferActions(r, r.transfer.OnSourcesFound(toKadSources(found.Sources), transfer.ChannelKad, e.now()))
	}
}

func (e *Engine) sendDatagram(to netip.AddrPort, data []byte) {
	if e.kad != nil {
		e.kad.Post(kad.Datagram{Addr: to, Data: data})
		return
	}
	e.udp.WriteTo(data, to)
}

// runUDPReader serves the UDP socket when Kad does not own it.
func (e *Engine) runUDPReader() {
	buf := make([]byte, maxDatagram)
	for {
		n, from, err := e.udp.ReadFrom(buf)
		if err != nil {
			return
		}
		if !e.send(e.ctx, datagramReceived{from, append([]byte(nil), buf[:n]...)}) {
			return
		}
	}
}

// onDatagram routes eD2k UDP: server packets to the server, peer reasks to
// the upload queue and the downloads.
func (e *Engine) onDatagram(from netip.AddrPort, data []byte) {
	if key := e.server.UDPKeyByAddr(from); key != 0 {
		if packet, ok := obfuscation.ParseServerDatagram(data, key); ok {
			data = packet
		}
	} else if packet, ok := obfuscation.ParsePeerDatagram(data, e.self.UserHash, from.Addr()); ok {
		data = packet
	}
	frame, err := wire.ParseDatagram(data)
	if err != nil {
		return
	}
	now := e.now()
	switch frame.Protocol {
	case wire.ProtocolEDonkey:
		if p, err := serverwire.ParseUDP(frame.Protocol, frame.Opcode, frame.Body); err == nil {
			e.runServer(e.server.OnPacket(from, p, now))
		}
	case wire.ProtocolEMule:
		p, err := client.ParseUDP(frame.Protocol, frame.Opcode, frame.Body)
		if err != nil {
			return
		}
		switch p := p.(type) {
		case client.ReaskFilePing:
			e.onReask(from, p)
		case client.ReaskCallbackUDP:
			e.onReaskCallbackUDP(from, p)
		case client.DirectCallbackReq:
			e.onDirectCallbackReq(from, p)
		case client.ReaskAck:
			for _, r := range slices.Clone(e.runs) {
				if e.downloadByHash(r.file.Hash) != nil {
					e.runTransferActions(r, r.transfer.OnReaskAnswered(from, int(p.Rank), now))
				}
			}
		}
	}
}

func (e *Engine) onReask(from netip.AddrPort, ping client.ReaskFilePing) {
	var reply wire.Packet
	var user wire.Hash
	switch a := e.queue.OnReask(from.Addr(), from.Port(), ping.Hash, e.now()).(type) {
	case upload.ReaskAck:
		ack := client.ReaskAck{Rank: uint16(min(a.Rank, 0xFFFF))}
		if r := e.runByHash[ping.Hash]; ping.HasParts && r != nil {
			ack.HasParts, ack.Parts = true, peer.ToStatus(r.share)
		}
		reply, user = ack, a.User
	case upload.FileNotFound:
		reply, user = client.FileNotFound{}, a.User
	case upload.QueueFull:
		reply = client.QueueFull{}
	default:
		return
	}
	canObfuscate := e.uploadEndpoints[uploadKey{user, from.Addr()}].canObfuscate
	e.sendPeerDatagram(from, reply, user, canObfuscate)
}

// sendPeerDatagram obfuscates p for the client with user hash user when it
// supports obfuscation and we know our public IPv4 address, which keys it;
// we always request obfuscation, so that is aMule's
// ShouldReceiveCryptUDPPackets (BaseClient.cpp:2609, MuleUDPSocket.cpp:269).
func (e *Engine) sendPeerDatagram(to netip.AddrPort, p wire.Packet, user wire.Hash, canObfuscate bool) {
	data := wire.BuildPacketDatagram(nil, p)
	if canObfuscate && user != (wire.Hash{}) && e.publicIP.Is4() {
		data = obfuscation.BuildPeerDatagram(data, user, e.publicIP, e.ports.Rand.Uint32())
	}
	e.sendDatagram(to, data)
}
