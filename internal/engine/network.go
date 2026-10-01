package engine

import (
	"log"
	"net/netip"
	"slices"

	"github.com/XiaoYouChR/Kelpie/internal/kad"
	"github.com/XiaoYouChR/Kelpie/internal/server"
	"github.com/XiaoYouChR/Kelpie/internal/transfer"
	"github.com/XiaoYouChR/Kelpie/internal/upload"
	"github.com/XiaoYouChR/Kelpie/internal/wire"
	"github.com/XiaoYouChR/Kelpie/internal/wire/client"
	kadwire "github.com/XiaoYouChR/Kelpie/internal/wire/kad"
	serverwire "github.com/XiaoYouChR/Kelpie/internal/wire/server"
)

const (
	kadVersion  = kadwire.Version
	maxDatagram = 65536
)

// runServer performs the server's Output in its documented order.
func (e *Engine) runServer(out server.Output) {
	for _, addr := range out.Close {
		if c := e.serverConnByEndpoint(addr); c != nil {
			e.closeConn(c, "server closed")
		}
	}
	for _, addr := range out.Connect {
		e.openConn(addr, true, wire.Hash{})
	}
	if c := e.serverConnByEndpoint(out.To); c != nil {
		for _, p := range out.Send {
			e.sendPacket(c, p, wire.Hash{}, 0)
		}
	}
	for _, d := range out.SendUDP {
		e.sendDatagram(d.To, wire.BuildPacketDatagram(nil, d.Packet))
	}
	for _, callback := range out.ConnectPeers {
		if e.connByEndpoint(callback.Endpoint) == nil && len(e.conns) < maxConnections {
			var obfuscateFor wire.Hash
			if callback.CanObfuscate {
				obfuscateFor = callback.UserHash
			}
			e.openConn(callback.Endpoint, false, obfuscateFor)
		}
	}
	for _, event := range out.Events {
		switch ev := event.(type) {
		case server.SourcesFound:
			channel := transfer.ChannelServer
			if ev.IsGlobal {
				channel = transfer.ChannelGlobalServer
			}
			if r := e.downloadByHash(ev.File); r != nil {
				e.addSources(r, toServerSources(ev.Sources), channel)
			}
		case server.IDChanged:
			e.serverAddr = ev.Server
			if !wire.IsLowID(ev.ClientID) {
				e.publicIP = wire.ToAddr(ev.ClientID)
			}
		case server.MessageReceived:
			log.Printf("engine: server message: %s", ev.Text)
		}
	}
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
	out, ok := e.server.RequestCallback(server.Source{ClientID: clientID, IsLowID: true, Server: e.serverAddr}, e.now())
	if ok {
		e.runServer(out)
	}
}

func toKadCallback(a transfer.RequestKadCallback, file wire.Hash) kad.Callback {
	return kad.Callback{Buddy: a.Buddy, BuddyID: a.BuddyID, Hash: file}
}

// buildServerWanted lists every running Transfer: incomplete ones are
// searched, those with verified parts are offered.
func (e *Engine) buildServerWanted() []server.Wanted {
	var wanted []server.Wanted
	for _, r := range e.runList {
		if r.transfer == nil {
			continue
		}
		wanted = append(wanted, server.Wanted{
			File:       r.file.Hash,
			Size:       uint64(r.file.Size),
			Name:       r.file.Name,
			IsComplete: r.share.Parts.IsFull(),
			IsShared:   r.published.Count() > 0,
		})
	}
	return wanted
}

// buildKadWanted is the whole set Kad searches and publishes; Kad paces its
// own searches, so it is sent every second.
func (e *Engine) buildKadWanted() kad.Wanted {
	var wanted kad.Wanted
	for _, r := range e.runList {
		if r.transfer == nil {
			continue
		}
		if r.mode == ModeDownload {
			wanted.Find = append(wanted.Find, kad.Search{Hash: r.file.Hash, Size: r.file.Size})
		}
		if r.published.Count() > 0 {
			wanted.Publish = append(wanted.Publish, kad.Publish{Hash: r.file.Hash, Size: r.file.Size})
		}
	}
	return wanted
}

func (e *Engine) onKadSources(found kad.SourcesFound) {
	if r := e.downloadByHash(found.Hash); r != nil {
		e.addSources(r, toKadSources(found.Sources), transfer.ChannelKad)
	}
}

func (e *Engine) sendDatagram(to netip.AddrPort, data []byte) {
	if e.kad != nil {
		e.kad.Send(kad.Datagram{Addr: to, Data: data})
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
	frame, err := wire.ParseDatagram(data)
	if err != nil {
		return
	}
	now := e.now()
	switch frame.Protocol {
	case wire.ProtocolEDonkey:
		if p, err := serverwire.ParseUDP(frame.Protocol, frame.Opcode, frame.Body); err == nil {
			e.runServer(e.server.OnUDPPacket(from, p, now))
		}
	case wire.ProtocolEMule:
		p, err := client.ParseUDP(frame.Protocol, frame.Opcode, frame.Body)
		if err != nil {
			return
		}
		switch p := p.(type) {
		case client.ReaskFilePing:
			e.onReask(from, p)
		case client.ReaskAck:
			for _, r := range slices.Clone(e.runList) {
				if e.downloadByHash(r.file.Hash) != nil {
					e.runTransferActions(r, r.transfer.OnReaskAnswered(from, int(p.Rank), now))
				}
			}
		}
	}
}

func (e *Engine) onReask(from netip.AddrPort, ping client.ReaskFilePing) {
	var reply wire.Packet
	switch a := e.queue.OnReask(from.Addr(), from.Port(), ping.Hash, e.now()).(type) {
	case upload.ReaskAck:
		ack := client.ReaskAck{Rank: uint16(min(a.Rank, 0xFFFF))}
		if r := e.runByHash[ping.Hash]; ping.HasParts && r != nil {
			ack.HasParts, ack.Parts = true, toStatus(r.share)
		}
		reply = ack
	case upload.FileNotFound:
		reply = client.FileNotFound{}
	case upload.QueueFull:
		reply = client.QueueFull{}
	default:
		return
	}
	e.sendDatagram(from, wire.BuildPacketDatagram(nil, reply))
}
