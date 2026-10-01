package server

import (
	"net/netip"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/wire"
	packet "github.com/XiaoYouChR/Kelpie/internal/wire/server"
)

// eMule's UDP pacing (Opcodes.h, DownloadQueue.cpp, ServerList.cpp).
const (
	udpSearchTime        = 30 * time.Minute             // UDPSERVERREASKTIME, between rounds
	udpSearchSpeed       = time.Second                  // UDPSEARCHSPEED, between packets
	udpStatTime          = 5 * time.Second              // UDPSERVERSTATTIME, between pings
	udpStatReaskTime     = 4*time.Hour + 30*time.Minute // UDPSERVSTATREASKTIME
	maxUDPPacketData     = 510                          // MAX_UDP_PACKET_DATA
	maxRequestsPerServer = 35                           // MAX_REQUESTS_PER_SERVER
	bytesPerFile         = 20                           // BYTES_PER_FILE_G2
	bytesPerLargeFile    = bytesPerFile + 8             // ADDITIONAL_BYTES_PER_LARGEFILE
	challengeBase        = 0x55AA0000                   // ServerStats challenge prefix
)

// udpSearch is the OP_GLOBGETSOURCES2 series to the server being asked,
// and the status ping cycle.
type udpSearch struct {
	server    *listed
	asked     int
	fileStart int
	lastSent  time.Time

	statCursor int
	lastStat   time.Time
	pings      uint16
}

func (s *Server) OnUDPPacket(from netip.AddrPort, p wire.Packet, now time.Time) Output {
	var out Output
	l := s.serverByUDP(from)
	if l == nil {
		return out
	}
	switch p := p.(type) {
	case packet.GlobServStatRes:
		if l.challenge == 0 || p.Challenge != l.challenge {
			return out
		}
		l.challenge, l.Failures, l.isDead = 0, 0, false
		l.Ping = uint32(now.Sub(l.pingedAt).Milliseconds())
		l.Users, l.Files, l.SoftFiles, l.UDPFlags = p.Users, p.Files, p.SoftFiles, p.UDPFlags
		l.TCPObfuscationPort, l.UDPObfuscationPort = p.TCPObfuscationPort, p.UDPObfuscationPort
	case packet.GlobFoundSources:
		for _, f := range p.Files {
			if !s.isWanted(f.Hash) {
				continue
			}
			var sources []Source
			for _, found := range f.Sources {
				// A LowID source from another server could only be reached
				// by a callback through that server, which we are not on.
				src, ok := s.toSource(found, l.Endpoint)
				if ok && !src.IsLowID {
					sources = append(sources, src)
				}
			}
			if len(sources) > 0 {
				out.Events = append(out.Events, SourcesFound{File: f.Hash, Sources: sources, IsGlobal: true})
			}
		}
	}
	return out
}

// runStats pings one server every UDPSERVERSTATTIME, each at most once per
// UDPSERVSTATREASKTIME. A server still owing the previous answer when its
// turn comes again is dead to UDP.
func (s *Server) runStats(now time.Time, out *Output) {
	u := &s.udp
	if !u.lastStat.IsZero() && now.Sub(u.lastStat) <= udpStatTime {
		return
	}
	for range s.servers {
		l := s.servers[u.statCursor%len(s.servers)]
		u.statCursor++
		if l.isDead || (!l.pingedAt.IsZero() && now.Sub(l.pingedAt) < udpStatReaskTime) {
			continue
		}
		u.lastStat = now
		if l.challenge != 0 {
			l.isDead = true
			return
		}
		u.pings++
		l.challenge = challengeBase + uint32(u.pings)
		l.pingedAt = now
		l.Failures++
		out.SendUDP = append(out.SendUDP, Datagram{To: toUDP(l.Endpoint), Packet: packet.GlobServStatReq{Challenge: l.challenge}})
		return
	}
}

// runSearch sends at most one OP_GLOBGETSOURCES2 per UDPSEARCHSPEED. A
// server is asked again only UDPSERVERREASKTIME after its last series, so
// none is asked more often than in eMule's rounds, but a server whose
// support shows up late is asked at once instead of a round later. Each
// series asks at most MAX_REQUESTS_PER_SERVER files; past that the file
// list rotates so the next server is asked about the others.
func (s *Server) runSearch(now time.Time, out *Output) {
	u := &s.udp
	if !u.lastSent.IsZero() && now.Sub(u.lastSent) < udpSearchSpeed {
		return
	}
	if u.server == nil || u.server == s.current {
		u.server, u.asked = s.nextSearchServer(now), 0
		if u.server == nil {
			return
		}
	}
	files := s.searchFiles(u.server.UDPFlags)
	quota := min(len(files), maxRequestsPerServer)
	var batch []packet.GetSources
	for size := 0; u.asked < quota && size < maxUDPPacketData; u.asked++ {
		w := files[u.asked]
		batch = append(batch, packet.GetSources{Hash: w.File, Size: w.Size})
		size += bytesPerFile
		if w.Size > largeFileSize {
			size += bytesPerLargeFile - bytesPerFile
		}
	}
	if len(batch) > 0 {
		out.SendUDP = append(out.SendUDP, Datagram{To: toUDP(u.server.Endpoint), Packet: packet.GlobGetSources2{Files: batch}})
		u.lastSent = now
	}
	if u.asked >= quota {
		if u.asked == maxRequestsPerServer {
			u.fileStart += maxRequestsPerServer
		}
		u.server.searchedAt = now
		u.server = nil
	}
}

// searchFiles is the incomplete files a server with udpFlags can be asked
// about, starting at the rotation point. A server without
// OP_GLOBGETSOURCES2 is not asked: every server Kelpie lists has it, and
// the older OP_GLOBGETSOURCES cannot ask about large files.
func (s *Server) searchFiles(udpFlags uint32) []Wanted {
	if udpFlags&packet.UDPFlagGetSources2 == 0 {
		return nil
	}
	var files []Wanted
	n := len(s.wanted)
	for i := range n {
		w := s.wanted[(s.udp.fileStart+i)%n]
		if !w.IsComplete && (w.Size <= largeFileSize || udpFlags&packet.UDPFlagLargeFiles != 0) {
			files = append(files, w)
		}
	}
	return files
}

// nextSearchServer is the first server in list order that is due, skipping
// the connected server (asked over TCP) and servers given up on. A server
// that failed over TCP may still answer over UDP, as aMule assumes.
func (s *Server) nextSearchServer(now time.Time) *listed {
	for _, l := range s.servers {
		isDue := l.searchedAt.IsZero() || now.Sub(l.searchedAt) > udpSearchTime
		if l != s.current && isDue && l.Failures < maxFailures && len(s.searchFiles(l.UDPFlags)) > 0 {
			return l
		}
	}
	return nil
}

func (s *Server) serverByUDP(from netip.AddrPort) *listed {
	for _, l := range s.servers {
		if toUDP(l.Endpoint) == from {
			return l
		}
	}
	return nil
}

// toUDP gives a server's UDP endpoint: its TCP port plus 4.
func toUDP(endpoint netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(endpoint.Addr(), endpoint.Port()+4)
}
