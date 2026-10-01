package engine

import (
	"fmt"
	"log"
	"net/netip"
	"sync"
	"time"

	"github.com/XiaoYouChR/Kelpie/internal/clock"
	"github.com/XiaoYouChR/Kelpie/internal/transport"
	"github.com/XiaoYouChR/Kelpie/internal/wire"
	"github.com/XiaoYouChR/Kelpie/internal/wire/client"
	serverwire "github.com/XiaoYouChR/Kelpie/internal/wire/server"
)

// kadLogTime spaces the Kad datagram counts; a line per Kad datagram would
// bury the server and peer lines.
const kadLogTime = time.Minute

// udpLogTransport writes every UDP datagram to the packet log, whichever
// actor owns the socket: the engine, or Kad.
type udpLogTransport struct {
	transport.Transport
	log   *log.Logger
	clock clock.Clock
}

func (t udpLogTransport) OpenUDP(port int) (transport.PacketConn, error) {
	conn, err := t.Transport.OpenUDP(port)
	if err != nil {
		return nil, err
	}
	return &udpLogConn{PacketConn: conn, log: t.log, clock: t.clock, loggedAt: t.clock.Now()}, nil
}

type udpLogConn struct {
	transport.PacketConn
	log   *log.Logger
	clock clock.Clock

	mu                      sync.Mutex
	loggedAt                time.Time
	kadIn, kadOut           int
	kadBytesIn, kadBytesOut int
}

func (c *udpLogConn) ReadFrom(b []byte) (int, netip.AddrPort, error) {
	n, from, err := c.PacketConn.ReadFrom(b)
	if err == nil {
		c.send("in ", from, b[:n])
	}
	return n, from, err
}

func (c *udpLogConn) WriteTo(b []byte, addr netip.AddrPort) (int, error) {
	n, err := c.PacketConn.WriteTo(b, addr)
	if err == nil {
		c.send("out", addr, b)
	}
	return n, err
}

func (c *udpLogConn) send(direction string, addr netip.AddrPort, data []byte) {
	if len(data) > 0 && (data[0] == wire.ProtocolKad || data[0] == wire.ProtocolKadPacked) {
		c.addKad(direction == "in ", len(data))
		return
	}
	c.log.Printf("udp %s %s %s %d", direction, addr, toDatagramName(data), len(data))
}

func (c *udpLogConn) addKad(isIn bool, size int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if isIn {
		c.kadIn, c.kadBytesIn = c.kadIn+1, c.kadBytesIn+size
	} else {
		c.kadOut, c.kadBytesOut = c.kadOut+1, c.kadBytesOut+size
	}
	now := c.clock.Now()
	if now.Sub(c.loggedAt) < kadLogTime {
		return
	}
	c.log.Printf("udp kad in %d (%d B) out %d (%d B) in %s", c.kadIn, c.kadBytesIn, c.kadOut, c.kadBytesOut, now.Sub(c.loggedAt).Round(time.Second))
	c.loggedAt, c.kadIn, c.kadOut, c.kadBytesIn, c.kadBytesOut = now, 0, 0, 0, 0
}

// toDatagramName names an eD2k datagram like toPacketName, adding the
// source count of server answers, which is what the log is read for.
func toDatagramName(data []byte) string {
	frame, err := wire.ParseDatagram(data)
	if err != nil {
		return "unparsed"
	}
	parse := serverwire.ParseUDP
	if frame.Protocol == wire.ProtocolEMule {
		parse = client.ParseUDP
	}
	p, err := parse(frame.Protocol, frame.Opcode, frame.Body)
	if err != nil {
		return fmt.Sprintf("broken(%#02x,%#02x)", frame.Protocol, frame.Opcode)
	}
	switch p := p.(type) {
	case serverwire.GlobFoundSources:
		count := 0
		for _, f := range p.Files {
			count += len(f.Sources)
		}
		return fmt.Sprintf("%s files=%d sources=%d", toPacketName(p), len(p.Files), count)
	case serverwire.GlobGetSources2:
		return fmt.Sprintf("%s files=%d", toPacketName(p), len(p.Files))
	case serverwire.GlobServStatRes:
		return fmt.Sprintf("%s users=%d files=%d udpFlags=%#x", toPacketName(p), p.Users, p.Files, p.UDPFlags)
	}
	return toPacketName(p)
}
