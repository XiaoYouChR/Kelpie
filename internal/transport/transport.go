// Package transport is the engine's seam for TCP and UDP sockets.
//
// Listeners and UDP sockets are dual-stack: one socket serves IPv4 and IPv6.
// Accepted connections report their peer as a *net.TCPAddr; call
// AddrPort().Unmap() on it, since a dual-stack socket may report an IPv4 peer
// as an IPv4-mapped IPv6 address.
package transport

import (
	"context"
	"net"
	"net/netip"
)

type Transport interface {
	OpenTCP(ctx context.Context, addr netip.AddrPort) (net.Conn, error)
	// OpenListener and OpenUDP pick a free port when port is 0.
	OpenListener(port int) (Listener, error)
	OpenUDP(port int) (PacketConn, error)
	// LookupHost resolves a host name to its IPv4 addresses.
	LookupHost(ctx context.Context, host string) ([]netip.Addr, error)
}

type Listener interface {
	Accept() (net.Conn, error)
	Close() error
	Port() int
}

type PacketConn interface {
	// ReadFrom reports an IPv4 sender as an IPv4 address, never IPv4-mapped.
	ReadFrom(b []byte) (int, netip.AddrPort, error)
	WriteTo(b []byte, addr netip.AddrPort) (int, error)
	Close() error
	Port() int
}

// Real is the Transport of the running process.
type Real struct{}

func (Real) OpenTCP(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, "tcp", addr.String())
}

func (Real) OpenListener(port int) (Listener, error) {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{Port: port})
	if err != nil {
		return nil, err
	}
	return realListener{listener}, nil
}

func (Real) OpenUDP(port int) (PacketConn, error) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: port})
	if err != nil {
		return nil, err
	}
	return realPacketConn{conn}, nil
}

func (Real) LookupHost(ctx context.Context, host string) ([]netip.Addr, error) {
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	for i, a := range addrs {
		addrs[i] = a.Unmap()
	}
	return addrs, err
}

// ProbeLocalAddrs lists the addresses of the host's network interfaces.
func ProbeLocalAddrs() ([]netip.Addr, error) {
	addrs, err := net.InterfaceAddrs()
	var local []netip.Addr
	for _, a := range addrs {
		if prefix, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(prefix.IP); ok {
				local = append(local, ip.Unmap())
			}
		}
	}
	return local, err
}

type realListener struct{ *net.TCPListener }

func (l realListener) Port() int { return l.Addr().(*net.TCPAddr).Port }

type realPacketConn struct{ conn *net.UDPConn }

func (c realPacketConn) ReadFrom(b []byte) (int, netip.AddrPort, error) {
	n, addr, err := c.conn.ReadFromUDPAddrPort(b)
	return n, netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port()), err
}

func (c realPacketConn) WriteTo(b []byte, addr netip.AddrPort) (int, error) {
	return c.conn.WriteToUDPAddrPort(b, addr)
}

func (c realPacketConn) Close() error { return c.conn.Close() }

func (c realPacketConn) Port() int { return c.conn.LocalAddr().(*net.UDPAddr).Port }
