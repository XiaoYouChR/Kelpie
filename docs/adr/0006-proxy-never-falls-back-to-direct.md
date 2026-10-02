# ADR-0006: A Proxy never falls back to a direct path

## Status

Accepted

## Decision

When Settings name a Proxy, everything we send goes through it: server and
peer TCP through SOCKS5 CONNECT; Kad, server UDP, and UDP reasks through one
SOCKS5 UDP ASSOCIATE. What the Proxy cannot carry stops; nothing goes out
directly instead.

- Only `socks5://` and `socks5h://` are accepted; any other scheme is an error
  at Settings, not a silent direct path. With `socks5://` a server listed by
  host name is resolved locally; with `socks5h://` no DNS query leaves
  directly, and since SOCKS5 cannot resolve without connecting, such a server
  is skipped.
- IPv4 and IPv6 destinations both go through the Proxy.
- When the Proxy has no UDP ASSOCIATE, or it drops, UDP stops and we download
  over TCP alone; the association is retried with backoff, and Network reports
  the reason in `proxyIssue`.
- We keep listening for TCP directly and keep port mapping. Listening sends
  nothing, and peers that already know our address can still reach us. UDP
  arrives only through the relay; datagrams sent straight to our UDP port are
  dropped, and their senders fall back to TCP.
- A changed Proxy applies to new TCP connections; open ones keep their path.
  The Kad and server UDP sockets reopen on the new path at once, so no
  datagram leaves directly after a Proxy is set.

## Considered Options

- eMule: TCP through the proxy, UDP and Kad direct. The direct UDP shows our
  address to every Kad node and server, which defeats the reason most users
  set a proxy.
- aMule 3.1.0: the same rule as ours, but it never re-associates after the
  control connection drops, so UDP stays off until restart, silently. It also
  sends IPv4 only and resolves names locally.
- Falling back to direct when the Proxy fails: users who want reachability
  rather than privacy can clear the Proxy instead; the fallback would leak for
  everyone else.
- No listening while a Proxy is set: little privacy gain, and both firewall
  checks would grow a special case.
- A second, direct UDP socket for datagrams sent straight to us: two sockets
  and a choice of path for every reply, to save UDP reasks that fall back to
  TCP anyway.
- Dialing host-named servers by name through the Proxy: TCP would work, but
  UDP replies name only an address we never resolved, and the server package
  would have to know about the Proxy. No listed server we have seen uses a
  host name.
- Keeping the old UDP sockets until restart: simpler, but after a user sets a
  Proxy, Kad would keep showing our address until the Engine Process exits.

## Consequences

- Behind a Proxy we are usually LowID: servers see the Proxy's address.
- A Proxy without UDP costs Kad and UDP reasks, so fewer sources.
- The SOCKS5 client is part of the transport seam, written against RFC 1928 and
  RFC 1929; the engine learns only the `proxyIssue` it reports, not how the
  Proxy works.
