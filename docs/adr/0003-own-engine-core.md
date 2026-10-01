# ADR-0003: Replace the goed2k runtime core with our own engine

## Status

Accepted

## Decision

Kelpie's first release ships our own engine; `third_party/goed2k` is not
carried into the Kelpie repository.

The new engine keeps the proven parts — wire codecs, ed2k hashing, server.met /
nodes.dat / link parsing, piece picking, Kad routing and traversal algorithms —
behind narrower interfaces, and rewrites the runtime core: session, transfer,
peer session, connection, upload queue, and storage. The actor structure is
recorded in ADR-0005.

The engine reads the existing goed2k `state.json` (versions up to 3), so identities,
credits, Kad nodes, and unfinished transfers survive the switch, and writes its
own format.

## Considered Options

- Refactor `goed2k` in place: its mutex does not guard the tick thread's
  mutations (`go test -race` reports data races), and Session and
  PeerConnection couple every subsystem, so no piece can move alone.
- Rewrite everything: discards codecs and Kad interoperability fixes that
  already have test vectors.
- Goroutine per peer with shared locks: keeps the race surface we are leaving.
- Keep an adapter for the old engine to run contract tests against both: costs
  a throwaway adapter for an engine that never ships behind the new protocol.

## Consequences

- Engine tests use fake net, clock, and disk adapters; the disk fake injects
  faults such as a full disk. Tests that reach the real network run only when
  explicitly enabled.
- The release bar is speed on a hot link: Kelpie must sustain 2 MiB/s on the
  Ubuntu ISO in bench/links.txt, which aMule reached behind a LowID in a
  2-minute smoke run while goed2kd stayed near 150 KiB/s. The benchmark logs one
  lifecycle event per source so a shortfall can be traced to a channel or stage.
- The connection limit is internal, matching eMule's defaults.
- First release: slot grants on incoming connections, UDP reask, Secure User
  Identification, eMule-sized connection limits, server callbacks for LowID in
  both directions, Source Exchange v2 in both directions, UDP global source
  search, Kad version 8 with firewall checks, a source index for other nodes,
  and buddies in both roles, a full request pipeline with compression,
  MULTIPACKET_EXT2 and rarest-first picking, asking each client for one file
  at a time as aMule's A4AF does, publishing partial files to servers and Kad, block-level corruption
  handling with AICH recovery and banning, one server connection at a time, our
  own client identity, and dual-stack addresses with IPv6 in Source Exchange
  between Kelpie peers and in server source answers following the emule-qt
  specification.
- Protocol obfuscation, TCP and UDP, is in the first release too: on the real
  network the fastest sources of the hot link (aMule seedboxes) require it and
  close a plain connection right after our Hello.
- Port mapping tries PCP and NAT-PMP before UPnP: UPnP is often off or broken
  on home routers, and a HighID matters more to speed than any other feature.
- Not planned: Kad keyword and note searches, which no caller needs. Kad stays
  IPv4.
- Code may be reused from `goed2k` (MIT) with attribution; eMule and aMule
  (GPL) contribute protocol knowledge only.
