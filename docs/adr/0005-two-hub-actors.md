# ADR-0005: Two hub actors; blocking sends point into hubs

## Status

Accepted

## Decision

The engine has two actors that own state. Engine owns transfers, peer
sessions, the upload queue, credits, the server connection, buddy links, and
the ticker. Kad owns the routing table, lookups, the source index, buddy
search, its timers, and the UDP socket it shares with eD2k UDP; with Kad off,
Engine holds that socket. Server UDP has a socket of its own, held by Engine.
Every other goroutine is a stateless leaf: the gateway on stdin and stdout,
the acceptor, one reader and one writer per connection, the UDP readers, the
disk workers, the trace writer, the store
saver, port mapping, and host lookups. Engine and Kad talk only through
`Post` and `Events`.

Inside each hub, peers, transfers, uploads, and the server are state machines
that consume events and return actions; the hub performs the I/O.

Deadlock freedom rests on one rule: only sends from a leaf into a hub may
block. A hub sends to a leaf only within credit it has counted, and to the other
hub by dropping when full. Engine sends to the gateway into latest-value slots
for progress and network, and a queue that grows by one `ended` per run.
Messages that must not be lost are latest values: Engine sends Kad the whole
set of wanted hashes, and Kad sends its status again until it gets through.

## Considered Options

- One actor for everything: Kad's UDP volume and timers would share Engine's
  loop, and Kad already meets Engine at only a few messages.
- A separate server actor: every server message reads or writes Engine's
  state, so it would own nothing but a mailbox.
- An actor per transfer and per peer: one connection serves downloads and
  uploads of several files, so a single packet would need synchronous asks
  across actors.

## Consequences

- A panic in a hub exits the Engine Process; the Python side is the
  supervisor and starts it again on the next call.
- A transfer's failure is isolated by value: it ends its own Run and leaves
  other transfers running.
- Rate limit buckets and progress slots are shared memory, not messages.
- Engine tests run every Engine channel at capacity one under `-race` to check
  the rule.
