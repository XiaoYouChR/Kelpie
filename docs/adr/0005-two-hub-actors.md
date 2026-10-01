# ADR-0005: Two hub actors; blocking sends point into hubs

## Status

Accepted

## Decision

The engine has two actors that own state. Engine owns transfers, peer
sessions, the upload queue, credits, the server connection, rate limits, and
the ticker. Kad owns the routing table, its UDP socket, and its timers. Every
other goroutine is a stateless leaf: the gateway on stdin and stdout, one
reader and one writer per connection, the disk workers, and the store.

Inside each hub, peers, transfers, uploads, and the server are state machines
that consume events and return actions; the hub performs the I/O.

Deadlock freedom rests on one rule: only sends from a leaf into a hub may
block. A hub sends to a leaf only within credit it has counted, sends to the
other hub by dropping when full, and sends to the gateway into latest-value
slots. Engine sends Kad the whole set of wanted hashes, so a dropped message is
replaced by the next one.

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
- Tests run every channel at capacity one under `-race` to check the rule.
