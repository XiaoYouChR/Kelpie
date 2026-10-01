# ADR-0004: A Transfer runs only while a Run is open

## Status

Accepted

## Decision

The caller opens a Run with `runDownload(link, file)` or `runSeed(link, file)` and
closes it by leaving its `async with` block. The Transfer runs exactly while
its Run is open. Whether a Transfer runs is never persisted, and the Engine
Process resumes nothing at startup.

A Run's outcome is the Transfer's state: it reports Progress while open, a
download Run ends on its own when the file is complete, a failed Run raises
`kelpie.Error`, and closing it stops the Transfer. Every failure, including
admission, startup, and Engine Process exit, reaches the caller through the
Run that it affects; no other call raises a business error.

Apart from the handshake, every protocol message is one-way. The caller tags
each Run with a run id; Progress for a run id may be coalesced, and exactly one
end message follows each Run.

## Considered Options

- Commands `add`, `pause`, `resume` with a persisted paused flag: the caller's
  task state and the engine's paused flag drift apart, and a crash makes the
  engine resume transfers the caller considers paused.
- One `run` for both modes with a completion flag: a seed whose
  file has gone would silently download again while the caller shows it as
  complete.
- Declaring the full desired set of Transfers: the caller would need an
  aggregator, and generations and tokens add concepts without removing any.
- Request and response for every command: two error exits and a pending
  request table, for no extra information.

## Consequences

- A Transfer has at most one open Run; a second one fails with
  `TRANSFER_BUSY`.
- Run ids, not hashes, route events, so a stopped download cannot end the seed
  that follows it.
- Removing a Transfer's Durable State is an explicit `remove(hash)`.
- A Run ended by anyone but its caller — `close()`, or `remove(hash)` while it
  is open — raises `asyncio.CancelledError` in the caller, because a normal
  end would read as a finished download.
