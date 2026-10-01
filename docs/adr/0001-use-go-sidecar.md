# ADR-0001: Use a Go engine process

## Status

Accepted

## Decision

Python starts one `kelpie` Engine Process and communicates through stdio
NDJSON. The Engine Process owns all eD2k protocol activity for the application.

The Python `Kelpie` class exposes typed Runs and Progress. It does not expose
raw JSON, Go objects, transport seams, or protocol persistence details.

## Consequences

- An Engine Process failure does not terminate the Python application.
- Kelpie starts the Engine Process when first needed and again on the next
  call after it exits; it never restarts it on its own.
- IPC carries commands and progress, never file payloads.
- The current asyncio loop owns subprocess execution.
- The same Kelpie instance remains bound to one event loop.
- Commands execute in stdin order.
