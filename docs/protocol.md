# Engine Process protocol

Kelpie talks to the Engine Process over stdin and stdout. Each line is one UTF-8
JSON object with a `type` field. Unknown fields are ignored (ADR-0002). The
Engine Process writes diagnostics to stderr, never to stdout.

## Kelpie to Engine Process

`hello` is the first line and is sent once.

```json
{"type": "hello", "protocol": 1, "dataFolder": "/abs/path",
 "settings": {"port": 4662, "enableKad": true, "enableUpnp": true,
              "serverLists": ["/abs/server.met"], "nodeLists": ["/abs/nodes.dat"],
              "traceFile": ""},
 "rateLimits": {"download": 0, "upload": 0}}
```

- `dataFolder` holds the Durable State; it must not be empty.
- `port` is used for TCP and UDP; 0 picks a port free for both.
- `enableUpnp` maps the ports on the home gateway: PCP first, then NAT-PMP,
  then UPnP IGD.
- A server or node list that cannot be read is skipped.
- `traceFile`, when not empty, receives one JSON line per source lifecycle event
  (see Trace).
- Rate limits are bytes per second; 0 means unlimited.

```json
{"type": "run", "run": 1, "mode": "download", "link": "ed2k://|file|...|/", "file": "/abs/dir/name.iso"}
{"type": "stop", "run": 1}
{"type": "remove", "hash": "31D6CFE0D16AE931B73C59D7E0C089C0"}
{"type": "setRateLimits", "download": 0, "upload": 102400}
```

- `run` ids are chosen by Kelpie, positive, and never reused within one Engine
  Process.
- `mode` is `download` or `seed`. `file` is the final file path; the name in the
  link is ignored.
- `stop` for an unknown or ended run is ignored.
- `remove` deletes the Transfer's Durable State, never the file. If a run is
  open for that hash, it ends first as if stopped. Unknown hashes are ignored.
- A line that cannot be parsed, or has an unknown `type`, a non-positive run
  id, an empty `file`, an unknown `mode`, an invalid `hash` or a negative rate
  limit, is logged to stderr and ignored; such a `run` gets no `ended`.
- Closing stdin asks the Engine Process to end every run, save Durable State
  and exit with status 0. Kelpie waits 15 s, then kills it.

## Engine Process to Kelpie

```json
{"type": "ready", "version": "v0.1.0", "protocol": 1}
{"type": "failed", "error": {"code": "START_FAILED", "message": "listen tcp :4662: address already in use"}}
```

Exactly one of these answers `hello`; an invalid `hello` gets `failed`.
After `failed` the Engine Process exits with a non-zero status. Kelpie waits
30 s for the answer; then it kills the Engine Process and fails with
`START_FAILED`.

```json
{"type": "progress", "run": 1, "hash": "31D6CFE0D16AE931B73C59D7E0C089C0", "size": 2048,
 "received": 1024, "downloadRate": 512, "uploadRate": 0, "uploaded": 0,
 "peers": 12, "activePeers": 3}
{"type": "ended", "run": 1, "error": null}
{"type": "network", "isServerConnected": true, "isHighId": false,
 "isKadFirewalled": true, "kadNodes": 812, "isBehindCarrierNat": false}
```

- The first `progress` of a run is sent as soon as the run is admitted; after
  that at most one per second, and only when something changed, and once more
  before `ended` if something changed. A consumer may keep only the newest one.
- `received` counts the bytes written, verified or not. Rates are bytes per
  second. `uploaded` is the Transfer's total across all runs. `peers` counts
  the sources not known to have failed; `activePeers` those sending to us now.
- Each run gets exactly one `ended`, and no `progress` after it. A run that is
  not admitted gets `ended` with its error and no `progress`. A download run
  ends with `error: null` when the file is complete and flushed to the device
  (fsync); any run ends with `error: null` after `stop` or `remove`.
- `network` is sent after `ready` and whenever a field changes.
- `isServerConnected` is whether we are logged in to a server; `isHighId` is
  whether that server gave us a HighID, false without a server. Without Kad,
  `isKadFirewalled` is false and `kadNodes` is 0.
- `isBehindCarrierNat` means port mapping cannot give a HighID because another
  NAT, usually the carrier's, sits above the home gateway. It is true while
  `isHighId` is false, the gateway mapped our ports, and the external IPv4
  address the gateway reports is not public (100.64.0.0/10, a private range,
  or another reserved range) or differs from the address a peer or server last
  reported for us. Without a port mapping it is false: nothing tells the cases
  apart.

## Run rules

- A `download` run for a hash with Durable State resumes it. If that state
  belongs to a different `file`, or its file is gone, it is dropped and the
  download starts over at `file`.
- A `download` run fails with `OUTPUT_EXISTS` when `file` exists, is not the
  Transfer's own file, and is not an empty regular file (an empty file is a
  placeholder the caller created and is taken over).
- A `seed` run fails with `FILE_ERROR` unless `file` has the link's size. Unless
  its Durable State says the file is complete, the file is hashed first and the
  run ends with `FILE_ERROR` if it does not match the link.
- A second open run for the same hash fails with `TRANSFER_BUSY`.

## Error codes

| Code | Sent by | Meaning |
|---|---|---|
| `INVALID_LINK` | Engine Process, Kelpie | The link is not an eD2k file link |
| `OUTPUT_EXISTS` | Engine Process | `file` is occupied |
| `TRANSFER_BUSY` | Engine Process, Kelpie | Another run is open for the hash |
| `DISK_FULL` | Engine Process | No space left while writing |
| `FILE_ERROR` | Engine Process | The file cannot be read or written, is missing, or does not match the link |
| `OUTDATED` | Kelpie | The Engine Process is older than Kelpie requires |
| `START_FAILED` | Engine Process, Kelpie | The Engine Process cannot start |
| `ENGINE_EXITED` | Kelpie | The Engine Process exited while the run was open |
| `INTERNAL` | Kelpie | The Engine Process sent a code Kelpie does not know |

## Trace

One JSON line per event, appended to `traceFile`, so a restarted Engine
Process adds to the trace of the one before. While the file falls more than
65536 lines behind, further lines are dropped.

```json
{"time": 1767225600123, "hash": "31D6...", "source": "1.2.3.4:4662", "event": "found", "channel": "server"}
```

`time` is Unix milliseconds. `source` is `address:port`, `clientId@server:port`
for a LowID source behind a server, or `kad:userHash` for a firewalled Kad
source reached through its buddy.

| `event` | Extra fields |
|---|---|
| `found` | `channel`: `link`, `server`, `globalServer`, `kad`, `exchange`, `incoming` |
| `connected` | `isIpv6` |
| `failed` | `reason` |
| `queued` | `rank` |
| `slot` | |
| `received` | `bytes` (since the previous `received` for this source) |
| `closed` | `reason` |
