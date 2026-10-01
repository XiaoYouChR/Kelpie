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

- `port` is used for TCP and UDP; 0 picks a free port.
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
- Closing stdin asks the Engine Process to save Durable State and exit with
  status 0.

## Engine Process to Kelpie

```json
{"type": "ready", "version": "v0.1.0", "protocol": 1}
{"type": "failed", "error": {"code": "START_FAILED", "message": "listen tcp :4662: address already in use"}}
```

Exactly one of these answers `hello`. After `failed` the Engine Process exits
with a non-zero status.

```json
{"type": "progress", "run": 1, "hash": "31D6CFE0D16AE931B73C59D7E0C089C0", "size": 2048,
 "received": 1024, "downloadRate": 512, "uploadRate": 0, "uploaded": 0,
 "peers": 12, "activePeers": 3}
{"type": "ended", "run": 1, "error": null}
{"type": "network", "isServerConnected": true, "isHighId": false,
 "isKadFirewalled": true, "kadNodes": 812}
```

- The first `progress` of a run is sent as soon as the run is admitted; after
  that at most one per second, and only when something changed. A consumer
  may keep only the newest one.
- `uploaded` is the Transfer's total across all runs.
- Each run gets exactly one `ended`, and no `progress` after it. A download run
  ends with `error: null` when the file is complete; any run ends with
  `error: null` after `stop` or `remove`.
- `network` is sent after `ready` and whenever a field changes.

## Run rules

- A `download` run for a hash with Durable State resumes it. If that state
  belongs to a different `file`, it is dropped and the download starts over at
  the new path.
- A `download` run fails with `OUTPUT_EXISTS` when `file` exists, is not the
  Transfer's own file, and is not an empty regular file (an empty file is a
  placeholder the caller created and is taken over).
- A `seed` run fails with `FILE_ERROR` unless `file` is complete for that hash.
- A second open run for the same hash fails with `TRANSFER_BUSY`.

## Error codes

| Code | Sent by | Meaning |
|---|---|---|
| `INVALID_LINK` | Engine Process, Kelpie | The link is not an eD2k file link |
| `OUTPUT_EXISTS` | Engine Process | `file` is occupied |
| `TRANSFER_BUSY` | Kelpie, Engine Process | Another run is open for the hash |
| `DISK_FULL` | Engine Process | No space left while writing |
| `FILE_ERROR` | Engine Process | The file cannot be read or written, or is missing |
| `OUTDATED` | Kelpie | The Engine Process is older than Kelpie requires |
| `START_FAILED` | Engine Process, Kelpie | The Engine Process cannot start |
| `ENGINE_EXITED` | Kelpie | The Engine Process exited while the run was open |
| `INTERNAL` | Engine Process | A bug |

## Trace

One JSON line per event, appended to `traceFile`:

```json
{"time": 1767225600123, "hash": "31D6...", "source": "1.2.3.4:4662", "event": "found", "channel": "server"}
```

| `event` | Extra fields |
|---|---|
| `found` | `channel`: `link`, `server`, `globalServer`, `kad`, `exchange`, `incoming` |
| `connected` | `isIpv6` |
| `failed` | `reason` |
| `queued` | `rank` |
| `slot` | |
| `received` | `bytes` (since the previous `received` for this source) |
| `closed` | `reason` |
