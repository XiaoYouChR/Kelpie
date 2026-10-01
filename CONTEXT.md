# Domain Context

## Kelpie

The Python entry point used by one application event loop. It owns one Engine
Process, starting it when first needed and again after it exits, and hides
process creation, the version handshake, and message routing.

Kelpie does not own product tasks, retry policy, UI state, or the eD2k protocol
state. It uses the caller's running asyncio loop and never changes the
event-loop policy.

_Avoid_: Client, wrapper

## Engine Process

The `kelpie` executable. It owns all eD2k protocol activity for the
application. It knows nothing about the caller's task model or user interface.
When it exits unexpectedly, every open Run fails; Kelpie never restarts it on
its own.

_Avoid_: daemon, sidecar

## Transfer

One eD2k file identified by its hash, together with its Durable State: resume
data and the total bytes uploaded. A Transfer runs only while a Run observes
it; whether it runs is never persisted, and nothing resumes it at startup.

## Run

One observation of a Transfer, opened by the caller as a download or a seed
and closed by the caller. Its outcome is the Transfer's state: while open it
reports Progress; a download Run ends on its own when the file is complete; a
failed Run ends with an Error; closing it stops the Transfer. A Transfer has at
most one open Run.

_Avoid_: session, job, watch

## Progress

The latest observable facts about a running Transfer. Progress is not a
history: a slow consumer only sees the newest value. The end of a Run is never
coalesced away.

## Error

Why a Run failed, as a code and a message. It is the only way a failure
reaches the caller, and it always arrives through the Run.

## Settings

The startup settings the caller chooses: port, Kad, UPnP, and the local server
list and node list files. Kelpie reads them again each time it starts the
Engine Process.

## Rate Limit

A session-wide cap on download or upload bytes per second; 0 means unlimited.
It counts every byte on peer connections, protocol overhead included, so the
observed rate never exceeds it. Server and Kad traffic is not limited. Rate
Limits change while running and survive Engine Process restarts.

## Network

Whether a server connection is established, whether the server gave a HighID
(other peers can connect to us) or a LowID, whether Kad sees us as firewalled,
and how many Kad nodes are known, as last reported. It is absent while no
Engine Process runs.

## Durable State

Protocol state owned and persisted by the Engine Process: identity, credits,
Kad nodes, and each Transfer's Durable State. The caller chooses its parent
folder but does not read, write, or interpret its contents.
