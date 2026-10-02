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

## Link

An eD2k file link: name, size, and hash. It names the file a Run is about;
the Run's own file path decides where it is written.

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
coalesced away. Besides counts and rates, it lists the sources that tell why a
download is as fast as it is: each with its address, Software, Source Status,
queue rank, rate, and Channel.

## Error

Why a Run failed, as a code and a message. It is the only way a failure
reaches the caller, and it always arrives through the Run.

## Source

A peer that may have parts of a Transfer's file, as a link, a server, Kad,
another peer, or the peer itself announced it.
Sources are not Durable State. When a download Run ends, the Engine Process
keeps its sources for an hour, for the next Run of the file, which goes on
asking each when it is due instead of waiting for a server or Kad to find
them again; `remove` drops them. This keeps no Transfer running.

## Channel

Where a source was first found: the link, a server, Kad, another peer's
Source Exchange, or the source itself connecting to us (incoming).

## Software

The client and version a peer names in its Hello, such as "eMule 0.70b" or
"aMule 2.3.3"; empty when it names none.

_Avoid_: client (a client is the peer itself), agent

## Source Status

What a listed source is doing for a download now: transferring (sending to
us), queued (we wait in its upload queue, at the rank it last told),
connecting (being reached, or connected and not yet answering our file
request), or held (a Held Source). A source in none of these is only known
and is not listed.

## Held Source

A source that is due to be asked again but waits, because asking it now
could get us banned for asking too often. A peer counts a request that comes
within about ten minutes of the one before against us and refuses us once
there are too many; the Engine Process keeps its own count for each source,
asks a source that was sending at once when its download is resumed, and
holds it only when that count is near the limit, until the request would no
longer count. Progress tells how many sources are held and when the first
may be asked.

## Settings

What the caller chooses: port, Kad, port mapping on the home gateway, the
local server list and node list files, an optional trace file, and the Rate
Limits. Kelpie reads them each time it starts the Engine Process, and again
when the caller asks it to update: Kad, port mapping, and the Rate Limits
then change at once without ending any Run; the others wait for the next
start.

## Rate Limit

A cap on download or upload bytes per second across all Transfers; 0 means
unlimited. It counts every byte on peer connections, protocol overhead
included, so the observed rate never exceeds it unless protocol messages
alone do: outgoing ones are sent at once, ahead of file data, which waits
longer for the bytes they took. Server traffic, including a server's
connection that checks whether peers can reach us, Kad, and other UDP traffic
is not limited.

## Network

Whether a server connection is established, whether the server gave a HighID
(other peers can connect to us) or a LowID, whether Kad sees us as firewalled,
how many Kad nodes are known, and whether a carrier NAT keeps us from a HighID.
Kelpie hands each change to the caller, whether or not a Run is open, and
hands it None when the Engine Process goes away.

## Durable State

Protocol state owned and persisted by the Engine Process: identity, credits,
Kad identity and nodes, what it learned about the listed servers, and each
Transfer's Durable State. The caller chooses its folder but does not read,
write, or interpret its contents.
