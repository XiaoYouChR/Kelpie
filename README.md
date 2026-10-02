<h4 align="right">
  English | <a href="README_zh.md">简体中文</a>
</h4>

<p align="center"><img src="docs/icon.png" width="160" alt="Kelpie"></p>

<h1 align="center">Kelpie</h1>

<p align="center">An eD2k engine that downloads as fast as eMule, behind a five-line asyncio interface.</p>

> [!NOTE]
> Kelpie is in active development; v0.1.0 is not released yet.

## Why Kelpie

- **eMule-level speed.** Kelpie speaks the parts of the protocol that decide
  real-world speed: Secure User Identification for credits, UDP reask to hold
  queue positions, LowID callbacks, Source Exchange v2, global server search,
  and a full request pipeline. The full list is in
  [ADR-0003](docs/adr/0003-own-engine-core.md).
- **A good citizen.** One server connection, eMule's request intervals, its own
  client name, and uploads while downloading — the behaviour that earns credits
  instead of bans.
- **IPv6-ready.** Addresses are dual-stack throughout; Kelpie peers exchange
  IPv6 sources with each other.

## Use it

Kelpie is two pieces: the `kelpie` Engine Process (download it from
[Releases](https://github.com/XiaoYouChR/Kelpie/releases)) and the `kelpie`
Python package (standard library only, Python 3.11+; copy the `kelpie/` folder
into your project).

```python
import asyncio
from pathlib import Path

from kelpie import Error, Kelpie, Link, Settings


async def main() -> None:
    kelpie = Kelpie(lambda: Path("build/kelpie"), Path("data"), lambda: Settings())
    link = Link.parse("ed2k://|file|example.bin|2048|31D6CFE0D16AE931B73C59D7E0C089C0|/")
    try:
        async with kelpie.runDownload(link, Path.home() / "Downloads" / link.name) as run:
            async for progress in run:
                print(f"{progress.received}/{progress.size} at {progress.downloadRate} B/s")
    except Error as error:
        print(error.code, error.message)
    finally:
        await kelpie.close()


asyncio.run(main())
```

Each `async with` block is one **Run**. The file transfers while the block is
open and stops when you leave it; `runSeed` uploads a complete file the same
way. Kelpie starts the Engine Process when you need it, and `close()` stops
it. Errors come from the Run as `kelpie.Error`. After your settings change,
`update()` applies them without ending any Run. `remove` and the `network`
property cover the rest.

[CONTEXT.md](CONTEXT.md) defines these words.
[ADR-0004](docs/adr/0004-transfers-run-only-while-observed.md) gives the reasons.

## How it fits together

```
your code ─▶ kelpie (Python) ══ stdio NDJSON ══▶ gateway ─▶ Engine ◀─▶ Kad
                                                              ▲
                              connection readers and writers, disk workers, store
```

The Engine and Kad actors own all state; everything else is a stateless leaf
that only sends them messages. [docs/protocol.md](docs/protocol.md) defines the
wire between Python and the Engine Process, and
[ADR-0005](docs/adr/0005-two-hub-actors.md) explains the actor structure.

```
Kelpie/
├── kelpie/            Python package
├── cmd/kelpie/        Engine Process entry point
├── bench/             Speed benchmark against aMule and goed2kd
└── internal/
    ├── gateway/       Messages between stdio and the Engine
    ├── engine/        Engine actor
    ├── kad/           Kad actor
    ├── peer/          Peer session state machine
    ├── transfer/      Transfer state machine
    ├── upload/        Upload queue state machine
    ├── server/        Server session state machine
    ├── wire/          Protocol codecs
    ├── obfuscation/   Protocol obfuscation for TCP and UDP
    ├── piece/         Parts, blocks, and hashing
    ├── aich/          AICH hash trees
    ├── link/          eD2k link parsing
    ├── identity/      Secure User Identification and credits
    ├── nat/           Port mapping: PCP, NAT-PMP, UPnP
    ├── transport/     Network seam, with a fake for tests
    ├── disk/          Disk seam, with a fake for tests
    ├── clock/         Clock seam, with a fake for tests
    ├── fakeserver/    eD2k server for tests
    ├── archtest/      Import rules from ADR-0005
    └── store/         Durable State, including migration from goed2k
```

## Develop

```sh
go build -o build/kelpie ./cmd/kelpie
go test -race ./...
python -m pytest tests
```

Conventions for contributors and coding agents are in [CLAUDE.md](CLAUDE.md).

## The name

eDonkey begat eMule; Kelpie keeps the family of hoofed animals going. A kelpie
is the shape-shifting water horse of Scottish legend — fitting for an engine
whose sources stream in from everywhere.

## See Also

- [Ghost Downloader](https://github.com/XiaoYouChR/Ghost-Downloader-3): the
  download manager Kelpie was built for.

## License

MIT. Portions of the engine are derived from
[goed2k](https://github.com/monkeyWie/goed2k); see [NOTICE](NOTICE).
