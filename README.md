<p align="center"><img src="docs/icon.png" width="160" alt="Kelpie"></p>

# Kelpie

Kelpie is an eD2k engine with a typed asyncio interface. The `kelpie` Engine
Process owns all eD2k protocol activity; the `kelpie` Python package starts it
when needed and exposes each download or seed as a Run.

```python
from kelpie import Kelpie, Link, Settings

kelpie = Kelpie(lambda: enginePath, dataFolder, lambda: Settings())
link = Link.parse("ed2k://|file|example.bin|2048|31D6CFE0D16AE931B73C59D7E0C089C0|/")
async with kelpie.runDownload(link, downloads / link.name) as run:
    async for progress in run:
        print(progress.received, progress.size)
```

## Build and test

```sh
go build -o build/kelpie ./cmd/kelpie
go test -race ./...
python -m pytest tests
```

See [CONTEXT.md](CONTEXT.md) for the domain language, [docs/protocol.md](docs/protocol.md)
for the Engine Process protocol, and [docs/adr](docs/adr) for decisions.

Portions of the engine are derived from goed2k; see [NOTICE](NOTICE).
