import asyncio
import os
import shutil
import sys
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path

from models import EngineUnavailable, Link, Sample, Setup


REPO_FOLDER = Path(__file__).resolve().parents[2]


def findExecutable() -> Path:
    for candidate in (os.environ.get("KELPIE_EXECUTABLE"), REPO_FOLDER / "bench" / "bin" / "kelpie",
                      shutil.which("kelpie")):
        if candidate and Path(candidate).is_file():
            return Path(candidate)
    raise EngineUnavailable(
        "no kelpie executable: build it with `go build -o bench/bin/kelpie ./cmd/kelpie` "
        "or set KELPIE_EXECUTABLE")


@asynccontextmanager
async def start(link: Link, setup: Setup) -> AsyncIterator[Callable[[], Awaitable[Sample]]]:
    sys.path.insert(0, str(REPO_FOLDER))
    try:
        import kelpie
    except ImportError as error:
        raise EngineUnavailable(f"the kelpie package cannot be imported: {error}") from error
    executable = findExecutable()
    settings = kelpie.Settings(
        port=setup.tcpPort,
        enableKad=True,
        enableUpnp=True,
        serverLists=(setup.serverMet,),
        nodeLists=(setup.nodesDat,),
        traceFile=setup.traceFile,
    )
    engine = kelpie.Kelpie(lambda: executable, setup.stateFolder, lambda: settings)
    latest = Sample(received=0, peers=0, activePeers=0, isComplete=False, network="starting")
    try:
        async with engine.runDownload(kelpie.Link.parse(link.text), setup.folder / link.name) as run:

            async def supervise() -> None:
                nonlocal latest
                async for progress in run:
                    latest = Sample(progress.received, progress.peers, progress.activePeers, False, "")
                latest = Sample(link.size, latest.peers, latest.activePeers, True, "")

            supervising = asyncio.create_task(supervise())

            async def probe() -> Sample:
                if supervising.done():
                    supervising.result()
                network = engine.network
                return Sample(
                    latest.received, latest.peers, latest.activePeers, latest.isComplete,
                    network=("" if network is None else
                             f"server={network.isServerConnected} highId={network.isHighId} "
                             f"kadFirewalled={network.isKadFirewalled} kadNodes={network.kadNodes}"),
                )

            try:
                yield probe
            finally:
                supervising.cancel()
        await engine.remove(link.hash)
    finally:
        await engine.close()
