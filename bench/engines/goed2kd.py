import platform
import urllib.request
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path

from models import Link, Sample, Setup
from vendor.python_ed2k import Client, Settings, TransferState


VERSION = "v0.2.4"
RELEASE_URL = "https://github.com/XiaoYouChR/Python-eD2k/releases/download"
BIN_FOLDER = Path(__file__).resolve().parent.parent / "bin"


def installBinary() -> Path:
    system = platform.system().lower()
    machine = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine(), platform.machine())
    asset = f"goed2kd-{system}-{machine}" + (".exe" if system == "windows" else "")
    file = BIN_FOLDER / f"{VERSION}-{asset}"
    if not file.exists():
        BIN_FOLDER.mkdir(parents=True, exist_ok=True)
        partial = file.with_suffix(".partial")
        urllib.request.urlretrieve(f"{RELEASE_URL}/{VERSION}/{asset}", partial)
        partial.chmod(0o755)
        partial.rename(file)
    return file


@asynccontextmanager
async def start(link: Link, setup: Setup) -> AsyncIterator[Callable[[], Awaitable[Sample]]]:
    client = Client(installBinary(), setup.folder / "state")
    await client.start(Settings(
        serverMetSource=str(setup.serverMet),
        nodesDatSource=str(setup.nodesDat),
        listenPort=setup.tcpPort,
        udpPort=setup.udpPort,
        enableDht=True,
        enableUpnp=True,
    ))
    try:
        await client.addLink(link.text, setup.folder / "download")

        async def probe() -> Sample:
            snapshot = await client.snapshot()
            transfer = next(t for t in snapshot.transfers if t.hash.upper() == link.hash)
            return Sample(
                received=transfer.received,
                peers=transfer.peers,
                activePeers=transfer.activePeers,
                isComplete=transfer.state == TransferState.FINISHED,
                network=f"server={snapshot.serverConnected} kadNodes={snapshot.kadNodes}",
            )

        yield probe
    finally:
        await client.close()
