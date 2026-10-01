"""Download each link with one engine and record a sample every 5 s.

    python bench/run.py --engine goed2kd|amule|kelpie --minutes 30 \
        --links bench/links.txt --out bench/results/<timestamp>-<engine>.csv

Links run one after another, each from a cold start in a fresh data folder
that is deleted afterwards; never run two engines at once, they would compete
for bandwidth. Only the engine's identity survives between runs, in
work/<engine>-state: aMule and eMule ban an IP for two hours when the client
on its port comes back with another user hash, so a fresh identity per run
gets every source seen before refused. elapsed_s counts from the engine's cold start, so time to first
byte includes connecting to servers and Kad. Next to the CSV each link leaves
`<csv stem>.<HASH>.log` (aMule) and `<csv stem>.<HASH>.trace.jsonl` (Kelpie).

bench/lists/server.met merges the three server.met files Ghost Downloader
fetches by default (emule-security, shortypower, gruk); bench/lists/nodes.dat
is emule-security's nodes.dat. Both were fetched on 2026-10-01.
"""

import argparse
import asyncio
import csv
import importlib
import shutil
import socket
import sys
import time
from pathlib import Path

from models import EngineUnavailable, Link, Setup, loadLinks


BENCH_FOLDER = Path(__file__).resolve().parent
SAMPLE_SECONDS = 5
TCP_PORT = 4662
UDP_PORT = 4672
PORT_WAIT_SECONDS = 300
COLUMNS = ["engine", "class", "hash", "elapsed_s", "received_bytes", "rate_bps", "peers",
           "active_peers"]


def matchPortsFree(tcpPort: int, udpPort: int) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp, \
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            tcp.bind(("0.0.0.0", tcpPort))
            udp.bind(("0.0.0.0", udpPort))
        return True
    except OSError:
        return False


async def runLink(engine: str, link: Link, setup: Setup, minutes: float, writer: csv.writer) -> None:
    started = time.monotonic()
    adapter = importlib.import_module(f"engines.{engine}")
    async with adapter.start(link, setup) as probe:
        lastElapsed, lastReceived = 0.0, 0
        tick = 1
        while True:
            await asyncio.sleep(max(0.0, started + tick * SAMPLE_SECONDS - time.monotonic()))
            tick += 1
            sample = await probe()
            elapsed = time.monotonic() - started
            rate = (sample.received - lastReceived) / (elapsed - lastElapsed)
            lastElapsed, lastReceived = elapsed, sample.received
            writer.writerow([engine, link.linkClass, link.hash, f"{elapsed:.1f}", sample.received,
                             round(rate), sample.peers, sample.activePeers])
            print(f"{elapsed:7.1f}s {sample.received:>12} B {rate / 1024:9.1f} KiB/s "
                  f"peers={sample.peers} active={sample.activePeers} {sample.network}", flush=True)
            if sample.isComplete or elapsed >= minutes * 60:
                return


async def run(arguments: argparse.Namespace) -> int:
    links = loadLinks(arguments.links)[:arguments.count]
    out: Path = arguments.out
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(COLUMNS)
        for link in links:
            print(f"== {arguments.engine} {link.linkClass} {link.hash} {link.name}", flush=True)
            setup = Setup(
                folder=BENCH_FOLDER / "work" / f"{arguments.engine}-{link.hash}",
                stateFolder=BENCH_FOLDER / "work" / f"{arguments.engine}-state",
                serverMet=BENCH_FOLDER / "lists" / "server.met",
                nodesDat=BENCH_FOLDER / "lists" / "nodes.dat",
                tcpPort=TCP_PORT,
                udpPort=UDP_PORT,
                traceFile=out.with_name(f"{out.stem}.{link.hash}.trace.jsonl").resolve(),
                logFile=out.with_name(f"{out.stem}.{link.hash}.log").resolve(),
                isProxiedEgressAllowed=arguments.allow_proxied_egress,
            )
            # OrbStack keeps a removed container's UDP flows bound on the host for a minute or two.
            deadline = time.monotonic() + PORT_WAIT_SECONDS
            while not matchPortsFree(TCP_PORT, UDP_PORT):
                if time.monotonic() > deadline:
                    print(f"ports {TCP_PORT}/tcp and {UDP_PORT}/udp stay busy", flush=True)
                    return 2
                await asyncio.sleep(5)
            shutil.rmtree(setup.folder, ignore_errors=True)
            setup.folder.mkdir(parents=True)
            try:
                await runLink(arguments.engine, link, setup, arguments.minutes, writer)
            except EngineUnavailable as error:
                print(f"skipped {arguments.engine}: {error}", flush=True)
                return 2
            except Exception as error:
                print(f"failed {link.hash}: {type(error).__name__}: {error}", flush=True)
            finally:
                file.flush()
                shutil.rmtree(setup.folder, ignore_errors=True)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--engine", required=True, choices=["goed2kd", "amule", "kelpie"])
    parser.add_argument("--minutes", type=float, default=30)
    parser.add_argument("--links", type=Path, default=BENCH_FOLDER / "links.txt")
    parser.add_argument("--count", type=int, help="run only the first COUNT links")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--allow-proxied-egress", action="store_true",
                        help="let aMule run when its container traffic goes through a proxy "
                             "(smoke tests only: the numbers are not comparable)")
    return asyncio.run(run(parser.parse_args()))


if __name__ == "__main__":
    sys.exit(main())
