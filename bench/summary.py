"""Summarize run.py CSVs per engine and link.

    python bench/summary.py bench/results/*.csv [--links bench/links.txt]

The links file supplies each hash's size, to tell whether a run completed.
For Kelpie, `<csv stem>.<HASH>.trace.jsonl` next to the CSV adds per-channel
source counts and per-stage attrition (docs/protocol.md, Trace).
"""

import argparse
import csv
import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from models import loadLinks


BENCH_FOLDER = Path(__file__).resolve().parent
CHECKPOINTS = (5, 30)
STAGES = ("found", "connected", "queued", "slot", "received")


@dataclass(frozen=True, slots=True)
class Row:
    elapsed: float
    received: int
    peers: int


def loadRuns(files: list[Path]) -> dict[tuple[str, str, str, Path], list[Row]]:
    runs: dict[tuple[str, str, str, Path], list[Row]] = defaultdict(list)
    for file in files:
        with file.open(newline="") as handle:
            for record in csv.DictReader(handle):
                key = (record["engine"], record["class"], record["hash"], file)
                runs[key].append(Row(float(record["elapsed_s"]), int(record["received_bytes"]),
                                     int(record["peers"])))
    return runs


def toPeersAt(rows: list[Row], minutes: int, isComplete: bool) -> str:
    seconds = minutes * 60
    if isComplete and rows[-1].elapsed < seconds:
        return "done"
    reached = [row for row in rows if row.elapsed <= seconds + 1]
    return str(reached[-1].peers) if reached and rows[-1].elapsed >= seconds - 1 else "-"


def toFirstByte(rows: list[Row]) -> str:
    return next((f"{row.elapsed:.0f}s" for row in rows if row.received > 0), "never")


def loadTrace(file: Path) -> tuple[dict[str, int], dict[str, int]]:
    channels: dict[str, set[str]] = defaultdict(set)
    stages: dict[str, set[str]] = defaultdict(set)
    for line in file.read_text(encoding="utf-8").splitlines():
        event = json.loads(line)
        source, kind = event["source"], event["event"]
        if kind == "found":
            channels[event["channel"]].add(source)
            channels["any"].add(source)
        if kind in STAGES and (kind != "received" or event.get("bytes", 0) > 0):
            stages[kind].add(source)
    return ({name: len(sources) for name, sources in sorted(channels.items())},
            {stage: len(stages[stage]) for stage in STAGES})


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("files", nargs="+", type=Path)
    parser.add_argument("--links", type=Path, default=BENCH_FOLDER / "links.txt")
    arguments = parser.parse_args()
    sizes = {link.hash: link.size for link in loadLinks(arguments.links)}

    header = ("engine", "class", "hash", "first byte", "peers@5m", "peers@30m", "avg KiB/s",
              "completed", "file")
    print("{:<8} {:<6} {:<32} {:>10} {:>8} {:>9} {:>9} {:>9}  {}".format(*header))
    for (engine, linkClass, hash, file), rows in loadRuns(arguments.files).items():
        last = rows[-1]
        size = sizes.get(hash)
        isComplete = size is not None and last.received >= size
        completed = "?" if size is None else ("yes" if isComplete else "no")
        rate = last.received / last.elapsed / 1024 if last.elapsed else 0
        peers = [toPeersAt(rows, minutes, isComplete) for minutes in CHECKPOINTS]
        print(f"{engine:<8} {linkClass:<6} {hash:<32} {toFirstByte(rows):>10} {peers[0]:>8} "
              f"{peers[1]:>9} {rate:>9.1f} {completed:>9}  {file.name}")
        trace = file.with_name(f"{file.stem}.{hash}.trace.jsonl")
        if engine == "kelpie" and trace.exists():
            channels, stages = loadTrace(trace)
            print("    sources by channel: " + " ".join(f"{k}={v}" for k, v in channels.items()))
            print("    attrition: " + " -> ".join(f"{k}={v}" for k, v in stages.items()))


if __name__ == "__main__":
    main()
