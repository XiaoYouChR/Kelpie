import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote


LINK_PATTERN = re.compile(r"ed2k://\|file\|([^|]+)\|(\d+)\|([0-9A-Fa-f]{32})\|(?:.*\|)?/")
CLASSES = ("hot", "medium", "rare")


@dataclass(frozen=True, slots=True)
class Link:
    text: str
    name: str
    size: int
    hash: str
    linkClass: str


@dataclass(frozen=True, slots=True)
class Setup:
    folder: Path
    stateFolder: Path
    serverMet: Path
    nodesDat: Path
    tcpPort: int
    udpPort: int
    traceFile: Path
    logFile: Path
    isProxiedEgressAllowed: bool


@dataclass(frozen=True, slots=True)
class Sample:
    received: int
    peers: int
    activePeers: int
    isComplete: bool
    network: str


class EngineUnavailable(Exception):
    pass


def parseLink(linkClass: str, text: str) -> Link:
    match = LINK_PATTERN.fullmatch(text)
    if match is None or linkClass not in CLASSES:
        raise ValueError(f"not '<{'|'.join(CLASSES)}> <ed2k file link>': {linkClass} {text}")
    return Link(text, unquote(match[1]), int(match[2]), match[3].upper(), linkClass)


def loadLinks(file: Path) -> list[Link]:
    links = []
    for line in file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            linkClass, text = line.split(maxsplit=1)
            links.append(parseLink(linkClass, text))
    return links
