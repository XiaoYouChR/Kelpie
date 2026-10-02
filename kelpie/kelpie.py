import asyncio
import json
import logging
import re
from collections import deque
from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .errors import Error, ErrorCode
from .models import Link, Network, Progress, Settings

PROTOCOL = 1
MIN_ENGINE_VERSION = (0, 1, 0)
CLOSE_TIMEOUT = 15
HANDSHAKE_TIMEOUT = 30
STREAM_LIMIT = 4 * 1024 * 1024
VERSION_PATTERN = re.compile(r"v?(\d+)\.(\d+)\.(\d+)")

logger = logging.getLogger(__name__)


class Run:
    def __init__(self, id: int) -> None:
        self.id = id
        self._progress: Progress | None = None
        self._isEnded = False
        self._error: BaseException | None = None
        self._changed = asyncio.Event()

    async def __aiter__(self) -> AsyncIterator[Progress]:
        while True:
            await self._changed.wait()
            self._changed.clear()
            progress, self._progress = self._progress, None
            if progress is not None:
                yield progress
            if self._isEnded:
                if self._error is not None:
                    raise self._error
                return

    def setProgress(self, progress: Progress) -> None:
        if self._isEnded:
            return
        self._progress = progress
        self._changed.set()

    def setEnded(self, error: BaseException | None) -> None:
        if self._isEnded:
            return
        self._isEnded = True
        self._error = error
        self._changed.set()

    def cancel(self) -> None:
        # Ended by someone other than its caller: a normal end would read as a
        # finished download, so the caller sees a cancellation instead.
        if not self._isEnded:
            self._progress = None
            self.setEnded(asyncio.CancelledError())


@dataclass
class EngineProcess:
    process: asyncio.subprocess.Process
    routes: dict[int, Run] = field(default_factory=dict)
    network: Network | None = None


class Kelpie:
    def __init__(
        self,
        executable: Callable[[], Path],
        dataFolder: Path,
        settings: Callable[[], Settings],
    ) -> None:
        self._executable = executable
        self._dataFolder = dataFolder
        self._settings = settings
        self._engine: EngineProcess | None = None
        self._starting: asyncio.Task[None] | None = None
        self._runs: dict[str, Run] = {}
        self._nextRunId = 1
        self._tasks: set[asyncio.Task[None]] = set()

    @property
    def network(self) -> Network | None:
        return self._engine.network if self._engine is not None else None

    def runDownload(self, link: Link, file: Path) -> AbstractAsyncContextManager[Run]:
        return self._run("download", link, file)

    def runSeed(self, link: Link, file: Path) -> AbstractAsyncContextManager[Run]:
        return self._run("seed", link, file)

    def update(self) -> None:
        if self._engine is not None:
            send(self._engine.process, {"type": "update", **buildSettings(self._settings())})

    def isActive(self, hash: str) -> bool:
        return hash in self._runs

    async def remove(self, hash: str) -> None:
        run = self._runs.get(hash)
        engine = self._engine
        if run is not None and engine is not None and engine.routes.pop(run.id, None) is not None:
            run.cancel()
        await self._start()
        if self._engine is not None:
            send(self._engine.process, {"type": "remove", "hash": hash})

    async def close(self) -> None:
        if self._starting is not None:
            try:
                await asyncio.shield(self._starting)
            except Error:
                pass
        engine = self._engine
        if engine is None:
            return
        self._engine = None
        for run in engine.routes.values():
            run.cancel()
        process = engine.process
        process.stdin.close()
        try:
            async with asyncio.timeout(CLOSE_TIMEOUT):
                await process.wait()
        except TimeoutError:
            process.kill()
            await process.wait()
        await asyncio.gather(*self._tasks)

    @asynccontextmanager
    async def _run(self, mode: str, link: Link, file: Path) -> AsyncIterator[Run]:
        if link.hash in self._runs:
            raise Error(ErrorCode.TRANSFER_BUSY, f"a Run is already open for {link.hash}")
        run = Run(self._nextRunId)
        self._nextRunId += 1
        self._runs[link.hash] = run
        try:
            try:
                await self._start()
            except Error as error:
                run.setEnded(error)
            else:
                if self._engine is None:
                    run.setEnded(Error(ErrorCode.ENGINE_EXITED, "Engine Process exited"))
                else:
                    self._engine.routes[run.id] = run
                    send(
                        self._engine.process,
                        {
                            "type": "run",
                            "run": run.id,
                            "mode": mode,
                            "link": str(link),
                            "file": str(file),
                        },
                    )
            yield run
        finally:
            del self._runs[link.hash]
            engine = self._engine
            if engine is not None and engine.routes.pop(run.id, None) is not None:
                send(engine.process, {"type": "stop", "run": run.id})

    async def _start(self) -> None:
        if self._engine is not None:
            return
        if self._starting is None:
            self._starting = asyncio.create_task(self._createProcess())
        await asyncio.shield(self._starting)

    async def _createProcess(self) -> None:
        try:
            executable = self._executable()
            settings = self._settings()
            try:
                process = await asyncio.create_subprocess_exec(
                    executable,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    limit=STREAM_LIMIT,
                )
            except OSError as error:
                raise Error(
                    ErrorCode.START_FAILED, f"cannot start {executable}: {error}"
                ) from error
            send(process, buildHello(self._dataFolder, settings))
            ready: asyncio.Future[None] = asyncio.get_running_loop().create_future()
            task = asyncio.create_task(self._supervise(process, ready))
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)
            await ready
            # An update() during the handshake found no Engine Process.
            if self._settings() != settings:
                self.update()
        finally:
            self._starting = None

    async def _supervise(
        self, process: asyncio.subprocess.Process, ready: asyncio.Future[None]
    ) -> None:
        stderr: deque[str] = deque(maxlen=20)
        stderrTask = asyncio.create_task(refreshStderr(process, stderr))
        engine = EngineProcess(process)
        try:
            async with asyncio.timeout(HANDSHAKE_TIMEOUT):
                line = await process.stdout.readline()
        except TimeoutError:
            process.kill()
            line = b""
            failure = Error(
                ErrorCode.START_FAILED,
                f"Engine Process did not answer hello within {HANDSHAKE_TIMEOUT} s",
            )
        else:
            failure = parseHandshake(line) if line else None
        isReady = bool(line) and failure is None
        if isReady:
            self._engine = engine
            ready.set_result(None)
            while line := await process.stdout.readline():
                onMessage(engine, line)
        elif failure is not None:
            process.stdin.close()
        await stderrTask
        exitCode = await process.wait()
        lastLine = stderr[-1] if stderr else f"exit code {exitCode}"
        if not isReady:
            ready.set_exception(
                failure
                or Error(
                    ErrorCode.START_FAILED, f"Engine Process exited during startup: {lastLine}"
                )
            )
            return
        if self._engine is engine:
            self._engine = None
        exited = Error(ErrorCode.ENGINE_EXITED, lastLine)
        for run in engine.routes.values():
            run.setEnded(exited)


def onMessage(engine: EngineProcess, line: bytes) -> None:
    try:
        message = json.loads(line)
        match message.get("type"):
            case "progress":
                run = engine.routes.get(message["run"])
                if run is not None:
                    run.setProgress(parseProgress(message))
            case "ended":
                run = engine.routes.pop(message["run"], None)
                if run is not None:
                    run.setEnded(parseError(message["error"]))
            case "network":
                engine.network = parseNetwork(message)
    except (ValueError, KeyError, TypeError, AttributeError) as error:
        logger.warning("ignored invalid Engine Process message %r: %s", line, error)


def send(process: asyncio.subprocess.Process, message: dict[str, Any]) -> None:
    process.stdin.write(json.dumps(message, separators=(",", ":")).encode() + b"\n")


def buildHello(dataFolder: Path, settings: Settings) -> dict[str, Any]:
    return {
        "type": "hello",
        "protocol": PROTOCOL,
        "dataFolder": str(dataFolder),
        **buildSettings(settings),
    }


def buildSettings(settings: Settings) -> dict[str, Any]:
    return {
        "settings": {
            "port": settings.port,
            "enableKad": settings.enableKad,
            "enableUpnp": settings.enableUpnp,
            "serverLists": [str(path) for path in settings.serverLists],
            "nodeLists": [str(path) for path in settings.nodeLists],
            "traceFile": str(settings.traceFile) if settings.traceFile is not None else "",
        },
        "rateLimits": {"download": settings.downloadRateLimit, "upload": settings.uploadRateLimit},
    }


def parseHandshake(line: bytes) -> Error | None:
    try:
        message = json.loads(line)
        if message["type"] == "failed":
            return Error(ErrorCode.START_FAILED, message["error"]["message"])
        if message["type"] != "ready":
            return Error(ErrorCode.START_FAILED, f"unexpected handshake: {line!r}")
        version = message["version"]
    except (ValueError, KeyError, TypeError) as error:
        return Error(ErrorCode.START_FAILED, f"invalid handshake {line!r}: {error}")
    if matchOutdated(version):
        required = ".".join(map(str, MIN_ENGINE_VERSION))
        return Error(ErrorCode.OUTDATED, f"Engine Process {version} is older than v{required}")
    return None


def matchOutdated(version: str) -> bool:
    parsed = VERSION_PATTERN.match(version)
    return parsed is not None and tuple(map(int, parsed.groups())) < MIN_ENGINE_VERSION


def parseProgress(message: dict[str, Any]) -> Progress:
    return Progress(
        hash=message["hash"],
        size=message["size"],
        received=message["received"],
        downloadRate=message["downloadRate"],
        uploadRate=message["uploadRate"],
        uploaded=message["uploaded"],
        peers=message["peers"],
        activePeers=message["activePeers"],
    )


def parseNetwork(message: dict[str, Any]) -> Network:
    return Network(
        isServerConnected=message["isServerConnected"],
        isHighId=message["isHighId"],
        isKadFirewalled=message["isKadFirewalled"],
        kadNodes=message["kadNodes"],
        isBehindCarrierNat=message["isBehindCarrierNat"],
    )


def parseError(error: dict[str, Any] | None) -> Error | None:
    if error is None:
        return None
    try:
        code = ErrorCode(error["code"])
    except ValueError:
        code = ErrorCode.INTERNAL
    return Error(code, error["message"])


async def refreshStderr(process: asyncio.subprocess.Process, lines: deque[str]) -> None:
    while line := await process.stderr.readline():
        lines.append(line.decode(errors="replace").rstrip())
