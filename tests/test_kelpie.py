import asyncio
import json
from pathlib import Path

import pytest

from kelpie import Error, ErrorCode, Kelpie, Link, Network, Progress, Settings

FAKE_ENGINE = Path(__file__).with_name("fake_engine.py")
DEFAULT_SETTINGS = Settings()
HASH_A = "31D6CFE0D16AE931B73C59D7E0C089C0"
HASH_B = "0123456789ABCDEF0123456789ABCDEF"
LINK_A = Link("a.bin", 2048, HASH_A)
LINK_B = Link("b b.bin", 4096, HASH_B)


def run(coroutine) -> None:
    async def watched():
        async with asyncio.timeout(10):
            await coroutine

    asyncio.run(watched())


class Engine:
    def __init__(self, folder: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self.folder = folder
        self.log = folder / "log.jsonl"
        self.scriptFile = folder / "script.json"
        self.starts = 0
        monkeypatch.setenv("KELPIE_FAKE_SCRIPT", str(self.scriptFile))
        self.setScript({})

    def setScript(self, script: dict) -> None:
        self.scriptFile.write_text(json.dumps({"log": str(self.log), **script}))

    def buildKelpie(self, settings: Settings = DEFAULT_SETTINGS) -> Kelpie:
        def executable() -> Path:
            self.starts += 1
            return FAKE_ENGINE

        return Kelpie(executable, self.folder / "data", lambda: settings)

    def loadMessages(self, type: str | None = None) -> list[dict]:
        if not self.log.exists():
            return []
        messages = [json.loads(line) for line in self.log.read_text().splitlines()]
        return [message for message in messages if type is None or message["type"] == type]


@pytest.fixture
def engine(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Engine:
    return Engine(tmp_path, monkeypatch)


async def collect(run) -> list[Progress]:
    return [progress async for progress in run]


def test_download_reports_progress_until_complete(engine: Engine) -> None:
    engine.setScript(
        {
            "runs": {
                HASH_A: [
                    {"progress": {"received": 1024}},
                    {"progress": {"received": 2048}},
                    {"ended": None},
                ]
            }
        }
    )

    async def main():
        kelpie = engine.buildKelpie(
            Settings(port=4662, enableKad=False, serverLists=(Path("/s.met"),))
        )
        async with kelpie.runDownload(LINK_A, Path("/out/a.bin")) as current:
            assert kelpie.isActive(HASH_A)
            progress = await collect(current)
        assert not kelpie.isActive(HASH_A)
        await kelpie.close()
        assert progress[-1].received == 2048
        assert progress[-1].size == 2048

    run(main())
    (hello,) = engine.loadMessages("hello")
    assert hello["protocol"] == 1
    assert hello["dataFolder"] == str(engine.folder / "data")
    assert hello["settings"] == {
        "port": 4662,
        "enableKad": False,
        "enableUpnp": True,
        "serverLists": ["/s.met"],
        "nodeLists": [],
        "traceFile": "",
    }
    (runMessage,) = engine.loadMessages("run")
    assert runMessage["mode"] == "download"
    assert runMessage["file"] == "/out/a.bin"
    assert Link.parse(runMessage["link"]) == LINK_A
    assert engine.loadMessages("stop") == []


def test_failed_run_raises_its_error(engine: Engine) -> None:
    engine.setScript({"runs": {HASH_A: [{"ended": {"code": "DISK_FULL", "message": "no space"}}]}})

    async def main():
        kelpie = engine.buildKelpie()
        async with kelpie.runSeed(LINK_A, Path("/out/a.bin")) as current:
            with pytest.raises(Error) as raised:
                await collect(current)
        await kelpie.close()
        assert raised.value.code == ErrorCode.DISK_FULL
        assert raised.value.message == "no space"

    run(main())
    assert engine.loadMessages("run")[0]["mode"] == "seed"


def test_cancelled_run_sends_stop(engine: Engine) -> None:
    async def main():
        kelpie = engine.buildKelpie()
        hasProgress = asyncio.Event()

        async def observe():
            async with kelpie.runDownload(LINK_A, Path("/out/a.bin")) as current:
                async for _ in current:
                    hasProgress.set()

        task = asyncio.create_task(observe())
        await hasProgress.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert not kelpie.isActive(HASH_A)
        await kelpie.close()

    run(main())
    (runMessage,) = engine.loadMessages("run")
    assert engine.loadMessages("stop") == [{"type": "stop", "run": runMessage["run"]}]


def test_leaving_the_block_early_sends_stop(engine: Engine) -> None:
    async def main():
        kelpie = engine.buildKelpie()
        async with kelpie.runDownload(LINK_A, Path("/out/a.bin")) as current:
            async for _ in current:
                break
        await kelpie.close()

    run(main())
    assert len(engine.loadMessages("stop")) == 1


def test_second_run_for_the_same_hash_is_busy(engine: Engine) -> None:
    async def main():
        kelpie = engine.buildKelpie()
        async with kelpie.runDownload(LINK_A, Path("/out/a.bin")):
            with pytest.raises(Error) as raised:
                async with kelpie.runSeed(LINK_A, Path("/out/a.bin")):
                    pass
            assert raised.value.code == ErrorCode.TRANSFER_BUSY
            assert kelpie.isActive(HASH_A)
        await kelpie.close()

    run(main())
    assert len(engine.loadMessages("run")) == 1


def test_concurrent_first_runs_share_one_start(engine: Engine) -> None:
    async def main():
        kelpie = engine.buildKelpie()

        async def observe(link: Link) -> Progress:
            async with kelpie.runDownload(link, Path("/out") / link.name) as current:
                async for progress in current:
                    return progress

        first, second = await asyncio.gather(observe(LINK_A), observe(LINK_B))
        await kelpie.close()
        assert (first.hash, second.hash) == (HASH_A, HASH_B)

    run(main())
    assert engine.starts == 1
    assert len(engine.loadMessages("hello")) == 1
    runIds = [message["run"] for message in engine.loadMessages("run")]
    assert len(set(runIds)) == 2 and all(runId > 0 for runId in runIds)


@pytest.mark.parametrize("version", ["v0.1.0", "v0.2.0", "1.0.0", "dev", "garbage"])
def test_current_or_unknown_versions_are_accepted(engine: Engine, version: str) -> None:
    engine.setScript({"version": version})

    async def main():
        kelpie = engine.buildKelpie()
        async with kelpie.runDownload(LINK_A, Path("/out/a.bin")) as current:
            async for _ in current:
                break
        await kelpie.close()

    run(main())


def test_older_engine_ends_the_run_with_outdated(engine: Engine) -> None:
    engine.setScript({"version": "v0.0.9"})

    async def main():
        kelpie = engine.buildKelpie()
        async with kelpie.runDownload(LINK_A, Path("/out/a.bin")) as current:
            with pytest.raises(Error) as raised:
                await collect(current)
        assert raised.value.code == ErrorCode.OUTDATED
        assert "v0.0.9" in raised.value.message
        assert kelpie.network is None
        await kelpie.close()

    run(main())
    assert engine.loadMessages("run") == []


def test_missing_executable_ends_the_run_with_start_failed(engine: Engine) -> None:
    async def main():
        kelpie = Kelpie(lambda: engine.folder / "missing", engine.folder, Settings)
        async with kelpie.runDownload(LINK_A, Path("/out/a.bin")) as current:
            with pytest.raises(Error) as raised:
                await collect(current)
        assert raised.value.code == ErrorCode.START_FAILED
        with pytest.raises(Error) as raised:
            await kelpie.remove(HASH_A)
        assert raised.value.code == ErrorCode.START_FAILED
        await kelpie.close()

    run(main())


def test_failed_handshake_ends_the_run_with_start_failed(engine: Engine) -> None:
    engine.setScript({"failed": "listen tcp :4662: address already in use"})

    async def main():
        kelpie = engine.buildKelpie()
        async with kelpie.runDownload(LINK_A, Path("/out/a.bin")) as current:
            with pytest.raises(Error) as raised:
                await collect(current)
        assert raised.value.code == ErrorCode.START_FAILED
        assert raised.value.message == "listen tcp :4662: address already in use"

        engine.setScript({})
        async with kelpie.runDownload(LINK_A, Path("/out/a.bin")) as current:
            async for _ in current:
                break
        await kelpie.close()

    run(main())
    assert engine.starts == 2


def test_crash_during_handshake_reports_stderr(engine: Engine) -> None:
    engine.setScript({"crashOnHello": "panic: bad data folder"})

    async def main():
        kelpie = engine.buildKelpie()
        async with kelpie.runDownload(LINK_A, Path("/out/a.bin")) as current:
            with pytest.raises(Error) as raised:
                await collect(current)
        assert raised.value.code == ErrorCode.START_FAILED
        assert "panic: bad data folder" in raised.value.message

    run(main())


def test_silent_handshake_kills_the_engine_and_ends_the_run_with_start_failed(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("kelpie.kelpie.HANDSHAKE_TIMEOUT", 0.5)
    engine.setScript({"silentOnHello": True})

    async def main():
        kelpie = engine.buildKelpie()
        async with kelpie.runDownload(LINK_A, Path("/out/a.bin")) as current:
            with pytest.raises(Error) as raised:
                await collect(current)
        assert raised.value.code == ErrorCode.START_FAILED
        assert "did not answer hello within 0.5 s" in raised.value.message
        assert kelpie.network is None

    run(main())


def test_engine_exit_ends_every_open_run_and_next_call_restarts(engine: Engine) -> None:
    engine.setScript({"runs": {HASH_B: [{"crash": "panic: boom"}]}})

    async def main():
        kelpie = engine.buildKelpie()
        async with kelpie.runDownload(LINK_A, Path("/out/a.bin")) as first:
            async for _ in first:
                break
            async with kelpie.runDownload(LINK_B, Path("/out/b.bin")) as second:
                for current in (first, second):
                    with pytest.raises(Error) as raised:
                        await collect(current)
                    assert raised.value.code == ErrorCode.ENGINE_EXITED
                    assert raised.value.message == "panic: boom"
                assert kelpie.network is None
        assert engine.starts == 1

        async with kelpie.runDownload(LINK_A, Path("/out/a.bin")) as current:
            async for progress in current:
                assert progress.hash == HASH_A
                break
        await kelpie.close()

    run(main())
    assert engine.starts == 2
    assert len(engine.loadMessages("hello")) == 2


def test_update_sends_the_settings_to_the_running_engine(engine: Engine) -> None:
    settings = [Settings(downloadRateLimit=1000, uploadRateLimit=2000)]

    async def main():
        kelpie = Kelpie(lambda: FAKE_ENGINE, engine.folder / "data", lambda: settings[0])
        kelpie.update()
        await kelpie.remove(HASH_A)
        settings[0] = Settings(enableKad=False, uploadRateLimit=512)
        kelpie.update()
        await kelpie.close()

        settings[0] = Settings(port=4662)
        kelpie.update()
        await kelpie.remove(HASH_A)
        await kelpie.close()

    run(main())
    first, second = engine.loadMessages("hello")
    assert first["rateLimits"] == {"download": 1000, "upload": 2000}
    assert second["settings"]["port"] == 4662
    (update,) = engine.loadMessages("update")
    assert update["settings"]["enableKad"] is False
    assert update["rateLimits"] == {"download": 0, "upload": 512}


def test_update_during_startup_reaches_the_engine(engine: Engine) -> None:
    reads = []

    def settings() -> Settings:
        reads.append(None)
        return Settings(enableKad=len(reads) == 1)

    async def main():
        kelpie = Kelpie(lambda: FAKE_ENGINE, engine.folder / "data", settings)
        await kelpie.remove(HASH_A)
        await kelpie.close()

    run(main())
    (hello,) = engine.loadMessages("hello")
    (update,) = engine.loadMessages("update")
    assert hello["settings"]["enableKad"] is True
    assert update["settings"]["enableKad"] is False


def test_network_is_reported_while_the_engine_runs(engine: Engine) -> None:
    engine.setScript(
        {
            "network": {
                "isServerConnected": True,
                "isHighId": False,
                "isKadFirewalled": True,
                "kadNodes": 812,
                "isBehindCarrierNat": True,
            }
        }
    )

    async def main():
        kelpie = engine.buildKelpie()
        assert kelpie.network is None
        async with kelpie.runDownload(LINK_A, Path("/out/a.bin")) as current:
            async for _ in current:
                break
            assert kelpie.network == Network(
                isServerConnected=True,
                isHighId=False,
                isKadFirewalled=True,
                kadNodes=812,
                isBehindCarrierNat=True,
            )
        await kelpie.close()
        assert kelpie.network is None

    run(main())


def test_remove_starts_the_engine_and_cancels_the_open_run(engine: Engine) -> None:
    async def main():
        kelpie = engine.buildKelpie()
        await kelpie.remove(HASH_B)
        assert engine.starts == 1
        with pytest.raises(asyncio.CancelledError):
            async with kelpie.runDownload(LINK_A, Path("/out/a.bin")) as current:
                async for _ in current:
                    await kelpie.remove(HASH_A)
        await kelpie.close()

    run(main())
    assert [message["hash"] for message in engine.loadMessages("remove")] == [HASH_B, HASH_A]
    assert engine.loadMessages("stop") == []


def test_close_cancels_open_runs(engine: Engine) -> None:
    async def main():
        kelpie = engine.buildKelpie()
        with pytest.raises(asyncio.CancelledError):
            async with kelpie.runDownload(LINK_A, Path("/out/a.bin")) as current:
                async for _ in current:
                    await kelpie.close()
        assert not kelpie.isActive(HASH_A)
        assert kelpie.network is None
        await kelpie.close()

    run(main())
    assert engine.loadMessages("stop") == []


def test_close_without_a_process_does_nothing(engine: Engine) -> None:
    run(engine.buildKelpie().close())
    assert engine.starts == 0
