import asyncio
import hashlib
import http.cookiejar
import json
import re
import shutil
import socket
import subprocess
import urllib.error
import urllib.request
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path

from models import EngineUnavailable, Link, Sample, Setup


IMAGE = "ngosang/amule@sha256:3f57ba34afa28f6c4bfc8871fcb70ece57771738e69bcc3a30a9a82ce8716a1d"
CONTAINER = "kelpie-bench-amule"
PASSWORD = "bench"
API_PORT = 4711
API_URL = f"http://127.0.0.1:{API_PORT}/api/v1"
EGRESS_PROBE = ("portquiz.net", 4662)
READY_TIMEOUT = 90

# Keys left out keep aMule's built-in defaults (obfuscation, queue sizes,
# connection limits), which is what a user who installs aMule gets.
AMULE_CONF = """[eMule]
Nick=kelpie-bench
MaxUpload=0
MaxDownload=0
Port={tcpPort}
UDPPort={udpPort}
UDPEnable=1
Autoconnect=1
Reconnect=1
ConnectToKad=1
ConnectToED2K=1
Serverlist=0
AddServerListFromServer=0
AddServerListFromClient=0
UPnPEnabled=0
IPFilterAutoLoad=0
NewVersionCheck=0
GeoIPEnabled=0
CreateSparseFiles=1
AllocateFullFile=0
TempDir=/work/temp
IncomingDir=/work/incoming
[ExternalConnect]
AcceptExternalConnections=1
ECAddress=127.0.0.1
ECPort=4712
ECPassword={ecPassword}
[WebServer]
Enabled=0
"""

AMULEAPI_CONF = f"""[Server]
BindAddress=0.0.0.0
Port={API_PORT}
[EC]
Host=127.0.0.1
Port=4712
Password={PASSWORD}
Encryption=1
"""


def runDocker(*args: str) -> str:
    try:
        result = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=600)
    except FileNotFoundError as error:
        raise EngineUnavailable("docker is not installed") from error
    if result.returncode != 0:
        raise EngineUnavailable(f"docker {args[0]} failed: {result.stderr.strip()}")
    return result.stdout


def parseEgressIp(page: str) -> str:
    match = re.search(r"Your IP: ([0-9a-fA-F.:]+)", page)
    return match[1] if match else ""


def fetchHostPage() -> str:
    host, port = EGRESS_PROBE
    with socket.create_connection(EGRESS_PROBE, timeout=10) as connection:
        connection.sendall(f"GET / HTTP/1.0\r\nHost: {host}:{port}\r\n\r\n".encode())
        return b"".join(iter(lambda: connection.recv(65536), b"")).decode(errors="replace")


def fetchContainerPage() -> str:
    host, port = EGRESS_PROBE
    return runDocker("exec", CONTAINER, "curl", "-s", "-m", "10", f"http://{host}:{port}/")


def probeEgress(isProxiedAllowed: bool) -> str:
    hostIp = parseEgressIp(fetchHostPage())
    containerIp = parseEgressIp(fetchContainerPage())
    if hostIp == containerIp:
        return f"egress=direct({hostIp})"
    message = (
        f"container TCP leaves through {containerIp or '?'} but the host goes direct through "
        f"{hostIp or '?'}: OrbStack forwards container traffic to the macOS proxy. Run "
        "`orb config set network_proxy none` for the aMule run and restore it with "
        "`orb config set network_proxy auto` afterwards"
    )
    if not isProxiedAllowed:
        raise EngineUnavailable(message)
    print(f"WARNING: {message}", flush=True)
    return f"egress=proxied({containerIp})"


def buildOpener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
    )


def request(opener: urllib.request.OpenerDirector, method: str, path: str, body: object = None) -> dict:
    data = None if body is None else json.dumps(body).encode()
    call = urllib.request.Request(f"{API_URL}/{path}", data=data, method=method,
                                  headers={"Content-Type": "application/json"})
    with opener.open(call, timeout=15) as response:
        return json.loads(response.read() or b"{}")


async def startApi(opener: urllib.request.OpenerDirector) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + READY_TIMEOUT
    while subprocess.run(["docker", "exec", CONTAINER, "amulecmd", "-P", PASSWORD, "-c", "status"],
                         capture_output=True).returncode != 0:
        if loop.time() > deadline:
            raise EngineUnavailable("amuled did not accept External Connections")
        await asyncio.sleep(1)
    runDocker("exec", CONTAINER, "amuleapi", "--config-dir=/work/conf", "--no-log-file",
              f"--set-admin-pass={PASSWORD}")
    runDocker("exec", "-d", CONTAINER, "amuleapi", "--config-dir=/work/conf", "--no-log-file")
    while True:
        try:
            request(opener, "POST", "auth/login", {"password": PASSWORD})
            return
        except (urllib.error.URLError, ConnectionError):
            if loop.time() > deadline:
                raise EngineUnavailable("amuleapi did not come up")
            await asyncio.sleep(1)


def buildNetwork(status: dict, egress: str) -> str:
    ed2k, kad = status.get("ed2k", {}), status.get("kad", {})
    return (f"server={ed2k.get('state')} highId={ed2k.get('high_id')} "
            f"kad={kad.get('state')} kadFirewalled={kad.get('firewalled_tcp')} "
            f"kadNodes={kad.get('network', {}).get('node_count')} {egress}")


@asynccontextmanager
async def start(link: Link, setup: Setup) -> AsyncIterator[Callable[[], Awaitable[Sample]]]:
    conf = setup.folder / "conf"
    for folder in (conf, setup.folder / "temp", setup.folder / "incoming"):
        folder.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(setup.serverMet, conf / "server.met")
    shutil.copyfile(setup.nodesDat, conf / "nodes.dat")
    (conf / "amule.conf").write_text(AMULE_CONF.format(
        tcpPort=setup.tcpPort,
        udpPort=setup.udpPort,
        ecPassword=hashlib.md5(PASSWORD.encode()).hexdigest(),
    ))
    (conf / "amuleapi.conf").write_text(AMULEAPI_CONF)
    (conf / "amuleapi.conf").chmod(0o600)

    subprocess.run(["docker", "rm", "-f", CONTAINER], capture_output=True)
    runDocker(
        "run", "-d", "--name", CONTAINER,
        "-p", f"{setup.tcpPort}:{setup.tcpPort}/tcp",
        "-p", f"{setup.udpPort}:{setup.udpPort}/udp",
        "-p", f"127.0.0.1:{API_PORT}:{API_PORT}/tcp",
        "-v", f"{setup.folder}:/work",
        "--entrypoint", "amuled", IMAGE, "-c", "/work/conf", "-o",
    )
    try:
        egress = probeEgress(setup.isProxiedEgressAllowed)
        opener = buildOpener()
        await startApi(opener)
        request(opener, "POST", "downloads", {"links": [link.text]})

        async def probe() -> Sample:
            download = request(opener, "GET", f"downloads/{link.hash.lower()}")
            status = request(opener, "GET", "status")
            return Sample(
                received=download["completed_bytes"],
                peers=download["sources"]["total"],
                activePeers=download["sources"]["transferring"],
                isComplete=download["status"] == "completed" or download["completed_bytes"] >= link.size,
                network=buildNetwork(status, egress),
            )

        yield probe
    finally:
        setup.logFile.write_text(
            subprocess.run(["docker", "logs", CONTAINER], capture_output=True, text=True).stdout)
        subprocess.run(["docker", "rm", "-f", CONTAINER], capture_output=True)
