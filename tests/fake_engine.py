#!/usr/bin/env python3
"""A scripted stand-in for the Engine Process.

KELPIE_FAKE_SCRIPT names a JSON file:
  version           ready.version (default "v0.2.0")
  failed            answer hello with `failed` and this message, then exit 1
  crashOnHello      write this line to stderr and exit 2 without answering hello
  silentOnHello     never answer hello
  network           sent after ready
  log               every received message is appended to this file as a JSON line
  runs              {hash: [step, ...]}; a step is {"progress": {...}}, {"ended": error|null}
                    or {"crash": "stderr line"}. Runs for other hashes report one progress
                    and stay open. Every run stays open after its steps until stopped.
"""

import json
import os
import sys
import time


def send(message):
    sys.stdout.write(json.dumps(message) + "\n")
    sys.stdout.flush()


def crash(line, status):
    sys.stderr.write(line + "\n")
    sys.stderr.flush()
    sys.exit(status)


def buildProgress(runId, hash, size, fields):
    return {
        "type": "progress",
        "run": runId,
        "hash": hash,
        "size": size,
        "received": 0,
        "downloadRate": 0,
        "uploadRate": 0,
        "uploaded": 0,
        "peers": 0,
        "activePeers": 0,
        "heldSources": 0,
        "heldUntil": 0,
        "sources": [],
        "unknownField": True,
        **fields,
    }


def main():
    with open(os.environ["KELPIE_FAKE_SCRIPT"]) as file:
        script = json.load(file)
    openRuns = {}
    sys.stderr.write("fake engine starting\n")
    sys.stderr.flush()
    for line in sys.stdin:
        message = json.loads(line)
        if "log" in script:
            with open(script["log"], "a") as log:
                log.write(json.dumps(message) + "\n")
        match message["type"]:
            case "hello":
                if "crashOnHello" in script:
                    crash(script["crashOnHello"], 2)
                if script.get("silentOnHello"):
                    time.sleep(3600)
                if "failed" in script:
                    send(
                        {
                            "type": "failed",
                            "error": {"code": "START_FAILED", "message": script["failed"]},
                        }
                    )
                    sys.exit(1)
                send({"type": "ready", "version": script.get("version", "v0.2.0"), "protocol": 1})
                if "network" in script:
                    send({"type": "network", **script["network"]})
            case "run":
                runId = message["run"]
                _, _, _, size, hash, _ = message["link"].split("|")
                steps = script.get("runs", {}).get(hash, [{"progress": {}}])
                openRuns[runId] = hash
                for step in steps:
                    if "progress" in step:
                        send(buildProgress(runId, hash, int(size), step["progress"]))
                    elif "ended" in step:
                        send({"type": "ended", "run": runId, "error": step["ended"]})
                        del openRuns[runId]
                        break
                    elif "crash" in step:
                        crash(step["crash"], 3)
            case "stop":
                if openRuns.pop(message["run"], None) is not None:
                    send({"type": "ended", "run": message["run"], "error": None})
            case "remove":
                for runId, hash in list(openRuns.items()):
                    if hash == message["hash"]:
                        del openRuns[runId]
                        send({"type": "ended", "run": runId, "error": None})
    sys.exit(0)


main()
