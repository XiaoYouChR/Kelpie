# eMule baseline (manual, Windows)

eMule has no headless mode or scriptable interface, so its run is recorded by
hand into a CSV with the same columns as `run.py`, which `summary.py` then
reads like any other run.

## Setup, once per link

1. Use eMule 0.50a or the current eMule Community release, unpacked as a
   portable install into a new folder, so every link starts with a fresh
   identity, empty credits and no known files (the cold start the other
   engines get).
2. Before the first start, copy `bench/lists/server.met` and
   `bench/lists/nodes.dat` into the install's `config` folder.
3. Start eMule, then in Options:
   - Connection: Download and Upload limits unlimited; Client port TCP 4662,
     UDP 4672; "Use UPnP to set up ports" on (goed2kd and Kelpie use UPnP);
     Networks: eD2K and Kad both on; Autoconnect and Reconnect on.
   - Server: turn off "Update server list when connecting to a server" and
     "... when a client connects", so the server list stays the shared one.
   - Leave everything else, including Security > Protocol Obfuscation, at
     eMule's defaults.
4. The machine must reach eD2k directly, not through a proxy. With Clash on
   Windows, turn TUN mode off or add a `PROCESS-NAME,emule.exe,DIRECT` rule.
   Check: `curl --noproxy * http://portquiz.net:4662` from the same machine
   prints the ISP address, and eMule's log shows the server connection.
5. Note whether the server gave a HighID or LowID and whether Kad is open or
   firewalled; put them in the results commit message.

## Recording

1. Close eMule, restart it, and start a stopwatch the moment eMule's window
   appears (this is the cold start `elapsed_s` counts from).
2. Paste the link from `bench/links.txt` into the Downloads search box
   (or eMule's "ed2k Links" field) right away.
3. Add the Downloads list columns Completed (bytes), Sources and Transferring
   if they are hidden. Record a row at first byte (the first time Completed is
   above 0) and at 1, 2, 5, 10, 15, 20, 25 and 30 minutes, or when the file
   completes. A screen recording of the Downloads list, read afterwards, is
   easier than reading live.
4. Stop at 30 minutes, close eMule, delete the install folder and the
   downloaded data.

One CSV per sitting, named `bench/results/<timestamp>-emule.csv`:

```
engine,class,hash,elapsed_s,received_bytes,rate_bps,peers,active_peers
emule,hot,3D366ED505B977FC61C9A6EE01E96329,18,1048576,0,12,3
```

- `received_bytes`: the Completed column converted to bytes.
- `rate_bps`: leave 0; `summary.py` derives the average rate from
  `received_bytes` and `elapsed_s`.
- `peers`: the Sources column; `active_peers`: Transferring.

Then `python bench/summary.py bench/results/*.csv` lists eMule beside the
other engines. Its time to first byte is as precise as the stopwatch; the
other engines sample every 5 s.
