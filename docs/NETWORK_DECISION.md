# Network monitoring: Zeek evaluation and decision (Phase 3, Task 5)

Status: **decision recorded; nothing installed; no Docker networking changed.**
Date of evaluation: 2026-11-07. Every number below was measured on the development machine or taken from the
cited Zeek documentation on that date.

## 1. The question

ThreatScope already accepts events with `source=network`. Module 5 asks whether to
1. implement a Zeek integration,
2. implement a simpler network-log adapter, or
3. defer network monitoring to future scope,

without inventing a monitor that fabricates events.

## 2. What the environment really offers (measured)

| Fact | Value | Why it matters |
|---|---|---|
| Host OS | Windows 11 Home, Docker Desktop (engine 29.9.2) with the **WSL2** backend (kernel 6.18.54.1-microsoft-standard-WSL2) | Containers run inside a Linux VM, not on the Windows network stack |
| Docker VM resources | 12 CPUs, 8.2 GB RAM | Enough for Zeek on a pcap |
| Host RAM | 15.7 GB total, about 3 GB free at check time | Tight; Zeek must not run permanently |
| **Disk C:** | **about 1.6 GB free** of 225 GB | **Blocking risk, see section 5** |
| Docker data file | `C:\Users\<user>\AppData\Local\Docker\wsl\disk\docker_data.vhdx`, 25.7 GB | Lives on C:. Any image pull grows it |
| Docker usage | images 9.6 GB, build cache 13.1 GB (8.5 GB reclaimable), volumes 0.6 GB | Free space exists *inside* the VM but not on C: |
| Disk F: | 215 GB free | Project and data files are here |
| Capture tools on the host | no Wireshark, tshark, dumpcap; Npcap present; `pktmon.exe` present (needs admin) | A pcap can be captured, with effort |
| Docker networks | `threascope_default` (bridge) plus other projects' networks | A sensor on it would only see container-to-container traffic |
| Other containers | `juice-shop` is published on `0.0.0.0:3000` (all interfaces) | Not part of ThreatScope; see the note in section 8 |

Past incident (Phase 2, Task 2): C: filled during an image pull and corrupted a local Docker image layer. The same
drive is nearly full again.

## 3. What Zeek can do here (from Zeek's own documentation)

| Topic | Finding | Source |
|---|---|---|
| Windows support | "Experimental support"; "Our testing has focused on pcap file processing, and we don't yet have much practical experience with real-time packet capture." The v7.0 install page also contains the sentence "This version of libpcap does not support packet capture on Windows, unlike other platforms" (its exact scope was not checked). | zeek.org/2022/11/zeek-on-windows ; docs.zeek.org install page |
| Docker | Official image `zeek/zeek`: Debian-based, stock install in `/usr/local/zeek`, **no entrypoint, does not run Zeek automatically**. Compressed size measured from the registry manifest: **165 MB** (6 layers, amd64). | hub.docker.com/r/zeek/zeek ; `docker manifest inspect` (no pull) |
| Offline mode | `zeek -r file.pcap` reads a capture and writes logs to the current directory. | docs.zeek.org/en/current/tutorial/logs.html |
| JSON logs | `zeek -r file.pcap LogAscii::use_json=T` writes one JSON object per line. Default is tab-separated text. | same page, quick-start guide |
| `conn.log` | One row per connection: `ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p, proto, service, duration, orig_bytes, resp_bytes, conn_state, ...` | same page |
| Detections | Zeek logs *metadata*. Detections are **notices** (`notice.log`) raised by scripts. Scan detection (`Scan::Port_Scan`, `Scan::Address_Scan`) is in `policy/misc/scan.zeek`, a policy script that must be loaded. | docs.zeek.org/en/v6.0.9/scripts/policy/misc/scan.zeek.html |
| Licence | BSD-style (Regents of the University of California / LBNL / ICSI). Compatible with GPL-3.0; we would not redistribute it. | github.com/zeek/zeek COPYING |

Consequences:
* **Live capture is not available.** Windows capture is untested upstream, and Docker Desktop containers cannot see the
  Windows network card. A Zeek container on `threascope_default` would see only ThreatScope's own backend-to-database
  traffic. Seeing more would require changing Docker networking, which is out of scope.
* **Offline pcap analysis is the supported, reproducible path.** It needs no network change.
* A `conn.log` row is not a security event on its own. Turning rows into "attacks" would mean inventing detection rules.
  Zeek's own notices are real detections made by Zeek's scripts.

## 4. Options compared

| Criterion | 1. Zeek, offline pcap + notice adapter | 2. "Simpler network-log adapter" | 3. Defer |
|---|---|---|---|
| Windows / Docker Desktop fit | Works as a one-shot container reading a mounted pcap | n/a (needs a log source, see below) | n/a |
| Resources | 165 MB download; runs for seconds, then exits | negligible | none |
| Install complexity | `docker pull zeek/zeek` plus one `docker run` per pcap | none, but no data source | none |
| Network visibility | Whatever the pcap contains (recorded traffic; honest, but historic) | see below | none |
| Log format | Documented JSON lines; stable | depends on the source | n/a |
| Integration effort | Small adapter (about the size of the ModSecurity one) | small, but see below | none |
| Demonstration value | Good if the pcap holds a real scan or brute force: ThreatScope shows a Zeek-detected event | low | none, but nothing false is shown |
| Main risk | Disk space on C:, finding a real pcap, time | Fabrication risk (below) | Fewer features in the demo |

Why option 2 was rejected: there is no honest simple source in this environment. A Windows Firewall log would need
administrator rights to enable and read, lives under `System32`, and mostly records broadcast noise, so labelling its rows as
attacks would be inventing detections. Writing our own pcap parser would be a hand-made Zeek with our own invented rules.

Why option 3 was not chosen outright: option 1 is feasible, small on the ThreatScope side, and produces real detections,
provided the conditions in section 5 are met.

## 5. Decision

**Option 1, restricted to offline mode: Zeek reads a recorded capture in a throw-away container, writes JSON logs, and a
ThreatScope adapter turns Zeek's own notices into `network` events through the normal API.**
No live capture, no sensor on any Docker network, no changes to `docker-compose.yml`.

This decision is **conditional**. It becomes work only if all three conditions are met; otherwise the answer is option 3
(defer), and nothing else in Phase 3 depends on it.

| # | Condition | Why it needs your approval |
|---|---|---|
| G1 | **Free space on C: is made safe before any pull.** Recommended: prune only Docker's *build cache* (8.5 GB reclaimable inside the VM, so the pull reuses space the VM already owns and the file on C: does not grow). Not touched: images, containers, volumes, the database. | It deletes data (cache) on your machine, and C: is nearly full |
| G2 | **Approval to `docker pull zeek/zeek`** (165 MB compressed) | "Install Zeek" was reserved until this decision was written |
| G3 | **A pcap with real detections.** Choose one: (a) a capture you provide, (b) a capture of your own test traffic made with `pktmon` (administrator), (c) a harmless public sample trace that contains a scan or brute force | Without a detection-bearing capture there is nothing honest to show |

If G1 is refused, option 3 applies. A pull without G1 risks repeating the Phase 2 disk incident.

## 6. Planned adapter (design only, nothing written yet)

* Input: a directory or file of Zeek JSON `notice.log` (one object per line), read-only, with the same `--state`,
  `--max-events` and `--dry-run` behaviour as the ModSecurity adapter and the same hostile-input limits.
* Mapping: `ts` becomes `occurred_at`; `id.orig_h` or `src` becomes `source_ip`; `id.resp_h` or `dst` becomes
  `destination_ip` (the API counts it as an indicator for `network` events); `note` becomes `event_type` (lower-cased,
  for example `scan_port_scan`); `msg` is shortened into the description; `uid`, `proto`, ports and `note` go to metadata.
* Severity: from a small fixed table by notice type (scans: medium; unknown notices: low). Never above medium, because a
  notice is a detection, not a verified compromise. The description and metadata say so.
* Duplicates: `external_event_id` from the notice's `uid`, `note` and `ts`, so re-reading a log is harmless.
* Not converted: plain `conn.log`, `dns.log` and `http.log` rows. They are context, not detections. A later step could
  add explicit, documented rules; this task will not invent any.
* Privacy: no packet payloads exist in these logs; URLs and hostnames in `msg` are limited and cleaned like the other
  adapters.
* Tests: written against real Zeek output produced in G2/G3, plus hostile-input cases. No fabricated "network" events.

Planned run recipe (not executed):

```
docker run --rm -v "<dir with capture>:/in:ro" -v "<empty output dir>:/out" zeek/zeek \
    sh -c "cd /out && zeek -C -r /in/capture.pcap LogAscii::use_json=T local"
docker compose exec backend python -m integrations.zeek_adapter /path/to/notice.log --state ... --dry-run
```
(`-C` ignores checksums, which captures taken on the sending host often get wrong. `local` loads the site policy; whether it
enables scan detection must be checked on the installed version, otherwise the scan script is loaded explicitly.)

## 7. What is explicitly not being done

* No live capture, no promiscuous sensor, no change to Docker networks or published ports.
* No Zeek installed on Windows or in WSL. No deletion of images, volumes, the database or demo events.
* No events generated without a real capture behind them.

## 8. Side notes found during the evaluation

* **C: has about 1.6 GB free.** Besides Docker, this can break builds, tests and temporary files. Freeing space is advisable
  whatever is decided here.
* `juice-shop` (a deliberately vulnerable web application, not part of ThreatScope) is published on `0.0.0.0:3000`, meaning
  every network interface. ThreatScope's own ports are bound to `127.0.0.1` only. If that container is not needed, publishing it
  on `127.0.0.1:3000` or stopping it would be safer. It was not touched.

## 9. Approval needed to continue

Reply with the gates you approve (G1, G2, G3 and which pcap source). With all three, the next step is "Task 5b": pull the
image, run Zeek on the capture, inspect the real logs, then build and test the adapter. Without G1, network monitoring stays
deferred and Phase 3 moves to Task 6.
