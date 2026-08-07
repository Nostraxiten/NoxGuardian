```
    _   __           ______                     ___
   / | / /___  _  __/ ____/_  ______ __________/ (_)___ _____
  /  |/ / __ \| |/_/ / __/ / / / __ `/ ___/ __  / / __ `/ __ \
 / /|  / /_/ />  </ /_/ / /_/ / /_/ / /  / /_/ / / /_/ / / / /
/_/ |_/\____/_/|_|\____/\__,_/\__,_/_/   \__,_/_/\__,_/_/ /_/
```

<h1 align="center">NoxGuardian</h1>

<p align="center">
  <strong>Continuous presence and port monitoring for a home LAN.</strong><br>
  Run it, forget it, press Ctrl+C, read the spreadsheet.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.9%2B-blue?style=flat-square" alt="Python 3.9+">
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="MIT License">
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20Termux-lightgrey?style=flat-square" alt="Platform">
  <img src="https://img.shields.io/badge/dependencies-openpyxl-orange?style=flat-square" alt="Dependencies">
  <img src="https://img.shields.io/badge/self--tests-142%20passing-brightgreen?style=flat-square" alt="Tests">
</p>

---

NoxGuardian answers one question, continuously and without supervision:

> **Who is on my network, when did they arrive, when did they leave, how long do
> they stay, and what ports do they have open?**

It runs from the command line on Kali Linux, any Linux, or Termux on Android.
It monitors indefinitely and stops on `Ctrl+C`, at which point it writes a
complete Excel report, a final checkpoint, and a session summary to the console.

---

## Table of Contents

- [Overview](#overview)
- [How It Works](#how-it-works)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Command Line Reference](#command-line-reference)
- [Output](#output)
- [Running Without Root](#running-without-root)
- [Vendor Resolution](#vendor-resolution)
- [Resilience](#resilience)
- [Project Layout](#project-layout)
- [Testing](#testing)
- [Field Testing Results](#field-testing-results)
- [Troubleshooting](#troubleshooting)
- [Design Notes](#design-notes)
- [License](#license)
- [Legal Notice](#legal-notice)

---

## Overview

Most network scanners give you a snapshot. NoxGuardian gives you a **timeline**.

It keeps two scan loops running at different tempos in separate threads, tracks
every unique device by MAC across DHCP lease changes, records each arrival and
departure as a discrete session, and accumulates a per-device presence
percentage over the whole run. Port scans are performed only against hosts that
the presence loop has confirmed alive, never blindly against the whole subnet.

Everything is written to disk the moment it happens. If the process is killed
without warning, the log on disk already contains everything up to that instant
and the last checkpoint is intact and resumable.

**Design constraints, deliberately kept tight:**

| Constraint | Rationale |
|---|---|
| Standard library first | One external dependency (`openpyxl`), nothing else |
| System `nmap` via `subprocess` | No wrapper libraries; XML parsed directly with `xml.etree.ElementTree`, which is stable across nmap versions |
| Fully offline vendor lookup | No API calls per MAC address, no network egress beyond the LAN scan itself |
| Survive unattended for 24h | No individual scan failure may terminate the process |

---

## How It Works

### Scan loops

Three threads run independently. The main thread waits for the stop signal.

| Loop | Default interval | Behaviour |
|---|---|---|
| **Presence** | 3 min | `nmap -sn <subnet>` ARP sweep. Returns IP, MAC, hostname and vendor for every live host. |
| **Deep scan** | 20 min | `nmap -p <4001 ports> -sV -T4 -Pn <ip>` against **only** the hosts presence confirmed alive. Records `open` ports exclusively; `filtered` and `closed` are discarded. |
| **Checkpoint** | 15 min | Atomically serialises the full state to JSON. |

The deep scan uses `-Pn` because liveness is already established; this skips
host discovery and avoids false negatives from devices that ignore ICMP. Results
are reported per host as each one finishes, not batched at the end of the cycle.

### Per-device model

Every unique MAC address accumulates:

- MAC, vendor, current IP, hostname, and the full history of IP changes
- First seen and last seen timestamps
- A list of **sessions** (arrival time, departure time, or still present)
- Arrival and departure counters
- Total time present, and presence as a percentage of total session runtime
- Per-port history: service, version reported by nmap, first seen open, last
  confirmed open, times confirmed, and every **open window**, so a port that
  opens, closes, and reopens is recorded with all three moments rather than
  just the most recent state

A device that first appears without a resolvable MAC is tracked provisionally by
IP. If its MAC is discovered later, the provisional record is **merged** into the
permanent one, preserving its history without duplicating the device or
double-counting its arrival.

---

## Installation

### Kali Linux / Debian / Ubuntu

```bash
sudo apt install -y nmap python3-openpyxl
git clone https://github.com/nostraxiten/NoxGuardian.git
cd NoxGuardian
```

### Termux (Android)

```bash
pkg install -y python nmap
pip install openpyxl
git clone https://github.com/nostraxiten/NoxGuardian.git
cd NoxGuardian
```

### As an installed package

```bash
pip install .
```

This exposes a `noxguardian` command on your `PATH`.

### Verify the environment

Before committing to a long run, confirm what NoxGuardian can and cannot do on
this machine. This scans nothing and exits immediately.

```bash
python3 -m noxguardian --check
```

```
    version         : NoxGuardian 1.0.0  (python 3.13.14)
    plataforma      : Linux
    nmap            : Nmap version 7.99 ( https://nmap.org )
    tabla OUI       : 38556 prefixes from: bundled (1479), /usr/share/nmap/nmap-mac-prefixes (38468)
    subred          : 192.168.1.0/24  [iface wlan0]
    este equipo     : 192.168.1.34  MAC aa:bb:cc:11:22:33
    metodo presencia: nmap -sn (ARP)  [root/privilegiado]
    presencia cada  : 3 min
    deep scan cada  : 20 min
    checkpoint cada : 15 min
    puertos         : 4001 puertos
```

> **Note on language.** The runtime console output, event log and Excel headers
> are in Spanish; this documentation is in English. The two are kept separate on
> purpose so that reports stay readable for their intended audience.

---

## Quick Start

```bash
sudo python3 -m noxguardian
```

Press `Ctrl+C` to stop. That single `SIGINT` triggers the ordered shutdown: it
kills any in-flight nmap process, closes open sessions, writes the final
checkpoint, generates the Excel workbook, and prints the summary. A second
`Ctrl+C` exits immediately, and the log and previous checkpoint are already
safely on disk.

**Faster tempo, custom output directory:**

```bash
sudo python3 -m noxguardian --presence-interval 2 --deepscan-interval 15 --output-dir ~/watch
```

**Fixed subnet, narrower port range:**

```bash
sudo python3 -m noxguardian --subnet 192.168.1.0/24 --ports 1-1024,8080,8443
```

**Continue a previous session:**

```bash
sudo python3 -m noxguardian --resume --output-dir ~/watch
```

On resume, accumulated runtime, counters and the complete device history
continue where they left off. Nobody is assumed present until the first
presence cycle reconfirms them, so a device connected both before and after the
pause records **two arrivals**. These are two genuine stays, separated by the
interval during which NoxGuardian was not watching.

---

## Command Line Reference

### Scan tempo

| Flag | Default | Description |
|---|---|---|
| `--presence-interval MIN` | `3` | Minutes between presence sweeps |
| `--deepscan-interval MIN` | `20` | Minutes between deep port scans |
| `--checkpoint-interval MIN` | `15` | Minutes between JSON checkpoints |

### Scan scope

| Flag | Default | Description |
|---|---|---|
| `--ports SPEC` | 4001 ports | nmap port syntax, e.g. `1-1024,8080,9000-9100` |
| `--subnet CIDR` | auto-detected | Manual override, e.g. `192.168.1.0/24` |
| `--no-deepscan` | off | Presence only, no port scanning |
| `--deepscan-workers N` | `2` | Hosts scanned concurrently in the deep cycle |
| `--absence-cycles N` | `2` | Consecutive missed sweeps before a device counts as gone |
| `--force-fallback` | off | Force the TCP sweep even when running as root |
| `--presence-timeout SEC` | `300` | Timeout for one presence sweep |
| `--deepscan-timeout SEC` | `900` | Timeout for scanning a single host |

### Output and persistence

| Flag | Default | Description |
|---|---|---|
| `--output-dir DIR` | `noxguardian_out` | Destination for log, checkpoints and Excel |
| `--resume` | off | Resume from the checkpoint in `--output-dir` |
| `--excel-on-checkpoint` | off | Also write an Excel file at every checkpoint |
| `--oui-file FILE` | — | Additional OUI table to merge |
| `--no-system-oui` | off | Use only the bundled OUI table |
| `-v`, `--verbose` | off | Echo every event to the console |

### Information

| Flag | Description |
|---|---|
| `--check` | Report environment capabilities and exit |
| `--list-ports` | Print the resolved port specification and exit |
| `--version` | Print version and exit |

---

## Output

### Directory layout

```
noxguardian_out/
├── noxguardian_events.log             Human-readable log, append-only
├── noxguardian_state.json             Checkpoint, used by --resume
└── noxguardian_report_<stamp>.xlsx    Final report
```

### Event log

Every relevant event is written **immediately**, with `flush` followed by
`fsync`. There is no buffer to lose.

```
2026-08-07 18:42:11 [+] DEVICE_JOIN   192.168.1.34 [aa:bb:cc:11:22:33] rpi.local :: ENTRA en la red: 192.168.1.34 (Raspberry Pi Foundation) hostname=rpi.local [aparicion #1]
2026-08-07 18:45:13 [*] SCAN           :: escaneo de presencia #2: 7 dispositivos activos, 7 con MAC, 2.8s (nmap -sn (barrido ARP))
2026-08-07 19:02:44 [!] PORT_OPEN     192.168.1.34 [aa:bb:cc:11:22:33] :: PUERTO NUEVO tcp/22 abierto en 192.168.1.34 -> ssh OpenSSH 9.2p1
2026-08-07 20:15:02 [-] DEVICE_LEAVE  192.168.1.51 [dd:ee:ff:44:55:66] :: SALE de la red: 192.168.1.51 (Apple) tras 1h 33m 12s [salida #1]
```

| Marker | Event |
|---|---|
| `[+]` | Device joined |
| `[-]` | Device left |
| `[!]` | New or reopened port |
| `[x]` | Port no longer open |
| `[~]` | IP address changed |
| `[*]` | Scan cycle completed |
| `[S]` | Checkpoint saved |
| `[E]` | Error |

The log is written **in arrival order**, and each entry carries the real time at
which the event occurred. Because presence and port scanning run on separate
threads, and a deep scan can take minutes, an event from a long-running scan may
appear after a more recent presence event. Results are flushed as soon as each
individual host finishes, not at the end of the cycle. For a strictly
chronological sequence, use the **Timeline** sheet in the workbook, which is
sorted by timestamp.

### Excel workbook

Four sheets, styled with frozen headers, autofilters and column formatting.

**1. Resumen** — one row per device, sorted by presence percentage descending.
This is the "who spends the most time in the house" ranking. Columns include
MAC, vendor, last IP, hostname, first and last seen, arrival and departure
counts, time present, presence percentage rendered as a data bar, ports seen and
ports currently open. Rows are tinted according to whether the device was still
present at shutdown.

**2. Timeline** — one row per arrival or departure event, in chronological
order, with the device's identity resolved at report time.

**3. Puertos** — one row per `(device, port)` pair: protocol, port, service,
the version string nmap reported, first seen open, last confirmed open, times
confirmed, whether it is currently open, and a readable summary of every open
window. Only ports that were open at some point appear here.

**4. Estadisticas** — session duration, scans performed of each type, failure
counts, unique devices, maximum and mean concurrent devices, and the devices
with the most arrivals, the most open ports, and the longest total presence. The
full effective configuration of the run is appended, so a report is
self-documenting.

---

## Running Without Root

An ARP sweep requires raw sockets. At startup NoxGuardian checks for root and
for `cap_net_raw` on the nmap binary. If neither is available it **states so
clearly on the console and in the log**, then degrades to a method that works
unprivileged:

- **TCP connect sweep** using standard-library sockets against fifteen common
  ports, in parallel across the subnet. A connection that returns `ACK` **or**
  `RST` (`ECONNREFUSED`) proves the host exists, so devices with everything
  closed are still detected.
- **MAC recovery from `/proc/net/arp`**, which is readable without root on Linux
  and Android and is typically fresh immediately after contacting the host.
  Anything that cannot be resolved is reported as `no disponible`. The field is
  marked as unavailable rather than guessed, and the scan does not fail.

If neither `nmap` nor `ip` is present at all, subnet detection falls back to
parsing `/proc/net/route` directly, and port scanning is disabled with an
explicit warning. Presence monitoring continues to work.

---

## Vendor Resolution

Fully offline. No API is contacted for lookups. Sources are merged in order of
increasing precedence:

1. **The bundled table** — `noxguardian/data/oui_prefixes.csv`, roughly 1,500
   curated prefixes covering vendors common on home networks.
2. **System databases**, when present — `/usr/share/nmap/nmap-mac-prefixes`,
   `/usr/share/wireshark/manuf`, `/usr/share/ieee-data/oui.txt`. On Kali all
   three exist, bringing the table to well over 38,000 prefixes.
3. **`--oui-file`**, if supplied.

All three on-disk formats are parsed, including their differing field
separators.

**Randomised MAC addresses** — those with the locally-administered bit set,
which iOS, Android and Windows use for privacy — are identified as such rather
than attributed to a fabricated vendor.

To regenerate the bundled table from a machine that has the full system
databases, which is useful before deploying to a minimal Termux install:

```bash
python3 tools/build_oui.py
```

---

## Resilience

Built to survive 24 hours unattended.

- **No individual scan failure terminates the process.** Every error is caught,
  written to the log, and the loop continues.
- **A presence cycle that fails entirely does not make everyone disappear.**
  With no results, absence is not evaluated for any device.
- **`--absence-cycles 2` by default.** Phones in power-save routinely miss ARP
  sweeps; requiring two consecutive misses prevents the timeline from filling
  with phantom arrivals and departures. Set it to `1` for immediate reporting.
- **Sessions close at the last real confirmation**, not at the moment absence
  was detected, so presence percentages are not inflated by the detection lag.
- **A host that does not answer a deep scan is not declared gone.** It is logged
  as a possible departure and left for the next presence cycle to confirm.
- **Per-host timeouts** in the deep scan; one slow host cannot block the cycle.
- **Checkpoints are written atomically** — temporary file, `fsync`, then
  `os.replace`. A power cut mid-write leaves either the previous checkpoint
  intact or the new one complete, never a corrupt file.
- **The workbook is built entirely in memory and saved in one operation.** It is
  either complete or absent, never truncated.
- If a scan thread dies unexpectedly, the failure is logged and **the remaining
  threads keep monitoring**.

---

## Project Layout

```
NoxGuardian/
├── noxguardian.py                  Direct launcher
├── pyproject.toml                  Packaging and console entry point
├── requirements.txt
├── noxguardian/
│   ├── cli.py                      Argument parsing, SIGINT/SIGTERM handling
│   ├── engine.py                   Thread orchestration and ordered shutdown
│   ├── config.py                   Effective session configuration
│   ├── state.py                    Data model and thread-safe state manager
│   ├── netinfo.py                  Subnet, interface, privileges, ARP table
│   ├── oui.py                      Offline vendor resolution
│   ├── ports_profile.py            4001-port profile and spec utilities
│   ├── data/oui_prefixes.csv       Bundled OUI table
│   ├── scanners/
│   │   ├── nmap_runner.py          subprocess execution and XML parsing
│   │   ├── presence.py             ARP sweep and unprivileged TCP fallback
│   │   └── ports.py                Per-host deep scan
│   └── exporters/
│       ├── txtlog.py               Immediate append-only log
│       ├── checkpoint.py           Atomic JSON persistence
│       └── excel.py                Four-sheet report
└── tools/
    ├── selftest.py                 142 checks, no network required
    └── build_oui.py                Regenerate the bundled OUI table
```

---

## Testing

```bash
python3 tools/selftest.py
```

142 assertions, none of which touch the network. The suite simulates a full
session — devices arriving and leaving, a presence cycle that fails entirely,
ports opening and closing and reopening, a DHCP address change, and a
provisional IP-keyed record being merged when its MAC is revealed — then
performs a checkpoint round trip and verifies the generated workbook cell by
cell. It also covers the OUI parsers for all three on-disk formats, the
`/proc/net/route` subnet detection path, and the port specification utilities.

To keep the generated artefacts for inspection:

```bash
python3 tools/selftest.py --keep ./testout
```

---

## Field Testing Results

Version 1.0.0 was validated against a live network on Kali Linux 6.19
with nmap 7.99, across six monitored sessions:

| Scenario | Result |
|---|---|
| Privileged ARP sweep | Ten devices tracked across arrivals and departures; `SIGINT` produced a complete workbook in two seconds, killing the in-flight nmap process |
| Unprivileged TCP fallback | Nine devices detected, with every MAC recovered from `/proc/net/arp` without root |
| Full 4001-port profile | Cycle completed in 19.8 seconds; found a UPnP service on port 49152 that a `1-1024` range does not reach |
| `--resume` | Accumulated runtime, scan counters and device history continued correctly across a restart |
| `SIGKILL` | Log intact, checkpoint valid and parseable, session successfully resumed from a dead process |
| No `nmap`, no `ip` on `PATH` | Subnet detected via `/proc/net/route`; both limitations reported at startup |

Seven defects were found and fixed during this testing. See
[CHANGELOG.md](CHANGELOG.md) for the details.

Not yet validated: a real Termux installation, and a continuous run longer than
a few hours.

---

## Troubleshooting

**No Excel file is produced.**
`openpyxl` is missing. NoxGuardian warns about this at startup precisely so that
you find out before, not after, a long run. The log and checkpoint are still
written. Install with `pip install openpyxl` or `apt install python3-openpyxl`.

**Every MAC address shows as `no disponible`.**
You are running unprivileged and the kernel ARP cache is not yielding entries.
Run with `sudo`, or grant the capability directly:

```bash
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)
```

**Devices constantly appear and disappear.**
Power-saving devices miss sweeps. Raise `--absence-cycles` to `3`, or lengthen
`--presence-interval`.

**Cycles are very slow.**
Check the detected subnet in `--check`. A mask wider than `/22` produces a very
large address space; narrow it with `--subnet`. Reducing `--ports` also helps
significantly, since `-sV` version probing dominates the deep scan.

**Subnet auto-detection fails.**
Pass it explicitly: `--subnet 192.168.1.0/24`.

---

## Design Notes

A few decisions that are deliberate rather than accidental:

**Timestamps are epoch floats everywhere.** Formatting to human-readable text
happens only at the output layer. This makes serialisation trivial and duration
arithmetic exact.

**Each host in a deep scan is timestamped when that host finished**, not when
the cycle began. A cycle can span minutes, and dating its events from the start
would both disorder the log and falsify every port's `first_seen`.

**Departure times use the last successful observation.** Using the detection
moment would credit each device with an extra `absence_cycles × interval` of
presence it did not have.

**The absence threshold defaults to 2 rather than 1.** This deviates from the
most literal reading of "detect when they leave", and it is the right trade:
with a threshold of one, a home network's presence ranking is dominated by
noise from sleeping phones.

**nmap is never given the whole subnet for port scanning.** The deep loop only
ever receives the list of IPs that the presence loop confirmed alive in that
cycle.

---

## License

Released under the [MIT License](LICENSE).

---

## Legal Notice

Scan only networks you own or have explicit written authorisation to assess.
Port scanning third-party networks is illegal in most jurisdictions. This tool
performs active scanning: it is not passive, and it is not stealthy. The authors
accept no liability for misuse.
