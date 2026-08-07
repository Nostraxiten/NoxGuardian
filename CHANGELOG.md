# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-08-07

First release.

### Added

- **Presence loop** — `nmap -sn` ARP sweep on a configurable interval, default
  three minutes, reporting IP, MAC, hostname and vendor for every live host.
- **Deep scan loop** — `nmap -p <4001 ports> -sV -T4 -Pn` on a configurable
  interval, default twenty minutes, run only against hosts the presence loop
  confirmed alive. Records `open` ports exclusively.
- **Automatic subnet detection** with four fallback strategies: the default
  route via `ip route` and `ip addr`, `ip route` scope-link entries,
  `/proc/net/route` parsed directly, and `ifconfig`. A UDP socket probe assuming
  `/24` is the last resort. Overridable with `--subnet`.
- **Privilege detection** for root and for `cap_net_raw` on the nmap binary,
  with an unprivileged fallback: a parallel TCP connect sweep that treats both
  `ACK` and `RST` as proof of life, plus best-effort MAC recovery from
  `/proc/net/arp`. Unresolvable MACs are reported as unavailable rather than
  guessed.
- **Offline vendor resolution** from a bundled table of roughly 1,500 curated
  prefixes, merged with the system databases when present
  (`nmap-mac-prefixes`, Wireshark `manuf`, IEEE `oui.txt`) and with any file
  given via `--oui-file`. Locally-administered MAC addresses are identified as
  randomised rather than attributed to a vendor.
- **Per-device model** tracking sessions, arrival and departure counters, total
  presence time, presence percentage, IP change history, and full per-port
  history including every open window.
- **Immediate append-only text log** with `flush` and `fsync` on every entry.
- **Atomic JSON checkpoints** written via temporary file, `fsync` and
  `os.replace`, with `--resume` to continue a previous session.
- **Excel report** with four sheets: Resumen, Timeline, Puertos and
  Estadisticas, including a presence ranking with data bars, conditional row
  tinting, frozen headers and autofilters.
- **Ordered shutdown on SIGINT and SIGTERM**: in-flight nmap processes are
  killed, open sessions closed, a final checkpoint written, the workbook
  generated and a summary printed. A second signal exits immediately.
- **`--check`** to report environment capabilities without scanning anything.
- **`tools/selftest.py`** with 142 assertions that require no network access.
- **`tools/build_oui.py`** to regenerate the bundled OUI table from system
  databases.

### Fixed during field testing

Seven defects were found while validating against a live network and were
fixed before release:

- The OUI parser dropped the first word of vendor names from
  `nmap-mac-prefixes`, rendering `Sagemcom Broadband SAS` as
  `Broadband SAS`. The nmap and Wireshark formats differ in their field
  separator and are now handled separately.
- The monitoring host reported its own MAC address as unavailable, since a
  machine does not ARP itself. It is now read from sysfs.
- A host that left the network between the presence cycle and the deep scan was
  counted as a scan failure. nmap omits the `<host>` element entirely in this
  case; it is now correctly recorded as a possible departure awaiting
  confirmation.
- Deep scan events were timestamped from the start of the cycle, disordering
  the log and falsifying every port's `first_seen` by up to several minutes.
  Each host is now timestamped when its own scan finished, and results are
  flushed to the log as each host completes rather than batched at the end.
- Startup warnings, including "openpyxl not installed, no Excel will be
  produced", were written to the log file but never echoed to the console
  without `--verbose`. They are now always shown.
- `ipaddress.ip_network()` raised `AttributeError` when given a tuple of two
  `IPv4Address` objects, crashing the `/proc/net/route` detection path — the
  exact path a minimal Termux installation would take.
- Passing `--subnet` manually discarded the detected interface and with it the
  local MAC address. The interface is now resolved independently of the subnet.

[1.0.0]: https://github.com/nostraxiten/NoxGuardian/releases/tag/v1.0.0
