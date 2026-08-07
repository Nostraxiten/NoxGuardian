# Contributing to NoxGuardian

Contributions are welcome. This document describes what the project expects.

---

## Ground rules

**Scan only what you own.** Do not submit output, logs, screenshots or test
fixtures containing MAC addresses, hostnames or IP addresses from a network you
do not control. Anonymise before opening an issue.

**Keep the dependency surface flat.** `openpyxl` is the only external
dependency, and adding a second one needs a strong justification. The project is
meant to run on a minimal Termux install where `pip` may be painful.

**No nmap wrapper libraries.** nmap is invoked as a binary with `-oX -` and its
XML is parsed with `xml.etree.ElementTree`. This is deliberate: it avoids a
dependency and is stable across nmap versions.

---

## Development setup

```bash
git clone https://github.com/nostraxiten/NoxGuardian.git
cd NoxGuardian
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

Running the monitor for real needs `nmap` and, for ARP sweeps, root:

```bash
sudo apt install -y nmap
sudo python3 -m noxguardian --check
```

---

## Before opening a pull request

Both of these must pass.

```bash
python3 tools/selftest.py
python3 -m pyflakes noxguardian tools noxguardian.py
```

The self-test requires no network access and must stay that way. If your change
touches behaviour, add assertions covering it. The suite is a plain script
rather than a pytest suite so that it runs anywhere Python does, including on a
phone.

---

## Code conventions

- **Python 3.9 compatible.** Every module carries
  `from __future__ import annotations`; do not use `match`, or `X | Y` unions in
  runtime positions.
- **Comments explain why, not what.** The codebase is deliberately light on
  narration and heavy on rationale where a decision is non-obvious.
- **Source is ASCII.** Identifiers, comments and docstrings avoid accented
  characters so that the code renders identically in any terminal encoding.
- **User-facing strings are in Spanish**, matching the console output, the event
  log and the Excel headers. Documentation is in English.
- **Nothing may terminate the process.** Any new code in a scan path must catch
  its own failures, log them, and let the loop continue. This is the core
  promise of the tool.
- **Timestamps are epoch floats.** Format to text only at the output layer.

---

## Reporting bugs

Useful reports include:

- The output of `python3 -m noxguardian --check`
- The exact command line used
- The relevant excerpt from `noxguardian_events.log`, with MAC addresses,
  hostnames and IP addresses redacted
- `nmap --version` and your platform

---

## Extending the OUI table

Do not hand-edit `noxguardian/data/oui_prefixes.csv` for bulk additions.
Regenerate it from system databases instead:

```bash
python3 tools/build_oui.py
```

Single-entry corrections by hand are fine. Format is `AABBCC,Vendor Name`, one
per line, with `#` for comments.
