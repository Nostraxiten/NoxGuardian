"""DNS reverse-lookup (PTR) and forward resolution for live hosts.

For each alive IP:
  - ``dig -x <ip> +short``  -> PTR record (reverse DNS)
  - If a local domain suffix is detected:
    ``dig <hostname>.<domain> A``  and  ``dig <hostname>.<domain> AAAA``

Raw dig stdout is saved to ``03_dns/dig_<ip>.txt`` inside the audit folder.
The resolved PTR name is stored in the device's ``dns_ptr`` field via the
``AuditState`` helpers added to ``state.py``.

Design rules (same as nmap_runner.py):
  * subprocess with explicit timeout -- never raises outside the module.
  * All failures are captured, logged with the [E] marker and execution
    continues.
  * Output / log messages are in Spanish; code / docstrings in English.
"""

from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

# Timeout for a single dig invocation (seconds).
DEFAULT_DIG_TIMEOUT = 15.0

# Common local-domain suffixes that indicate there is an mDNS / local-DNS
# zone worth querying.  We only attempt a forward lookup if the PTR result
# ends with one of these (or the caller provides an explicit domain suffix).
_LOCAL_SUFFIXES = (".local", ".lan", ".home", ".internal", ".localdomain")


def find_dig() -> Optional[str]:
    """Absolute path of the ``dig`` binary, or *None* if not installed."""
    return shutil.which("dig")


def dig_version(path: Optional[str] = None) -> Optional[str]:
    """Version string reported by dig, or *None* on any error."""
    binary = path or find_dig()
    if not binary:
        return None
    try:
        proc = subprocess.run(
            [binary, "-v"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        # dig -v prints to stderr: "DiG 9.18.x ..."
        output = (proc.stderr or proc.stdout or "").strip()
        return output.splitlines()[0] if output else None
    except (OSError, subprocess.SubprocessError):
        return None


@dataclass
class DnsResult:
    """DNS resolution results for a single host."""

    ip: str
    ptr: Optional[str] = None          # PTR (reverse) record
    a_records: List[str] = field(default_factory=list)    # A records for the PTR name
    aaaa_records: List[str] = field(default_factory=list) # AAAA records for the PTR name
    raw_output: str = ""               # concatenated raw dig stdout for the .txt file
    error: Optional[str] = None        # first error encountered, if any
    duration: float = 0.0
    command_ptr: str = ""              # exact command run (for section 9 of the report)
    command_fwd: str = ""              # forward lookup command, if performed

    @property
    def ok(self) -> bool:
        return self.error is None

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "ptr": self.ptr,
            "a_records": self.a_records,
            "aaaa_records": self.aaaa_records,
            "error": self.error,
            "duration": round(self.duration, 3),
            "command_ptr": self.command_ptr,
            "command_fwd": self.command_fwd,
        }


class DnsRunner:
    """Runs dig for PTR and optional forward lookups; saves raw output to disk."""

    def __init__(
        self,
        dig_path: Optional[str] = None,
        timeout: float = DEFAULT_DIG_TIMEOUT,
        local_domain: Optional[str] = None,
    ) -> None:
        self.path = dig_path or find_dig()
        self.timeout = timeout
        # Strip leading dot if the caller included one.
        self.local_domain = (local_domain or "").lstrip(".")

    @property
    def available(self) -> bool:
        return self.path is not None

    # -- public API -----------------------------------------------------------

    def run(self, ip: str, out_dir: Path) -> DnsResult:
        """Resolve *ip* and write raw dig output to *out_dir*/dig_<ip>.txt.

        Never raises -- all errors are captured in ``DnsResult.error``.
        """
        started = time.monotonic()
        result = DnsResult(ip=ip)

        if not self.available:
            result.error = "dig no esta instalado o no esta en el PATH"
            result.duration = time.monotonic() - started
            return result

        # -- PTR lookup -------------------------------------------------------
        ptr_stdout, ptr_err = self._run_dig(["-x", ip, "+short"], result)
        result.command_ptr = f"{self.path} -x {ip} +short"
        raw_parts = [f"# dig -x {ip} +short\n{ptr_stdout}"]

        if ptr_err:
            result.error = ptr_err
        else:
            ptr = _first_line(ptr_stdout)
            if ptr:
                result.ptr = ptr.rstrip(".")  # strip trailing FQDN dot

        # -- Forward lookup (A + AAAA) ----------------------------------------
        # Attempt if: PTR resolved to a .local/.lan/... name, OR the caller
        # supplied an explicit local domain.
        fwd_name: Optional[str] = None

        if result.ptr and _is_local_name(result.ptr):
            fwd_name = result.ptr
        elif self.local_domain and result.ptr:
            bare = result.ptr.split(".")[0]
            fwd_name = f"{bare}.{self.local_domain}"

        if fwd_name:
            result.command_fwd = (
                f"{self.path} {fwd_name} A +short && {self.path} {fwd_name} AAAA +short"
            )

            a_stdout, a_err = self._run_dig([fwd_name, "A", "+short"], result)
            raw_parts.append(f"# dig {fwd_name} A +short\n{a_stdout}")
            if not a_err:
                result.a_records = [line for line in a_stdout.splitlines() if line.strip()]

            aaaa_stdout, aaaa_err = self._run_dig([fwd_name, "AAAA", "+short"], result)
            raw_parts.append(f"# dig {fwd_name} AAAA +short\n{aaaa_stdout}")
            if not aaaa_err:
                result.aaaa_records = [line for line in aaaa_stdout.splitlines() if line.strip()]

        # -- persist raw output -----------------------------------------------
        result.raw_output = "\n".join(raw_parts)
        result.duration = time.monotonic() - started

        out_dir.mkdir(parents=True, exist_ok=True)
        safe_ip = ip.replace(":", "_")  # handle IPv6
        txt_path = out_dir / f"dig_{safe_ip}.txt"
        try:
            txt_path.write_text(result.raw_output, encoding="utf-8")
        except OSError as exc:
            # Writing to disk should not abort the scan.
            result.error = result.error or f"no se pudo escribir {txt_path}: {exc}"

        return result

    # -- internal helpers -----------------------------------------------------

    def _run_dig(self, args: List[str], result: DnsResult):  # noqa: ARG002
        """Run ``dig <args>`` and return (stdout, error_message_or_None)."""
        command = [self.path, *args]
        try:
            proc = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
            return proc.stdout or "", None
        except subprocess.TimeoutExpired:
            msg = f"timeout de {self.timeout:g}s superado en: {' '.join(command)}"
            return "", msg
        except OSError as exc:
            return "", f"no se pudo ejecutar dig: {exc}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _first_line(text: str) -> str:
    """Return the first non-empty line from *text*, stripped."""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return ""


def _is_local_name(name: str) -> bool:
    """True if *name* ends with one of the well-known local domain suffixes."""
    lower = name.lower()
    return any(lower.endswith(suffix) for suffix in _LOCAL_SUFFIXES)
