"""HTTP/HTTPS header inspection for open web ports.

Only fires for ports that the deep scan already flagged as open and that
belong to the set of well-known web ports.  ``curl`` is called with
``-s -I -L --max-time 5`` so no body is downloaded.

For each (ip, port) pair the raw ``curl`` stdout is saved to
``04_http/curl_<ip>_<port>.txt`` and the structured result is returned so
``audit_runner.py`` can write it to ``audit_state.json`` and
``docx_report.py`` can fill section 5.6.

Design rules (same as nmap_runner.py):
  * subprocess with explicit timeout -- never raises outside the module.
  * Failures are captured and logged; execution continues.
  * Output / log messages in Spanish; code / docstrings in English.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Set

# Ports we consider "web" and that trigger this runner.
WEB_PORTS: Set[int] = {80, 443, 8000, 8008, 8080, 8443}

DEFAULT_CURL_TIMEOUT = 10.0  # subprocess hard limit (> curl's --max-time)
CURL_MAX_TIME = 5            # passed to --max-time

# Security headers we specifically track for section 5.6.
_SECURITY_HEADERS = (
    "strict-transport-security",
    "x-frame-options",
    "content-security-policy",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
)

# Header that identifies the server software.
_SERVER_HEADER = "server"


def find_curl() -> Optional[str]:
    """Absolute path of the ``curl`` binary, or *None* if not installed."""
    return shutil.which("curl")


def curl_version(path: Optional[str] = None) -> Optional[str]:
    """Version string reported by curl, or *None* on any error."""
    binary = path or find_curl()
    if not binary:
        return None
    try:
        proc = subprocess.run(
            [binary, "--version"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        lines = (proc.stdout or "").splitlines()
        return lines[0].strip() if lines else None
    except (OSError, subprocess.SubprocessError):
        return None


@dataclass
class HttpResult:
    """HTTP header inspection result for a single (ip, port) pair."""

    ip: str
    port: int
    scheme: str = "http"               # "http" or "https"
    status_code: Optional[int] = None
    server: Optional[str] = None       # value of the Server: header
    redirects_to_https: bool = False   # 80 -> 443 redirect detected
    hsts: Optional[str] = None         # Strict-Transport-Security value
    x_frame_options: Optional[str] = None
    csp: Optional[str] = None          # Content-Security-Policy value
    x_content_type: Optional[str] = None
    referrer_policy: Optional[str] = None
    permissions_policy: Optional[str] = None
    all_headers: List[str] = field(default_factory=list)  # raw header lines
    raw_output: str = ""               # full curl stdout for the .txt file
    error: Optional[str] = None
    duration: float = 0.0
    command: str = ""                  # exact command (for section 9)

    @property
    def ok(self) -> bool:
        return self.error is None

    @property
    def url(self) -> str:
        return f"{self.scheme}://{self.ip}:{self.port}"

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "port": self.port,
            "scheme": self.scheme,
            "url": self.url,
            "status_code": self.status_code,
            "server": self.server,
            "redirects_to_https": self.redirects_to_https,
            "hsts": self.hsts,
            "x_frame_options": self.x_frame_options,
            "csp": self.csp,
            "x_content_type": self.x_content_type,
            "referrer_policy": self.referrer_policy,
            "permissions_policy": self.permissions_policy,
            "error": self.error,
            "duration": round(self.duration, 3),
            "command": self.command,
        }


class HttpRunner:
    """Fetches HTTP headers with curl; saves raw output to disk."""

    def __init__(
        self,
        curl_path: Optional[str] = None,
        timeout: float = DEFAULT_CURL_TIMEOUT,
        web_ports: Optional[Set[int]] = None,
    ) -> None:
        self.path = curl_path or find_curl()
        self.timeout = timeout
        self.web_ports = web_ports if web_ports is not None else WEB_PORTS

    @property
    def available(self) -> bool:
        return self.path is not None

    def is_web_port(self, port: int) -> bool:
        """True if *port* is in the configured set of web ports."""
        return port in self.web_ports

    # -- public API -----------------------------------------------------------

    def run(self, ip: str, port: int, out_dir: Path) -> HttpResult:
        """Fetch headers for *ip*:*port* and write raw output to *out_dir*.

        The scheme (http vs https) is inferred from the port number:
        443 and 8443 default to https; everything else starts as http.
        ``curl -L`` follows redirects, so a 301 to https is captured.

        Never raises -- errors end up in ``HttpResult.error``.
        """
        started = time.monotonic()
        scheme = "https" if port in (443, 8443) else "http"
        result = HttpResult(ip=ip, port=port, scheme=scheme)

        if not self.available:
            result.error = "curl no esta instalado o no esta en el PATH"
            result.duration = time.monotonic() - started
            return result

        url = f"{scheme}://{ip}:{port}"
        command = [
            self.path,
            "-s",                    # silent (no progress bar)
            "-I",                    # headers only
            "-L",                    # follow redirects
            "--max-time", str(CURL_MAX_TIME),
            "--insecure",            # skip TLS cert validation for self-signed certs
            "-D", "-",               # dump headers to stdout
            url,
        ]
        result.command = " ".join(command)

        try:
            proc = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
            stdout = proc.stdout or ""
            stderr = (proc.stderr or "").strip()
        except subprocess.TimeoutExpired:
            result.error = f"timeout de {self.timeout:g}s superado en: {' '.join(command)}"
            result.duration = time.monotonic() - started
            return result
        except OSError as exc:
            result.error = f"no se pudo ejecutar curl: {exc}"
            result.duration = time.monotonic() - started
            return result

        result.raw_output = stdout
        if stderr and not stdout:
            result.error = f"curl stderr: {stderr}"
        else:
            _parse_headers(stdout, result)

        # -- persist raw output -----------------------------------------------
        result.duration = time.monotonic() - started
        out_dir.mkdir(parents=True, exist_ok=True)
        safe_ip = ip.replace(":", "_")
        txt_path = out_dir / f"curl_{safe_ip}_{port}.txt"
        try:
            txt_path.write_text(result.raw_output, encoding="utf-8")
        except OSError as exc:
            result.error = result.error or f"no se pudo escribir {txt_path}: {exc}"

        return result


# ---------------------------------------------------------------------------
# Header parsing helpers
# ---------------------------------------------------------------------------


def _parse_headers(raw: str, result: HttpResult) -> None:
    """Populate *result* fields by parsing the raw curl -I -L output.

    curl with -L may return multiple header blocks separated by blank lines
    (one per redirect hop).  We take the *last* block as the final response.
    """
    # Split on blank lines to get individual response blocks.
    blocks = re.split(r"\r?\n\r?\n", raw.strip())
    # The last non-empty block is the final response.
    last_block = ""
    for block in reversed(blocks):
        if block.strip():
            last_block = block.strip()
            break

    if not last_block:
        return

    lines = last_block.splitlines()
    if not lines:
        return

    # First line: status line ("HTTP/1.1 200 OK" or "HTTP/2 200")
    status_match = re.match(r"HTTP/[\d.]+\s+(\d+)", lines[0])
    if status_match:
        result.status_code = int(status_match.group(1))

    # Look for 301/302 redirect to https in any block to detect HTTP->HTTPS redirect.
    for block in blocks:
        block_lines = block.splitlines()
        if not block_lines:
            continue
        sm = re.match(r"HTTP/[\d.]+\s+(\d+)", block_lines[0])
        if sm and sm.group(1) in ("301", "302"):
            for bline in block_lines[1:]:
                lc = bline.lower()
                if lc.startswith("location:") and "https://" in bline:
                    result.redirects_to_https = True
                    break

    result.all_headers = lines[1:]

    # Extract individual headers.
    header_map: dict = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        header_map[name.strip().lower()] = value.strip()

    result.server = header_map.get(_SERVER_HEADER)
    result.hsts = header_map.get("strict-transport-security")
    result.x_frame_options = header_map.get("x-frame-options")
    result.csp = header_map.get("content-security-policy")
    result.x_content_type = header_map.get("x-content-type-options")
    result.referrer_policy = header_map.get("referrer-policy")
    result.permissions_policy = header_map.get("permissions-policy")
