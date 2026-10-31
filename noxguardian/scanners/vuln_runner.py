"""Vulnerability lookup for (service, version) pairs found by the deep scan.

Two independent backends, both optional and gracefully degrading:

1. **searchsploit** (Kali / Exploit-DB local DB) -- offline.
   Runs ``searchsploit --json <service> <version>``.
   If not installed, logs a notice and skips.

2. **NVD REST API v2** -- online, but only calls ``services.nvd.nist.gov``.
   Endpoint: ``/rest/json/cves/2.0?keywordSearch=<service>+<version>``
   Stores the top CVE IDs and their CVSS v3.1 base scores.
   If the network is unavailable the error is captured and execution continues.

Raw output for each (service, version) pair is saved to:
  ``05_vulnerabilidades/searchsploit_<service>_<version>.txt``
  ``05_vulnerabilidades/nvd_<cve>.txt`` (one per matching CVE)

Design rules (same as nmap_runner.py):
  * subprocess with explicit timeout for searchsploit.
  * urllib (stdlib) for NVD -- no requests dependency.
  * Never raises outside the module; all errors are captured.
  * Output / log messages in Spanish; code / docstrings in English.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

DEFAULT_SEARCHSPLOIT_TIMEOUT = 30.0
DEFAULT_NVD_TIMEOUT = 15.0

# Maximum CVEs to retrieve per (service, version) query.
NVD_MAX_RESULTS = 5

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Characters not safe for filenames.
_UNSAFE = re.compile(r"[^A-Za-z0-9._-]")


def find_searchsploit() -> Optional[str]:
    """Absolute path of the ``searchsploit`` binary, or *None* if not installed."""
    return shutil.which("searchsploit")


def searchsploit_version(path: Optional[str] = None) -> Optional[str]:
    """Version string, or *None* on any error."""
    binary = path or find_searchsploit()
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
class CveEntry:
    """A single CVE with its CVSS score."""

    cve_id: str
    description: str = ""
    cvss_v3: Optional[float] = None
    severity: str = "UNKNOWN"     # CRITICAL / HIGH / MEDIUM / LOW / NONE
    url: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "description": self.description[:500],   # keep JSON compact
            "cvss_v3": self.cvss_v3,
            "severity": self.severity,
            "url": self.url,
        }


@dataclass
class VulnResult:
    """Vulnerability findings for a single (service, version) pair."""

    service: str
    version: str
    searchsploit_hits: List[str] = field(default_factory=list)  # exploit titles
    cves: List[CveEntry] = field(default_factory=list)
    searchsploit_raw: str = ""
    error: Optional[str] = None
    duration: float = 0.0
    command_searchsploit: str = ""   # for section 9
    nvd_query: str = ""              # for section 9

    @property
    def ok(self) -> bool:
        return self.error is None

    @property
    def has_findings(self) -> bool:
        return bool(self.searchsploit_hits or self.cves)

    @property
    def label(self) -> str:
        return f"{self.service} {self.version}".strip()

    @property
    def highest_cvss(self) -> Optional[float]:
        scores = [cve.cvss_v3 for cve in self.cves if cve.cvss_v3 is not None]
        return max(scores) if scores else None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "service": self.service,
            "version": self.version,
            "searchsploit_hits": self.searchsploit_hits,
            "cves": [cve.to_dict() for cve in self.cves],
            "highest_cvss": self.highest_cvss,
            "error": self.error,
            "duration": round(self.duration, 3),
            "command_searchsploit": self.command_searchsploit,
            "nvd_query": self.nvd_query,
        }


class VulnRunner:
    """Runs searchsploit and NVD lookups for (service, version) pairs."""

    def __init__(
        self,
        searchsploit_path: Optional[str] = None,
        searchsploit_timeout: float = DEFAULT_SEARCHSPLOIT_TIMEOUT,
        nvd_timeout: float = DEFAULT_NVD_TIMEOUT,
        nvd_api_key: Optional[str] = None,
    ) -> None:
        self.searchsploit_path = searchsploit_path or find_searchsploit()
        self.searchsploit_timeout = searchsploit_timeout
        self.nvd_timeout = nvd_timeout
        self.nvd_api_key = nvd_api_key

    @property
    def searchsploit_available(self) -> bool:
        return self.searchsploit_path is not None

    # -- public API -----------------------------------------------------------

    def run(self, service: str, version: str, out_dir: Path) -> VulnResult:
        """Look up vulnerabilities for *service* / *version*.

        Skips silently if both service and version are empty or ``"unknown"``.
        Never raises -- errors end up in ``VulnResult.error``.
        """
        started = time.monotonic()
        result = VulnResult(service=service, version=version)

        if not service or version.lower() in ("", "unknown"):
            result.error = "version desconocida; se omite la busqueda"
            result.duration = time.monotonic() - started
            return result

        out_dir.mkdir(parents=True, exist_ok=True)

        # -- searchsploit -----------------------------------------------------
        if self.searchsploit_available:
            self._run_searchsploit(service, version, out_dir, result)
        else:
            # Degradation: log once, keep going.
            result.error = (
                "searchsploit no instalado; se omite la busqueda offline. "
                "Instala exploitdb (Kali: 'apt install exploitdb')"
            )

        # -- NVD API ----------------------------------------------------------
        self._query_nvd(service, version, out_dir, result)

        result.duration = time.monotonic() - started
        return result

    # -- searchsploit ---------------------------------------------------------

    def _run_searchsploit(
        self, service: str, version: str, out_dir: Path, result: VulnResult
    ) -> None:
        query_terms = [service, version]
        command = [self.searchsploit_path, "--json", *query_terms]
        result.command_searchsploit = " ".join(command)

        try:
            proc = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.searchsploit_timeout,
                check=False,
            )
            raw = proc.stdout or ""
        except subprocess.TimeoutExpired:
            result.error = (
                f"timeout de {self.searchsploit_timeout:g}s superado en searchsploit"
            )
            return
        except OSError as exc:
            result.error = f"no se pudo ejecutar searchsploit: {exc}"
            return

        result.searchsploit_raw = raw

        # Parse JSON output from searchsploit --json
        try:
            data = json.loads(raw)
            exploits = data.get("RESULTS_EXPLOIT", []) + data.get("RESULTS_SHELLCODE", [])
            result.searchsploit_hits = [
                entry.get("Title", "") for entry in exploits if entry.get("Title")
            ]
        except (json.JSONDecodeError, AttributeError):
            # searchsploit may not always produce valid JSON (older versions).
            result.searchsploit_hits = _parse_searchsploit_text(raw)

        # Persist raw output.
        safe = _safe_name(f"{service}_{version}")
        txt_path = out_dir / f"searchsploit_{safe}.txt"
        try:
            txt_path.write_text(raw, encoding="utf-8")
        except OSError:
            pass

    # -- NVD ------------------------------------------------------------------

    def _query_nvd(
        self, service: str, version: str, out_dir: Path, result: VulnResult
    ) -> None:
        keyword = f"{service} {version}"
        params = urllib.parse.urlencode({
            "keywordSearch": keyword,
            "resultsPerPage": str(NVD_MAX_RESULTS),
        })
        url = f"{NVD_BASE_URL}?{params}"
        result.nvd_query = url

        headers = {"User-Agent": "NoxGuardian-audit/1.0"}
        if self.nvd_api_key:
            headers["apiKey"] = self.nvd_api_key

        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.nvd_timeout) as resp:
                raw_bytes = resp.read()
        except urllib.error.URLError as exc:
            result.error = result.error or f"NVD no disponible: {exc}"
            return
        except OSError as exc:
            result.error = result.error or f"error de red consultando NVD: {exc}"
            return

        raw_text = raw_bytes.decode("utf-8", errors="replace")

        try:
            data = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            result.error = result.error or f"respuesta NVD ilegible: {exc}"
            return

        vulnerabilities = data.get("vulnerabilities", [])
        for item in vulnerabilities:
            cve_data = item.get("cve", {})
            cve_id = cve_data.get("id", "")
            if not cve_id:
                continue

            descriptions = cve_data.get("descriptions", [])
            desc = next(
                (d.get("value", "") for d in descriptions if d.get("lang") == "en"), ""
            )

            # CVSS v3.1 score
            cvss_v3 = None
            severity = "UNKNOWN"
            metrics = cve_data.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                entries = metrics.get(key, [])
                if entries:
                    cvss_data = entries[0].get("cvssData", {})
                    try:
                        cvss_v3 = float(cvss_data.get("baseScore", 0))
                    except (TypeError, ValueError):
                        cvss_v3 = None
                    severity = cvss_data.get("baseSeverity", "UNKNOWN").upper()
                    break

            cve_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            entry = CveEntry(
                cve_id=cve_id,
                description=desc,
                cvss_v3=cvss_v3,
                severity=severity,
                url=cve_url,
            )
            result.cves.append(entry)

            # Persist one file per CVE.
            cve_txt = out_dir / f"nvd_{cve_id}.txt"
            try:
                cve_txt.write_text(
                    f"CVE: {cve_id}\nURL: {cve_url}\nCVSS v3: {cvss_v3} ({severity})\n\n{desc}\n",
                    encoding="utf-8",
                )
            except OSError:
                pass

        if not vulnerabilities:
            # Write an explicit "no results" file so the Annex can reference it.
            safe = _safe_name(f"{service}_{version}")
            txt_path = out_dir / f"nvd_{safe}.txt"
            try:
                txt_path.write_text(
                    f"# NVD keywordSearch: {keyword}\n# Sin resultados.\n",
                    encoding="utf-8",
                )
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _safe_name(text: str) -> str:
    """Return a filesystem-safe version of *text* (max 80 chars)."""
    return _UNSAFE.sub("_", text)[:80]


def _parse_searchsploit_text(raw: str) -> List[str]:
    """Fallback: extract exploit titles from non-JSON searchsploit output."""
    titles: List[str] = []
    for line in raw.splitlines():
        line = line.strip()
        if line and not line.startswith("-") and not line.startswith("="):
            titles.append(line)
    return titles[:50]  # cap at 50 to avoid noise
