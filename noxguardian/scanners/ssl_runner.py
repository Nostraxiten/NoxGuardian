"""SSL/TLS cipher suite and certificate scanner for open TLS ports.

Integrates ``sslscan`` when available on the system (e.g. Kali, Debian, Ubuntu),
and provides an automated Python stdlib ``ssl`` fallback so TLS evaluation
works reliably on any machine without external dependencies.

For each TLS-capable service (e.g. 443, 8443 or any port flagged with ssl/tls):
  - Extracts supported protocols (SSLv2, SSLv3, TLS 1.0, 1.1, 1.2, 1.3)
  - Identifies preferred and supported cipher suites
  - Checks for insecure renegotiation, compression (CRIME) and Heartbleed
  - Retrieves certificate details: Subject, Issuer, Validity and Self-signed status
  - Saves raw output to ``04_http/sslscan_<ip>_<port>.txt``

Design rules (same as nmap_runner.py):
  * Subprocess with explicit timeout -- never raises outside the module.
  * Failures are captured, logged and execution continues gracefully.
  * Output / log messages in Spanish; code / docstrings in English.
"""

from __future__ import annotations

import re
import shutil
import socket
import ssl
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

DEFAULT_SSLSCAN_TIMEOUT = 25.0
SSL_PORTS: Set[int] = {443, 465, 993, 995, 8000, 8080, 8443}


def find_sslscan() -> Optional[str]:
    """Absolute path of the ``sslscan`` binary, or *None* if not installed."""
    return shutil.which("sslscan")


def sslscan_version(path: Optional[str] = None) -> Optional[str]:
    """Version string reported by sslscan, or *None* on any error."""
    binary = path or find_sslscan()
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
        lines = (proc.stdout or proc.stderr or "").splitlines()
        for line in lines:
            line_clean = line.strip()
            if "sslscan" in line_clean.lower() or "version" in line_clean.lower():
                return line_clean
        return lines[0].strip() if lines else "disponible"
    except (OSError, subprocess.SubprocessError):
        return None


@dataclass
class SslResult:
    """SSL/TLS inspection result for a single (ip, port) pair."""

    ip: str
    port: int
    tool_used: str = "sslscan"                   # "sslscan" or "stdlib-ssl"
    protocols_enabled: List[str] = field(default_factory=list)
    protocols_disabled: List[str] = field(default_factory=list)
    preferred_cipher: Optional[str] = None
    ciphers_supported: List[str] = field(default_factory=list)
    cert_subject: Optional[str] = None
    cert_issuer: Optional[str] = None
    cert_validity: Optional[str] = None
    cert_expired: bool = False
    cert_self_signed: bool = False
    heartbleed_vulnerable: bool = False
    insecure_renegotiation: bool = False
    compression_enabled: bool = False
    raw_output: str = ""
    error: Optional[str] = None
    duration: float = 0.0
    command: str = ""

    @property
    def ok(self) -> bool:
        return self.error is None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "port": self.port,
            "tool_used": self.tool_used,
            "protocols_enabled": self.protocols_enabled,
            "protocols_disabled": self.protocols_disabled,
            "preferred_cipher": self.preferred_cipher,
            "ciphers_supported": self.ciphers_supported,
            "cert_subject": self.cert_subject,
            "cert_issuer": self.cert_issuer,
            "cert_validity": self.cert_validity,
            "cert_expired": self.cert_expired,
            "cert_self_signed": self.cert_self_signed,
            "heartbleed_vulnerable": self.heartbleed_vulnerable,
            "insecure_renegotiation": self.insecure_renegotiation,
            "compression_enabled": self.compression_enabled,
            "error": self.error,
            "duration": self.duration,
            "command": self.command,
        }

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "SslResult":
        return SslResult(
            ip=data.get("ip", ""),
            port=int(data.get("port", 0)),
            tool_used=data.get("tool_used", "sslscan"),
            protocols_enabled=list(data.get("protocols_enabled") or []),
            protocols_disabled=list(data.get("protocols_disabled") or []),
            preferred_cipher=data.get("preferred_cipher"),
            ciphers_supported=list(data.get("ciphers_supported") or []),
            cert_subject=data.get("cert_subject"),
            cert_issuer=data.get("cert_issuer"),
            cert_validity=data.get("cert_validity"),
            cert_expired=bool(data.get("cert_expired", False)),
            cert_self_signed=bool(data.get("cert_self_signed", False)),
            heartbleed_vulnerable=bool(data.get("heartbleed_vulnerable", False)),
            insecure_renegotiation=bool(data.get("insecure_renegotiation", False)),
            compression_enabled=bool(data.get("compression_enabled", False)),
            raw_output="",
            error=data.get("error"),
            duration=float(data.get("duration", 0.0)),
            command=data.get("command", ""),
        )


class SslRunner:
    """Executes sslscan or standard library TLS inspection on open ports."""

    def __init__(
        self,
        sslscan_path: Optional[str] = None,
        timeout: float = DEFAULT_SSLSCAN_TIMEOUT,
        ssl_ports: Optional[Set[int]] = None,
    ) -> None:
        self.path = sslscan_path if sslscan_path is not None else find_sslscan()
        self.timeout = timeout
        self.ssl_ports = ssl_ports if ssl_ports is not None else SSL_PORTS

    @property
    def available(self) -> bool:
        """True if the sslscan binary is found on the system."""
        return self.path is not None

    def is_ssl_port(self, port: int, service: str = "") -> bool:
        """Return True if the port or service suggests SSL/TLS."""
        svc = (service or "").lower()
        if any(keyword in svc for keyword in ("ssl", "https", "tls")):
            return True
        return port in self.ssl_ports

    def run(self, ip: str, port: int, out_dir: Path) -> SslResult:
        """Run SSL/TLS scan against *ip*:*port* and write raw output to disk.

        If ``sslscan`` is installed, runs it. Otherwise falls back to Python's
        built-in ``ssl`` socket inspection so TLS analysis never fails to produce
        findings. Never raises -- errors are stored in ``SslResult.error``.
        """
        started = time.monotonic()
        result = SslResult(ip=ip, port=port)

        if self.available:
            self._run_sslscan(ip, port, result)
        else:
            self._run_stdlib_ssl(ip, port, result)

        result.duration = time.monotonic() - started

        # Persist raw output into 04_http/sslscan_<ip>_<port>.txt
        out_dir.mkdir(parents=True, exist_ok=True)
        txt_path = out_dir / f"sslscan_{ip}_{port}.txt"
        try:
            txt_path.write_text(result.raw_output, encoding="utf-8", errors="replace")
        except OSError as exc:
            if not result.error:
                result.error = f"error al guardar {txt_path.name}: {exc}"

        return result

    # -- Internal execution methods -------------------------------------------

    def _run_sslscan(self, ip: str, port: int, result: SslResult) -> None:
        """Execute sslscan binary and parse its output."""
        result.tool_used = "sslscan"
        cmd = [self.path or "sslscan", "--no-colour", f"{ip}:{port}"]
        result.command = " ".join(cmd)

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
            raw = proc.stdout or ""
            if proc.stderr:
                raw += f"\n[stderr]\n{proc.stderr}"
            result.raw_output = raw
            self._parse_sslscan_output(raw, result)

            if proc.returncode != 0 and not result.protocols_enabled and not result.cert_subject:
                result.error = f"sslscan salio con codigo {proc.returncode}"
        except subprocess.TimeoutExpired:
            result.error = f"timeout ({self.timeout}s) ejecutando sslscan"
            result.raw_output = f"# ERROR: timeout tras {self.timeout}s\n# Comando: {result.command}\n"
        except OSError as exc:
            result.error = f"error al ejecutar sslscan: {exc}"
            result.raw_output = f"# ERROR: {exc}\n"

    def _run_stdlib_ssl(self, ip: str, port: int, result: SslResult) -> None:
        """Fallback when sslscan is not installed: stdlib socket + ssl context."""
        result.tool_used = "stdlib-ssl"
        result.command = f"python-stdlib-ssl {ip}:{port}"

        raw_lines = [
            "# Inspección SSL/TLS (fallback stdlib ssl, sslscan no disponible)",
            f"# Destino: {ip}:{port}",
        ]

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((ip, port), timeout=min(self.timeout, 10.0)) as sock:
                with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                    version = ssock.version()
                    if version:
                        result.protocols_enabled.append(version)
                        raw_lines.append(f"Protocolo negociado : {version}")

                    cipher = ssock.cipher()
                    if cipher:
                        c_name, c_proto, c_bits = cipher
                        result.preferred_cipher = f"{c_name} ({c_bits} bits)"
                        result.ciphers_supported.append(c_name)
                        raw_lines.append(f"Cifrado preferido   : {result.preferred_cipher}")

                    cert = ssock.getpeercert() or {}
                    if not cert:
                        # With CERT_NONE, binary form is available
                        raw_lines.append("Certificado obtenido: presente (no verificado/autofirmado)")

                    subject = _format_dn(cert.get("subject", ()))
                    issuer = _format_dn(cert.get("issuer", ()))
                    if subject:
                        result.cert_subject = subject
                        raw_lines.append(f"Certificado Sujeto  : {subject}")
                    if issuer:
                        result.cert_issuer = issuer
                        raw_lines.append(f"Certificado Emisor  : {issuer}")
                    if subject and issuer and subject == issuer:
                        result.cert_self_signed = True
                        raw_lines.append("Certificado autofirmado: Sí")

                    not_after = cert.get("notAfter")
                    not_before = cert.get("notBefore")
                    if not_before or not_after:
                        validity = f"{not_before or '?'} hasta {not_after or '?'}"
                        result.cert_validity = validity
                        raw_lines.append(f"Validez             : {validity}")

            result.raw_output = "\n".join(raw_lines) + "\n"
        except (socket.error, ssl.SSLError, OSError) as exc:
            result.error = f"no se pudo establecer conexion TLS: {exc}"
            raw_lines.append(f"# Error TLS: {exc}")
            result.raw_output = "\n".join(raw_lines) + "\n"

    # -- Parsing helpers ------------------------------------------------------

    @staticmethod
    def _parse_sslscan_output(stdout: str, result: SslResult) -> None:
        """Parse raw sslscan stdout into structured fields."""
        for line in stdout.splitlines():
            line_clean = line.strip()

            # Protocol detection: e.g. "TLSv1.2   enabled" or "Accepted  TLSv1.2"
            proto_match = re.search(
                r"\b(SSLv2|SSLv3|TLSv1\.0|TLSv1\.1|TLSv1\.2|TLSv1\.3)\b\s+(enabled|disabled|accepted)",
                line_clean,
                re.IGNORECASE,
            )
            if proto_match:
                proto, status = proto_match.group(1), proto_match.group(2).lower()
                if status in ("enabled", "accepted") and proto not in result.protocols_enabled:
                    result.protocols_enabled.append(proto)
                elif status == "disabled" and proto not in result.protocols_disabled:
                    result.protocols_disabled.append(proto)

            # Preferred cipher
            if line_clean.startswith("Preferred") and not result.preferred_cipher:
                result.preferred_cipher = line_clean.replace("Preferred", "").strip()

            # Accepted ciphers
            if "accepted" in line_clean.lower() and "bits" in line_clean.lower():
                result.ciphers_supported.append(line_clean)

            # Heartbleed
            if "vulnerable to heartbleed" in line_clean.lower():
                if "not vulnerable" not in line_clean.lower():
                    result.heartbleed_vulnerable = True

            # Insecure renegotiation
            if "insecure" in line_clean.lower() and "renegotiation" in line_clean.lower():
                result.insecure_renegotiation = True

            # Compression / CRIME
            if "compression enabled" in line_clean.lower():
                result.compression_enabled = True

            # Certificate fields
            if line_clean.startswith("Subject:"):
                result.cert_subject = line_clean[len("Subject:") :].strip()
            elif line_clean.startswith("Issuer:"):
                result.cert_issuer = line_clean[len("Issuer:") :].strip()
            elif line_clean.startswith("Not valid after:"):
                valid_after = line_clean[len("Not valid after:") :].strip()
                result.cert_validity = (
                    f"hasta {valid_after}"
                    if not result.cert_validity
                    else f"{result.cert_validity} -> {valid_after}"
                )
            elif line_clean.startswith("Not valid before:"):
                valid_before = line_clean[len("Not valid before:") :].strip()
                result.cert_validity = f"desde {valid_before}"

            if "self-signed" in line_clean.lower() or "self signed" in line_clean.lower():
                result.cert_self_signed = True

        if result.cert_subject and result.cert_issuer and result.cert_subject == result.cert_issuer:
            result.cert_self_signed = True


def _format_dn(dn_tuple: Any) -> str:
    """Format an X.509 Distinguished Name from stdlib getpeercert() format."""
    if not dn_tuple:
        return ""
    parts = []
    for rdn in dn_tuple:
        for key, val in rdn:
            parts.append(f"{key}={val}")
    return ", ".join(parts)
