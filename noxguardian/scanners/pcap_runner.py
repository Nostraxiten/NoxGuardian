"""Targeted packet capture evidence for a single host.

Runs two subprocesses *in parallel*:

1. ``tshark -i <iface> -a duration:5 -f "host <ip>" -w <tmpfile.pcapng>``
   -- captures for 5 seconds, directed at the specific host.

2. ``ping -c 2 <ip>``
   -- generates traffic so there is at least something to capture.

After both finish, a *summary* is produced with
``tshark -r <tmpfile.pcapng> -q -z io,phs``
and saved to ``06_evidencia_pcap/tshark_<ip>.txt``.
The ``.pcapng`` itself is *deleted* so the audit folder does not contain
sensitive traffic; only the human-readable summary is kept.

Design rules (same as nmap_runner.py):
  * subprocess with explicit timeout -- never raises outside the module.
  * Failures captured and logged; execution continues.
  * tshark requires capture privileges (root or ``setcap cap_net_raw``).
  * Output / log messages in Spanish; code / docstrings in English.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

DEFAULT_CAPTURE_DURATION = 5        # seconds passed to tshark -a duration:N
DEFAULT_PING_COUNT = 2              # packets sent by ping -c N
DEFAULT_PCAP_TIMEOUT = 30.0        # subprocess hard limit for tshark capture
DEFAULT_SUMMARY_TIMEOUT = 15.0     # subprocess hard limit for tshark read pass


def find_tshark() -> Optional[str]:
    """Absolute path of the ``tshark`` binary, or *None* if not installed."""
    return shutil.which("tshark")


def find_ping() -> Optional[str]:
    """Absolute path of the ``ping`` binary, or *None* if not found."""
    return shutil.which("ping")


def tshark_version(path: Optional[str] = None) -> Optional[str]:
    """Version string reported by tshark, or *None* on any error."""
    binary = path or find_tshark()
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
class PcapResult:
    """Evidence summary for a single host."""

    ip: str
    interface: str
    summary: str = ""             # output of tshark -q -z io,phs
    raw_output: str = ""          # same as summary (kept for consistency)
    packets_captured: Optional[int] = None
    error: Optional[str] = None
    duration: float = 0.0
    command_capture: str = ""     # for section 9
    command_summary: str = ""     # for section 9

    @property
    def ok(self) -> bool:
        return self.error is None

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "interface": self.interface,
            "packets_captured": self.packets_captured,
            "summary_lines": self.summary.splitlines()[:30],  # keep JSON compact
            "error": self.error,
            "duration": round(self.duration, 3),
            "command_capture": self.command_capture,
            "command_summary": self.command_summary,
        }


class PcapRunner:
    """Captures a short, directed packet burst and saves only the summary."""

    def __init__(
        self,
        tshark_path: Optional[str] = None,
        ping_path: Optional[str] = None,
        capture_duration: int = DEFAULT_CAPTURE_DURATION,
        ping_count: int = DEFAULT_PING_COUNT,
        capture_timeout: float = DEFAULT_PCAP_TIMEOUT,
        summary_timeout: float = DEFAULT_SUMMARY_TIMEOUT,
    ) -> None:
        self.tshark_path = tshark_path or find_tshark()
        self.ping_path = ping_path or find_ping()
        self.capture_duration = capture_duration
        self.ping_count = ping_count
        self.capture_timeout = capture_timeout
        self.summary_timeout = summary_timeout

    @property
    def available(self) -> bool:
        return self.tshark_path is not None

    # -- public API -----------------------------------------------------------

    def run(self, ip: str, interface: str, out_dir: Path) -> PcapResult:
        """Capture traffic to/from *ip* on *interface* and write a summary.

        Steps:
          1. Create a temporary ``.pcapng`` file.
          2. Launch tshark (capture) and ping in parallel threads.
          3. Wait for tshark to finish (it self-terminates after *duration* s).
          4. Run tshark summary pass over the temp file.
          5. Delete the temp file.
          6. Save the summary to ``06_evidencia_pcap/tshark_<ip>.txt``.

        Never raises -- errors end up in ``PcapResult.error``.
        """
        started = time.monotonic()
        result = PcapResult(ip=ip, interface=interface)

        if not self.available:
            result.error = (
                "tshark no instalado o sin permisos de captura. "
                "Instala wireshark-common y ejecuta: "
                "sudo setcap cap_net_raw,cap_net_admin+eip $(which tshark)"
            )
            result.duration = time.monotonic() - started
            return result

        # -- temporary pcap file ----------------------------------------------
        tmp_fd, tmp_path_str = tempfile.mkstemp(suffix=".pcapng", prefix=f"nox_{ip}_")
        import os; os.close(tmp_fd)
        tmp_path = Path(tmp_path_str)

        try:
            # -- build capture command ----------------------------------------
            cap_command = [
                self.tshark_path,
                "-i", interface,
                "-a", f"duration:{self.capture_duration}",
                "-f", f"host {ip}",
                "-w", str(tmp_path),
            ]
            result.command_capture = " ".join(cap_command)

            # -- launch tshark and ping in parallel ---------------------------
            capture_error: Optional[str] = None
            tshark_proc: list = []   # mutable container for the thread to write into

            def _capture() -> None:
                nonlocal capture_error
                try:
                    proc = subprocess.run(
                        cap_command,
                        capture_output=True,
                        text=True,
                        timeout=self.capture_timeout,
                        check=False,
                    )
                    tshark_proc.append(proc)
                    if proc.returncode not in (0, 1, 2):  # tshark exit codes vary
                        capture_error = (
                            f"tshark termino con codigo {proc.returncode}: "
                            f"{(proc.stderr or '').strip()[:200]}"
                        )
                except subprocess.TimeoutExpired:
                    capture_error = (
                        f"timeout de {self.capture_timeout:g}s superado en la captura"
                    )
                except OSError as exc:
                    capture_error = f"no se pudo ejecutar tshark: {exc}"

            def _ping() -> None:
                if not self.ping_path:
                    return
                try:
                    ping_command = [self.ping_path, "-c", str(self.ping_count), ip]
                    subprocess.run(
                        ping_command,
                        capture_output=True,
                        timeout=self.capture_duration + 5,
                        check=False,
                    )
                except (OSError, subprocess.SubprocessError):
                    pass  # ping failure is not critical -- tshark still runs

            cap_thread = threading.Thread(target=_capture, daemon=True)
            ping_thread = threading.Thread(target=_ping, daemon=True)

            # Start capture first so it is ready before ping traffic arrives.
            cap_thread.start()
            time.sleep(0.5)  # small head-start for tshark to open the interface
            ping_thread.start()

            cap_thread.join(timeout=self.capture_timeout + 5)
            ping_thread.join(timeout=10)

            if capture_error:
                result.error = capture_error
                return result

            # -- summary pass -------------------------------------------------
            if not tmp_path.exists() or tmp_path.stat().st_size == 0:
                result.error = "tshark no genero el fichero de captura (sin paquetes o sin permisos)"
                return result

            summary_command = [
                self.tshark_path,
                "-r", str(tmp_path),
                "-q",
                "-z", "io,phs",
            ]
            result.command_summary = " ".join(summary_command)

            try:
                summary_proc = subprocess.run(
                    summary_command,
                    capture_output=True,
                    text=True,
                    timeout=self.summary_timeout,
                    check=False,
                )
                result.summary = summary_proc.stdout or ""
                result.raw_output = result.summary
            except subprocess.TimeoutExpired:
                result.error = "timeout generando el resumen de la captura"
                return result
            except OSError as exc:
                result.error = f"error leyendo la captura: {exc}"
                return result

            # Try to extract packet count from summary.
            for line in result.summary.splitlines():
                if "frames" in line.lower():
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part.isdigit() and i > 0:
                            result.packets_captured = int(part)
                            break

        finally:
            # Always delete the pcap -- we only keep the text summary.
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass

        # -- persist summary --------------------------------------------------
        result.duration = time.monotonic() - started
        out_dir.mkdir(parents=True, exist_ok=True)
        safe_ip = ip.replace(":", "_")
        txt_path = out_dir / f"tshark_{safe_ip}.txt"
        try:
            txt_path.write_text(result.summary, encoding="utf-8")
        except OSError as exc:
            result.error = result.error or f"no se pudo escribir {txt_path}: {exc}"

        return result
