"""Audit orchestrator for the ``noxguardian audit`` subcommand.

Runs a single-pass audit of the local network:

  1. Creates the ``noxguardian_audit_<timestamp>/`` folder tree.
  2. Runs a presence scan (nmap -sn or TCP sweep).
  3. Runs a deep port scan (nmap -sV) for every live host.
  4. For every live host: dns_runner and (if web ports found) http_runner
     -- these two run in parallel using the same worker-pool pattern as the
     deep scan.
  5. For each (service, version) with a known version: vuln_runner.
  6. For each live host: pcap_runner (sequential, not parallel, to avoid
     mixing capture traffic).
  7. Writes the final ``00_resumen/audit_state.json`` checkpoint.
  8. Generates the Word report via docx_report.py.
  9. Prints a summary to stdout.

All failures in individual modules are captured and logged; a failure in one
host or module never aborts the rest.

Usage (from CLI):
    sudo python3 -m noxguardian audit [options]

Log markers follow the existing convention:
    [+]  new finding
    [!]  notable event
    [*]  scan completed
    [E]  error (captured, execution continues)
    [i]  informational
    [S]  checkpoint saved
"""

from __future__ import annotations

import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Set

from . import netinfo, ports_profile
from .exporters.checkpoint import CheckpointStore
from .exporters.txtlog import EventLog
from .oui import OuiResolver
from .scanners.dns_runner import DnsRunner, dig_version
from .scanners.http_runner import HttpRunner, WEB_PORTS, curl_version
from .scanners.nmap_runner import NmapRunner, nmap_version
from .scanners.pcap_runner import PcapRunner, tshark_version
from .scanners.ports import PortScanner
from .scanners.presence import PresenceScanner
from .scanners.ssl_runner import SslRunner, sslscan_version
from .scanners.vuln_runner import VulnRunner, searchsploit_version
from .state import StateManager

# Subdirectory layout inside the audit output folder.
_SUBDIRS = {
    "summary": "00_resumen",
    "presence": "01_presencia",
    "ports": "02_puertos",
    "dns": "03_dns",
    "http": "04_http",
    "vulns": "05_vulnerabilidades",
    "pcap": "06_evidencia_pcap",
    "report": "07_informe",
}

AUDIT_LOG_NAME = "noxguardian_audit.log"
AUDIT_STATE_NAME = "audit_state.json"


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def run_audit(
    subnet: Optional[str] = None,
    template: Optional[Path] = None,
    workers: int = 2,
    ports: str = ports_profile.DEFAULT_PORT_SPEC,
    force_fallback: bool = False,
    oui_file: Optional[Path] = None,
    no_system_oui: bool = False,
    base_output_dir: Optional[Path] = None,
    local_domain: Optional[str] = None,
    nvd_api_key: Optional[str] = None,
) -> int:
    """Run the full audit and return an exit code (0 = success, 1 = error)."""

    timestamp = time.strftime("%Y%m%d_%H%M%S")
    audit_dir = (base_output_dir or Path(".")) / f"noxguardian_audit_{timestamp}"
    audit_dir.mkdir(parents=True, exist_ok=True)

    # Create subdirectories up front.
    dirs: Dict[str, Path] = {key: audit_dir / name for key, name in _SUBDIRS.items()}
    for path in dirs.values():
        path.mkdir(parents=True, exist_ok=True)

    log_path = audit_dir / AUDIT_LOG_NAME
    log = EventLog(log_path, echo_console=True, verbose=False)

    log.banner(
        "INICIO DE AUDITORÍA NOXGUARDIAN",
        [
            f"directorio : {audit_dir}",
            f"timestamp  : {timestamp}",
        ],
    )

    # -- tool detection -------------------------------------------------------
    runner = NmapRunner()
    oui = OuiResolver(extra_file=oui_file, use_system_sources=not no_system_oui)

    privileges = netinfo.detect_privileges(runner.path)
    network = netinfo.detect_network(subnet)

    tool_versions: Dict[str, str] = {
        "nmap": nmap_version(runner.path) or "no disponible",
        "dig": dig_version() or "no disponible",
        "curl": curl_version() or "no disponible",
        "sslscan": sslscan_version() or "no disponible (fallback stdlib ssl)",
        "tshark": tshark_version() or "no disponible",
        "searchsploit": searchsploit_version() or "no disponible",
    }

    log.note(
        f"[i] Subred: {network.cidr}  |  Interfaz: {network.interface}  |  "
        f"Privilegios ARP: {'sí' if privileges.can_arp_scan else 'no'}"
    )
    for tool, ver in tool_versions.items():
        log.note(f"[i] {tool}: {ver}")

    # -- state manager --------------------------------------------------------
    state = StateManager(oui=oui, absence_cycles=1)

    # =========================================================================
    # FASE 1 — Presencia
    # =========================================================================
    log.note("[*] Fase 1: escaneo de presencia...")

    presence = PresenceScanner(
        subnet=network.cidr or "",
        runner=runner,
        privileged=privileges.can_arp_scan and not force_fallback,
        timeout=300.0,
        force_fallback=force_fallback,
        local_ip=network.local_ip,
        local_mac=netinfo.interface_mac(network.interface),
    )
    presence_result = presence.scan()
    events = state.apply_presence(presence_result)
    log.write_events(events)

    live_ips = sorted(set(state.live_ips()))
    log.note(f"[*] Presencia: {len(live_ips)} hosts vivos: {', '.join(live_ips[:20])}")

    # Save raw nmap -sn output if available.
    # PresenceScanner does not expose raw text directly, so we reconstruct it.
    presence_summary = (
        f"# Presencia detectada via: {presence_result.method}\n"
        f"# Duracion: {presence_result.duration:.1f}s\n"
        f"# Hosts vivos ({len(presence_result.hosts)}):\n"
    )
    for host in presence_result.hosts:
        presence_summary += (
            f"  {host.ip}  MAC:{host.mac or '—'}  HOST:{host.hostname or '—'}\n"
        )
    (dirs["presence"] / "nmap_sn.txt").write_text(presence_summary, encoding="utf-8")

    if not live_ips:
        log.note("[!] No se encontraron hosts vivos. Terminando auditoría.")
        _write_state(state, dirs["summary"] / AUDIT_STATE_NAME, log)
        log.close()
        return 0

    # =========================================================================
    # FASE 2 — Escaneo profundo de puertos
    # =========================================================================
    log.note(f"[*] Fase 2: escaneo profundo de {len(live_ips)} hosts...")

    normalized_ports = ports_profile.normalize(ports)
    port_scanner = PortScanner(
        runner=runner,
        ports=normalized_ports,
        timeout=900.0,
        workers=workers,
    )

    def on_host_scan(scan) -> None:
        host_events = state.apply_host_scan(scan.ip, scan)
        log.write_events(host_events)
        # Save raw nmap -sV output (approximation via port records)
        raw = f"# nmap -sV {scan.ip}\n"
        if scan.error:
            raw += f"# ERROR: {scan.error}\n"
        else:
            for port in scan.open_ports:
                raw += f"{port.port}/{port.protocol}  open  {port.service} {port.version}\n"
        txt = dirs["ports"] / f"nmap_sV_{scan.ip}.txt"
        try:
            txt.write_text(raw, encoding="utf-8")
        except OSError:
            pass

    state.begin_port_cycle()
    port_result = port_scanner.scan_hosts(live_ips, on_host=on_host_scan)
    log.write_events(state.finish_port_cycle(port_result))

    # =========================================================================
    # FASE 3 — DNS + HTTP en paralelo por host
    # =========================================================================
    log.note("[*] Fase 3: resolución DNS + inspección HTTP...")

    dns_runner = DnsRunner(timeout=15.0, local_domain=local_domain)
    http_runner = HttpRunner(timeout=10.0)
    ssl_runner = SslRunner(timeout=15.0)

    def process_host_dns_http(ip: str) -> None:
        device = state._find_by_ip(ip)  # noqa: SLF001 - internal access for performance

        # DNS
        if dns_runner.available:
            dns_result = dns_runner.run(ip, dirs["dns"])
            if dns_result.ptr and device:
                with state._lock:  # noqa: SLF001
                    device.dns_ptr = dns_result.ptr
                    if not device.hostname:
                        device.hostname = dns_result.ptr
            if dns_result.error:
                log.note(f"[E] DNS {ip}: {dns_result.error}")
        else:
            log.note("[!] dig no disponible; se omite resolución DNS")

        # HTTP -- only if web ports are currently open
        if not device:
            return
        open_web_ports: List[int] = [
            record.port
            for record in device.ports.values()
            if record.currently_open and record.port in WEB_PORTS
        ]
        for port in open_web_ports:
            http_result = http_runner.run(ip, port, dirs["http"])
            if http_result.error:
                log.note(f"[E] HTTP {ip}:{port}: {http_result.error}")
            with state._lock:  # noqa: SLF001
                device.http_headers[str(port)] = http_result.to_dict()

        # SSL/TLS scan via sslscan (with stdlib fallback)
        for precord in device.ports.values():
            if precord.currently_open and ssl_runner.is_ssl_port(precord.port, precord.service):
                ssl_result = ssl_runner.run(ip, precord.port, dirs["http"])
                if ssl_result.error:
                    log.note(f"[E] SSL {ip}:{precord.port}: {ssl_result.error}")
                else:
                    protos = ", ".join(ssl_result.protocols_enabled) or "TLS"
                    log.note(f"[+] SSL {ip}:{precord.port}: {protos} ({ssl_result.tool_used})")
                with state._lock:  # noqa: SLF001
                    device.ssl_results[str(precord.port)] = ssl_result.to_dict()

    actual_workers = min(workers, len(live_ips))
    with ThreadPoolExecutor(max_workers=actual_workers, thread_name_prefix="nox-audit") as pool:
        futures = {pool.submit(process_host_dns_http, ip): ip for ip in live_ips}
        for future in as_completed(futures):
            ip = futures[future]
            try:
                future.result()
            except Exception as exc:  # noqa: BLE001
                log.note(f"[E] error interno en DNS/HTTP de {ip}: {exc!r}")

    # =========================================================================
    # FASE 4 — Vulnerabilidades
    # =========================================================================
    log.note("[*] Fase 4: búsqueda de vulnerabilidades...")

    vuln_runner = VulnRunner(nvd_api_key=nvd_api_key)

    # Deduplicate (service, version) pairs across all hosts.
    seen_pairs: Set[tuple] = set()
    for device in state.snapshot_devices():
        for record in device.ports.values():
            if not record.currently_open:
                continue
            svc = record.service.strip()
            ver = record.version.strip()
            if not svc or not ver or ver.lower() == "unknown":
                continue
            pair = (svc, ver)
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)

            vuln_result = vuln_runner.run(svc, ver, dirs["vulns"])
            if vuln_result.error:
                log.note(f"[E] vuln {svc} {ver}: {vuln_result.error}")
            if not vuln_result.has_findings:
                continue

            # Attach the finding to every device that has this (service, version).
            for dev in state.snapshot_devices():
                for prec in dev.ports.values():
                    if prec.service.strip() == svc and prec.version.strip() == ver:
                        with state._lock:  # noqa: SLF001
                            dev.vuln_findings.append(vuln_result.to_dict())
                        break

            if vuln_result.cves:
                log.note(
                    f"[!] {svc} {ver}: {len(vuln_result.cves)} CVE(s) encontrado(s) "
                    f"(CVSS max {vuln_result.highest_cvss})"
                )

    # =========================================================================
    # FASE 5 — Captura de paquetes (secuencial)
    # =========================================================================
    log.note("[*] Fase 5: evidencia de captura de paquetes (tshark)...")

    interface = network.interface or ""
    if interface:
        pcap_runner = PcapRunner()
        if pcap_runner.available:
            for ip in live_ips:
                log.note(f"[*] captura pcap: {ip} en {interface}")
                pcap_result = pcap_runner.run(ip, interface, dirs["pcap"])
                if pcap_result.error:
                    log.note(f"[E] pcap {ip}: {pcap_result.error}")
                device = state._find_by_ip(ip)  # noqa: SLF001
                if device:
                    with state._lock:  # noqa: SLF001
                        device.pcap_evidence = pcap_result.to_dict()
        else:
            log.note("[!] tshark no disponible o sin permisos; se omite la captura pcap")
    else:
        log.note("[!] interfaz no detectada; se omite la captura pcap")

    # =========================================================================
    # FASE 6 — Checkpoint final
    # =========================================================================
    log.note("[S] Guardando audit_state.json...")
    _write_state(state, dirs["summary"] / AUDIT_STATE_NAME, log)

    # =========================================================================
    # FASE 7 — Informe Word
    # =========================================================================
    report_path: Optional[Path] = None
    template_path = template or Path("Plantilla_Informe_Auditoria_Seguridad.docx")
    if template_path.is_file():
        try:
            from .exporters.docx_report import generate

            date_label = time.strftime("%Y-%m-%d")
            report_path = dirs["report"] / f"Auditoria_{date_label}.docx"
            generate(
                state=state,
                template_path=template_path,
                output_path=report_path,
                audit_dir=audit_dir,
                tool_versions=tool_versions,
            )
            log.note(f"[+] Informe Word generado: {report_path}")
        except ImportError:
            log.note("[!] python-docx no instalado; se omite la generación del informe Word")
        except Exception as exc:  # noqa: BLE001
            log.note(f"[E] no se pudo generar el informe Word: {exc}")
    else:
        log.note(
            f"[!] Plantilla '{template_path}' no encontrada; "
            "se omite la generación del informe Word. "
            "Pasa la ruta con --template."
        )

    # =========================================================================
    # Resumen final
    # =========================================================================
    devices = state.snapshot_devices()
    total_vulns = sum(len(d.vuln_findings) for d in devices)
    log.banner(
        "AUDITORÍA COMPLETADA",
        [
            f"hosts analizados   : {len(live_ips)}",
            f"dispositivos únicos: {len(devices)}",
            f"hallazgos de vuln. : {total_vulns}",
            f"directorio         : {audit_dir}",
            f"informe Word       : {report_path or 'no generado'}",
        ],
    )
    log.close()
    return 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_state(state: StateManager, path: Path, log: EventLog) -> None:
    """Write the full state to *path* as JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    store = CheckpointStore(path)
    payload = state.to_dict()
    if store.save(payload):
        log.note(f"[S] audit_state.json guardado en {path}")
    else:
        log.note(f"[E] no se pudo guardar audit_state.json: {store.last_error}")


# ---------------------------------------------------------------------------
# CLI entry point (called from cli.py's audit subcommand)
# ---------------------------------------------------------------------------


def main(argv: Optional[List[str]] = None) -> int:
    """Minimal CLI wrapper for direct invocation."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="audit_runner",
        description="Auditoría de red doméstica de un solo comando.",
    )
    parser.add_argument("--subnet", default=None, metavar="CIDR")
    parser.add_argument("--template", type=Path, default=None, metavar="DOCX")
    parser.add_argument("--workers", type=int, default=2, metavar="N")
    parser.add_argument("--ports", default=ports_profile.DEFAULT_PORT_SPEC)
    parser.add_argument("--force-fallback", action="store_true")
    parser.add_argument("--oui-file", type=Path, default=None)
    parser.add_argument("--no-system-oui", action="store_true")
    parser.add_argument("--output-dir", type=Path, default=Path("."), metavar="DIR")
    parser.add_argument("--local-domain", default=None, metavar="DOMINIO")
    parser.add_argument("--nvd-api-key", default=None, metavar="APIKEY")

    args = parser.parse_args(argv)
    return run_audit(
        subnet=args.subnet,
        template=args.template,
        workers=args.workers,
        ports=args.ports,
        force_fallback=args.force_fallback,
        oui_file=args.oui_file,
        no_system_oui=args.no_system_oui,
        base_output_dir=args.output_dir,
        local_domain=args.local_domain,
        nvd_api_key=args.nvd_api_key,
    )


if __name__ == "__main__":
    sys.exit(main())
