"""Punto de entrada CLI de NoxGuardian y manejo de senales.

Uso tipico:
    sudo python3 -m noxguardian
    python3 -m noxguardian --presence-interval 2 --deepscan-interval 15
    python3 -m noxguardian --resume --output-dir ./salida

Se detiene con Ctrl+C: eso dispara el cierre ordenado (ultimo checkpoint +
reporte Excel + resumen por consola).
"""

from __future__ import annotations

import argparse
import os
import signal
import sys
import time
from pathlib import Path
from typing import List, Optional

from . import __version__, netinfo, ports_profile
from .config import (
    DEFAULT_CHECKPOINT_INTERVAL_MIN,
    DEFAULT_DEEPSCAN_INTERVAL_MIN,
    DEFAULT_PRESENCE_INTERVAL_MIN,
    Config,
)
from .engine import GuardianEngine
from .exporters.checkpoint import CheckpointError, CheckpointStore
from .exporters.txtlog import EventLog
from .oui import OuiResolver
from .scanners.nmap_runner import NmapRunner, nmap_version
from .scanners.ports import PortScanner
from .scanners.presence import PresenceScanner
from .state import EVT_ERROR, EVT_INFO, StateManager

BANNER = r"""
    _   __           ______                     ___
   / | / /___  _  __/ ____/_  ______ __________/ (_)___ _____
  /  |/ / __ \| |/_/ / __/ / / / __ `/ ___/ __  / / __ `/ __ \
 / /|  / /_/ />  </ /_/ / /_/ / /_/ / /  / /_/ / / /_/ / / / /
/_/ |_/\____/_/|_|\____/\__,_/\__,_/_/   \__,_/_/\__,_/_/ /_/
"""


# ---------------------------------------------------------------------------
# Argumentos
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="noxguardian",
        description=(
            "Monitorizacion continua de una LAN domestica: presencia de "
            "dispositivos, puertos abiertos, log en vivo y reporte Excel al salir."
        ),
        epilog=(
            "Se detiene con Ctrl+C, momento en el que genera el reporte final. "
            "Para el barrido ARP hace falta root (o cap_net_raw en nmap); sin "
            "privilegios cae automaticamente a un barrido TCP sin MAC fiable."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    timing = parser.add_argument_group("ritmo de escaneo")
    timing.add_argument(
        "--presence-interval",
        type=float,
        default=DEFAULT_PRESENCE_INTERVAL_MIN,
        metavar="MIN",
        help="minutos entre escaneos de presencia",
    )
    timing.add_argument(
        "--deepscan-interval",
        type=float,
        default=DEFAULT_DEEPSCAN_INTERVAL_MIN,
        metavar="MIN",
        help="minutos entre escaneos profundos de puertos",
    )
    timing.add_argument(
        "--checkpoint-interval",
        type=float,
        default=DEFAULT_CHECKPOINT_INTERVAL_MIN,
        metavar="MIN",
        help="minutos entre guardados de checkpoint JSON",
    )

    scanning = parser.add_argument_group("alcance del escaneo")
    scanning.add_argument(
        "--ports",
        default=ports_profile.DEFAULT_PORT_SPEC,
        metavar="SPEC",
        help=(
            f"puertos del escaneo profundo, formato nmap (por defecto "
            f"{ports_profile.DEFAULT_PORT_COUNT} puertos comunes+extendidos)"
        ),
    )
    scanning.add_argument(
        "--subnet",
        default=None,
        metavar="CIDR",
        help="subred a monitorizar; por defecto se autodetecta (ej. 192.168.1.0/24)",
    )
    scanning.add_argument(
        "--no-deepscan",
        action="store_true",
        help="desactiva el escaneo de puertos (solo presencia)",
    )
    scanning.add_argument(
        "--deepscan-workers",
        type=int,
        default=2,
        metavar="N",
        help="hosts escaneados en paralelo en el ciclo profundo",
    )
    scanning.add_argument(
        "--absence-cycles",
        type=int,
        default=2,
        metavar="N",
        help=(
            "ciclos de presencia seguidos sin responder antes de dar un "
            "dispositivo por ausente (1 = inmediato; 2 evita falsas salidas de "
            "moviles en ahorro de energia)"
        ),
    )
    scanning.add_argument(
        "--force-fallback",
        action="store_true",
        help="fuerza el barrido TCP sin privilegios aunque haya root",
    )
    scanning.add_argument(
        "--presence-timeout",
        type=float,
        default=300.0,
        metavar="SEG",
        help="timeout de un escaneo de presencia",
    )
    scanning.add_argument(
        "--deepscan-timeout",
        type=float,
        default=900.0,
        metavar="SEG",
        help="timeout del escaneo profundo de un host",
    )

    output = parser.add_argument_group("salida y persistencia")
    output.add_argument(
        "--output-dir",
        type=Path,
        default=Path("noxguardian_out"),
        metavar="DIR",
        help="carpeta donde se escriben log, checkpoints y Excel",
    )
    output.add_argument(
        "--resume",
        action="store_true",
        help="reanuda la sesion desde el checkpoint JSON de la carpeta de salida",
    )
    output.add_argument(
        "--excel-on-checkpoint",
        action="store_true",
        help="genera tambien un Excel en cada checkpoint, no solo al final",
    )
    output.add_argument(
        "--oui-file",
        type=Path,
        default=None,
        metavar="FICHERO",
        help="tabla OUI adicional (formato nmap-mac-prefixes, manuf u oui.txt)",
    )
    output.add_argument(
        "--no-system-oui",
        action="store_true",
        help="no cargar las bases OUI del sistema, solo la incluida",
    )
    output.add_argument("-v", "--verbose", action="store_true", help="muestra todos los eventos")

    info = parser.add_argument_group("informacion")
    info.add_argument("--version", action="version", version=f"NoxGuardian {__version__}")
    info.add_argument(
        "--list-ports",
        action="store_true",
        help="imprime la especificacion de puertos por defecto y sale",
    )
    info.add_argument(
        "--check",
        action="store_true",
        help="ejecuta las comprobaciones de entorno (nmap, privilegios, red) y sale",
    )

    # -- subcomando audit ----------------------------------------------------
    subparsers = parser.add_subparsers(dest="subcommand", metavar="SUBCOMANDO")
    audit_p = subparsers.add_parser(
        "audit",
        help="auditoría completa de un solo golpe: presencia, puertos, DNS, HTTP, "
             "vulnerabilidades, captura pcap e informe Word.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    audit_p.add_argument(
        "--subnet",
        default=None,
        metavar="CIDR",
        help="subred a auditar (por defecto se autodetecta)",
    )
    audit_p.add_argument(
        "--template",
        type=Path,
        default=None,
        metavar="DOCX",
        help="ruta de la plantilla Word para el informe final",
    )
    audit_p.add_argument(
        "--workers",
        type=int,
        default=2,
        metavar="N",
        help="hosts analizados en paralelo (DNS/HTTP)",
    )
    audit_p.add_argument(
        "--ports",
        default=ports_profile.DEFAULT_PORT_SPEC,
        metavar="SPEC",
        help="especificacion de puertos para el escaneo profundo",
    )
    audit_p.add_argument(
        "--output-dir",
        type=Path,
        default=Path("."),
        metavar="DIR",
        help="directorio raiz donde se crea la carpeta de auditoría",
    )
    audit_p.add_argument(
        "--force-fallback",
        action="store_true",
        help="fuerza el barrido TCP aunque haya root",
    )
    audit_p.add_argument(
        "--oui-file",
        type=Path,
        default=None,
        metavar="FICHERO",
    )
    audit_p.add_argument(
        "--no-system-oui",
        action="store_true",
    )
    audit_p.add_argument(
        "--local-domain",
        default=None,
        metavar="DOMINIO",
        help="sufijo DNS local para resolución forward (ej. home.lan)",
    )
    audit_p.add_argument(
        "--nvd-api-key",
        default=None,
        metavar="APIKEY",
        help="API key de NVD (opcional; sin ella el rate-limit es más restrictivo)",
    )

    return parser


def build_config(args: argparse.Namespace) -> Config:
    """Valida los argumentos y construye la configuracion efectiva."""
    if args.presence_interval <= 0:
        raise ValueError("--presence-interval debe ser mayor que 0")
    if args.deepscan_interval <= 0:
        raise ValueError("--deepscan-interval debe ser mayor que 0")
    if args.checkpoint_interval <= 0:
        raise ValueError("--checkpoint-interval debe ser mayor que 0")
    if args.absence_cycles < 1:
        raise ValueError("--absence-cycles debe ser al menos 1")
    if args.deepscan_workers < 1:
        raise ValueError("--deepscan-workers debe ser al menos 1")

    ports = ports_profile.normalize(args.ports)  # lanza ValueError si es invalida

    return Config(
        output_dir=Path(args.output_dir).expanduser().resolve(),
        subnet=args.subnet,
        presence_interval=args.presence_interval * 60,
        deepscan_interval=args.deepscan_interval * 60,
        checkpoint_interval=args.checkpoint_interval * 60,
        ports=ports,
        resume=args.resume,
        absence_cycles=args.absence_cycles,
        deepscan_workers=args.deepscan_workers,
        deepscan_enabled=not args.no_deepscan,
        excel_on_checkpoint=args.excel_on_checkpoint,
        force_fallback=args.force_fallback,
        presence_timeout=args.presence_timeout,
        deepscan_timeout=args.deepscan_timeout,
        oui_file=args.oui_file,
        no_system_oui=args.no_system_oui,
        verbose=args.verbose,
    )


# ---------------------------------------------------------------------------
# Comprobaciones de entorno
# ---------------------------------------------------------------------------


def preflight(config: Config, runner: NmapRunner) -> List[str]:
    """Rellena config con lo detectado y devuelve la lista de avisos."""
    warnings: List[str] = []

    if not runner.available:
        warnings.append(
            "nmap NO esta instalado: no habra escaneo de puertos y la presencia "
            "usara el barrido TCP sin privilegios. Instalalo con "
            "'apt install nmap' o 'pkg install nmap'."
        )

    privileges = netinfo.detect_privileges(runner.path)
    config.privileged = privileges.can_arp_scan
    if not privileges.can_arp_scan:
        warnings.append(
            f"SIN PRIVILEGIOS para barrido ARP ({privileges.reason}). Se usara "
            "un barrido TCP connect: funciona, pero las MAC solo se obtendran "
            "si aparecen en la cache ARP del kernel; el resto quedaran como "
            "'no disponible'. Para MAC fiables ejecuta con sudo."
        )

    network = netinfo.detect_network(config.subnet)
    config.resolved_subnet = network.cidr
    config.interface = network.interface
    config.local_ip = network.local_ip or netinfo.local_ip_via_udp()
    config.local_mac = netinfo.interface_mac(network.interface)
    if network.host_count > 4096:
        warnings.append(
            f"la subred detectada ({network.cidr}) tiene {network.host_count} "
            "direcciones: los ciclos seran lentos. Considera acotarla con --subnet."
        )

    try:
        from .exporters.excel import OPENPYXL_AVAILABLE
    except ImportError:
        OPENPYXL_AVAILABLE = False
    if not OPENPYXL_AVAILABLE:
        warnings.append(
            "openpyxl NO esta instalado: al terminar NO se generara el Excel "
            "(el log .txt y el checkpoint JSON si). Instalalo con "
            "'pip install openpyxl'."
        )

    return warnings


def print_environment(config: Config, runner: NmapRunner, oui: OuiResolver) -> List[str]:
    version = nmap_version(runner.path) if runner.available else None
    return [
        f"version         : NoxGuardian {__version__}  (python {sys.version.split()[0]})",
        f"plataforma      : {netinfo.platform_label()}",
        f"nmap            : {version or 'NO DISPONIBLE'}",
        f"tabla OUI       : {oui.describe()}",
        *config.summary_lines(),
    ]


# ---------------------------------------------------------------------------
# Senales
# ---------------------------------------------------------------------------


def install_signal_handlers(engine: GuardianEngine) -> None:
    """SIGINT/SIGTERM disparan el cierre ordenado; la segunda senal sale ya."""

    def handler(signum: int, _frame: object) -> None:
        name = signal.Signals(signum).name
        if engine.stopping:
            print(
                f"\n[!] segunda {name} recibida: saliendo inmediatamente "
                "(el log y el ultimo checkpoint ya estan en disco)",
                file=sys.stderr,
                flush=True,
            )
            os._exit(130)
        print(
            f"\n[!] {name} recibida: cerrando de forma ordenada, "
            "generando checkpoint y reporte... (pulsa Ctrl+C de nuevo para forzar)",
            flush=True,
        )
        engine.request_stop(f"senal {name}")

    signal.signal(signal.SIGINT, handler)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, handler)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # -- subcomando audit -----------------------------------------------------
    if getattr(args, "subcommand", None) == "audit":
        try:
            from .audit_runner import run_audit
        except ImportError:
            from audit_runner import run_audit

        return run_audit(
            subnet=getattr(args, "subnet", None),
            template=getattr(args, "template", None),
            workers=getattr(args, "workers", 2),
            ports=getattr(args, "ports", ports_profile.DEFAULT_PORT_SPEC),
            force_fallback=getattr(args, "force_fallback", False),
            oui_file=getattr(args, "oui_file", None),
            no_system_oui=getattr(args, "no_system_oui", False),
            base_output_dir=getattr(args, "output_dir", Path(".")),
            local_domain=getattr(args, "local_domain", None),
            nvd_api_key=getattr(args, "nvd_api_key", None),
        )

    if args.list_ports:
        spec = ports_profile.normalize(args.ports)
        print(f"# {ports_profile.count(spec)} puertos")
        print(spec)
        return 0

    try:
        config = build_config(args)
    except ValueError as exc:
        parser.error(str(exc))
        return 2  # inalcanzable: parser.error sale con 2

    runner = NmapRunner()
    oui = OuiResolver(
        extra_file=config.oui_file,
        use_system_sources=not config.no_system_oui,
    )

    try:
        warnings = preflight(config, runner)
    except (RuntimeError, ValueError) as exc:
        print(f"[E] {exc}", file=sys.stderr)
        return 1

    config.scan_method = (
        "nmap -sn (ARP)" if (runner.available and config.privileged and not config.force_fallback)
        else "TCP connect sweep"
    )

    if args.check:
        print(BANNER)
        for line in print_environment(config, runner, oui):
            print(f"    {line}")
        print()
        for warning in warnings:
            print(f"    [!] {warning}")
        print("\n    comprobacion completada (no se ha monitorizado nada).")
        return 0

    config.output_dir.mkdir(parents=True, exist_ok=True)

    state = StateManager(oui=oui, absence_cycles=config.absence_cycles)
    checkpoints = CheckpointStore(config.checkpoint_path)
    log = EventLog(config.log_path, echo_console=True, verbose=config.verbose)

    print(BANNER)
    log.banner(f"INICIO DE SESION NOXGUARDIAN {__version__}", print_environment(config, runner, oui))
    for warning in warnings:
        log.write_event(state.note(EVT_INFO, f"AVISO: {warning}"), force_console=True)

    # -- reanudacion ---------------------------------------------------------
    if config.resume:
        try:
            state.load_dict(checkpoints.load())
            log.write_event(
                state.note(
                    EVT_INFO,
                    f"sesion reanudada desde {checkpoints.path}: "
                    f"{len(state.devices)} dispositivos y {len(state.events)} eventos "
                    f"previos, {state.carried_runtime / 60:.1f} min ya acumulados "
                    f"(reanudacion #{state.resume_count})",
                ),
                force_console=True,
            )
        except (CheckpointError, ValueError) as exc:
            log.write_event(
                state.note(EVT_ERROR, f"no se pudo reanudar: {exc}. Se empieza de cero.")
            )
    elif checkpoints.exists:
        log.write_event(
            state.note(
                EVT_INFO,
                f"existe un checkpoint previo en {checkpoints.path} pero no se paso "
                "--resume: se empieza una sesion nueva y ese fichero se sobrescribira",
            ),
            force_console=True,
        )

    # -- escaneres y motor ---------------------------------------------------
    engine_holder: dict[str, GuardianEngine] = {}

    presence = PresenceScanner(
        subnet=config.resolved_subnet or "",
        runner=runner,
        privileged=config.privileged,
        timeout=config.presence_timeout,
        force_fallback=config.force_fallback,
        should_stop=lambda: engine_holder["engine"].stopping if engine_holder else False,
        local_ip=config.local_ip,
        local_mac=config.local_mac,
    )
    ports = (
        PortScanner(
            runner=runner,
            ports=config.ports,
            timeout=config.deepscan_timeout,
            workers=config.deepscan_workers,
            should_stop=lambda: engine_holder["engine"].stopping if engine_holder else False,
        )
        if config.deepscan_enabled and runner.available
        else None
    )
    if config.deepscan_enabled and ports is None:
        log.write_event(
            state.note(EVT_ERROR, "escaneo profundo desactivado: nmap no esta disponible")
        )

    engine = GuardianEngine(
        config=config,
        state=state,
        log=log,
        checkpoints=checkpoints,
        runner=runner,
        presence=presence,
        ports=ports,
    )
    engine_holder["engine"] = engine

    install_signal_handlers(engine)

    log.note("monitorizando... (Ctrl+C para parar y generar el reporte)")
    started = time.time()

    try:
        engine.start()
        engine.run_forever()
    except KeyboardInterrupt:
        # Red de seguridad: si el Ctrl+C llega fuera del handler.
        engine.request_stop("KeyboardInterrupt")
    except Exception as exc:  # noqa: BLE001 - queremos reporte incluso si algo peta
        log.write_event(
            state.note(EVT_ERROR, f"error fatal en el bucle principal: {exc!r}")
        )
        engine.request_stop(f"error fatal: {exc!r}")
        engine.shutdown()
        return 1
    finally:
        engine.shutdown()

    elapsed = time.time() - started
    if elapsed < 1.0:
        print("[i] la sesion duro menos de un segundo; revisa el log por si hubo errores.")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
