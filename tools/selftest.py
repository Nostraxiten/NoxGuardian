#!/usr/bin/env python3
"""Auto-test de NoxGuardian: ejercita todo el pipeline sin tocar la red.

Simula una sesion de monitorizacion con dispositivos que entran y salen,
puertos que se abren y se cierran, un guardado/reanudacion de checkpoint y la
generacion del Excel; despues verifica el contenido del libro celda a celda.

    python3 tools/selftest.py            # ejecuta y limpia
    python3 tools/selftest.py --keep DIR # deja los ficheros generados en DIR

Devuelve 0 si todo pasa, 1 si algo falla.
"""

from __future__ import annotations

import argparse
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from noxguardian import ports_profile  # noqa: E402
from noxguardian.exporters.checkpoint import CheckpointStore  # noqa: E402
from noxguardian.exporters.txtlog import EventLog  # noqa: E402
from noxguardian.oui import OuiResolver  # noqa: E402
from noxguardian.scanners.ports import HostPortScan, OpenPort, PortResult  # noqa: E402
from noxguardian.scanners.presence import PresenceHost, PresenceResult  # noqa: E402
from noxguardian.state import (  # noqa: E402
    EVT_DEVICE_JOIN,
    EVT_DEVICE_LEAVE,
    EVT_PORT_CLOSE,
    EVT_PORT_OPEN,
    StateManager,
    format_duration,
)

FAILURES: List[str] = []
CHECKS = 0


def check(condition: bool, description: str) -> bool:
    global CHECKS
    CHECKS += 1
    if condition:
        print(f"  [ok] {description}")
        return True
    print(f"  [FALLO] {description}")
    FAILURES.append(description)
    return False


def equals(actual: object, expected: object, description: str) -> bool:
    return check(actual == expected, f"{description} (esperado {expected!r}, obtenido {actual!r})")


def section(title: str) -> None:
    print(f"\n=== {title} ===")


# ---------------------------------------------------------------------------
# Datos sinteticos
# ---------------------------------------------------------------------------

MOVIL = "b8:27:eb:aa:bb:cc"       # Raspberry Pi en la tabla incluida
PORTATIL = "3c:15:c2:11:22:33"    # Apple
IOT = "24:0a:c4:99:88:77"         # Espressif
RANDOM_MAC = "da:a1:19:00:00:01"  # MAC localmente administrada


def presence(hosts: List[PresenceHost], when: float, errors: Optional[List[str]] = None):
    return PresenceResult(
        hosts=hosts,
        method="simulado",
        duration=0.4,
        started_at=when,
        errors=errors or [],
        macs_resolved=sum(1 for host in hosts if host.mac),
    )


def ports_result(when: float, scans: dict) -> PortResult:
    result = PortResult(started_at=when, targets=len(scans), duration=1.5)
    result.scans = scans
    return result


# ---------------------------------------------------------------------------
# Escenario
# ---------------------------------------------------------------------------


def run_scenario(state: StateManager, log: EventLog, base: float) -> None:
    """Ciclos de presencia y puertos separados 60s entre si."""

    def at(minute: float) -> float:
        return base + minute * 60

    # t=0: entran el movil y el portatil
    log.write_events(
        state.apply_presence(
            presence(
                [
                    PresenceHost(ip="192.168.1.10", mac=MOVIL, hostname="rpi.local"),
                    PresenceHost(ip="192.168.1.20", mac=PORTATIL),
                ],
                at(0),
            )
        )
    )

    # t=1: siguen los dos, ademas aparece un host sin MAC (modo sin privilegios)
    log.write_events(
        state.apply_presence(
            presence(
                [
                    PresenceHost(ip="192.168.1.10", mac=MOVIL, hostname="rpi.local"),
                    PresenceHost(ip="192.168.1.20", mac=PORTATIL),
                    PresenceHost(ip="192.168.1.30"),
                ],
                at(1),
            )
        )
    )

    # t=2: el host sin MAC revela su MAC -> debe fusionarse, no duplicarse
    log.write_events(
        state.apply_presence(
            presence(
                [
                    PresenceHost(ip="192.168.1.10", mac=MOVIL, hostname="rpi.local"),
                    PresenceHost(ip="192.168.1.30", mac=IOT),
                ],
                at(2),
            )
        )
    )

    # t=3: el portatil sigue sin aparecer -> con absence_cycles=2 ya sale
    log.write_events(
        state.apply_presence(
            presence(
                [
                    PresenceHost(ip="192.168.1.10", mac=MOVIL, hostname="rpi.local"),
                    PresenceHost(ip="192.168.1.30", mac=IOT),
                ],
                at(3),
            )
        )
    )

    # t=4: escaneo profundo sobre los dos vivos
    log.write_events(
        state.apply_ports(
            ports_result(
                at(4),
                {
                    "192.168.1.10": HostPortScan(
                        ip="192.168.1.10",
                        open_ports=[
                            OpenPort(22, "tcp", "ssh", "OpenSSH 9.2p1"),
                            OpenPort(80, "tcp", "http", "nginx 1.22.1"),
                        ],
                    ),
                    "192.168.1.30": HostPortScan(
                        ip="192.168.1.30",
                        open_ports=[OpenPort(8080, "tcp", "http", "ESP-IDF httpd")],
                    ),
                },
            )
        )
    )

    # t=5: un ciclo de presencia que falla entero: nadie debe "salir" por ello
    log.write_events(
        state.apply_presence(presence([], at(5), errors=["timeout simulado de nmap"]))
    )

    # t=6: vuelve el portatil (segunda aparicion) con IP distinta (DHCP)
    log.write_events(
        state.apply_presence(
            presence(
                [
                    PresenceHost(ip="192.168.1.10", mac=MOVIL, hostname="rpi.local"),
                    PresenceHost(ip="192.168.1.30", mac=IOT),
                    PresenceHost(ip="192.168.1.55", mac=PORTATIL),
                    PresenceHost(ip="192.168.1.77", mac=RANDOM_MAC),
                ],
                at(6),
            )
        )
    )

    # t=7: el 80 se cierra, aparece el 443, y un host no responde al deep scan
    log.write_events(
        state.apply_ports(
            ports_result(
                at(7),
                {
                    "192.168.1.10": HostPortScan(
                        ip="192.168.1.10",
                        open_ports=[
                            OpenPort(22, "tcp", "ssh", "OpenSSH 9.2p1"),
                            OpenPort(443, "tcp", "ssl/http", "nginx 1.22.1"),
                        ],
                    ),
                    "192.168.1.30": HostPortScan(ip="192.168.1.30", unreachable=True),
                    "192.168.1.55": HostPortScan(
                        ip="192.168.1.55", error="timeout: simulado"
                    ),
                },
            )
        )
    )

    # t=8: el 80 vuelve a abrirse -> debe generar PORT_REOPEN y 2 ventanas
    log.write_events(
        state.apply_ports(
            ports_result(
                at(8),
                {
                    "192.168.1.10": HostPortScan(
                        ip="192.168.1.10",
                        open_ports=[
                            OpenPort(22, "tcp", "ssh", "OpenSSH 9.2p1"),
                            OpenPort(80, "tcp", "http", "nginx 1.22.1"),
                            OpenPort(443, "tcp", "ssl/http", "nginx 1.22.1"),
                        ],
                    )
                },
            )
        )
    )


# ---------------------------------------------------------------------------
# Verificaciones
# ---------------------------------------------------------------------------


def verify_state(state: StateManager, base: float) -> None:
    section("Modelo de datos")
    devices = {device.key: device for device in state.snapshot_devices()}

    equals(len(devices), 4, "dispositivos unicos (movil, portatil, iot, mac aleatoria)")
    check("ip:192.168.1.30" not in devices, "el registro provisional por IP se fusiono")

    iot = devices.get(IOT)
    if check(iot is not None, "el dispositivo IoT existe con clave MAC"):
        equals(iot.first_seen, base + 60, "conserva el first_seen del registro provisional")
        equals(iot.vendor, "Espressif", "fabricante resuelto por la tabla OUI incluida")
        equals(iot.appearances, 1, "no se contabilizo una entrada duplicada al fusionar")

    portatil = devices.get(PORTATIL)
    if check(portatil is not None, "el portatil existe"):
        equals(portatil.appearances, 2, "el portatil entro dos veces")
        equals(portatil.departures, 1, "el portatil salio una vez")
        equals(portatil.ip, "192.168.1.55", "el portatil refleja su nueva IP por DHCP")
        equals(len(portatil.sessions), 2, "el portatil tiene dos estancias")
        first = portatil.sessions[0]
        equals(first.end, base + 60, "la estancia cerro en la ultima confirmacion real")
        equals(portatil.vendor, "Apple", "fabricante del portatil")

    movil = devices.get(MOVIL)
    if check(movil is not None, "el movil existe"):
        equals(movil.departures, 0, "el movil nunca salio pese al ciclo fallido")
        equals(movil.hostname, "rpi.local", "hostname conservado")
        equals(len(movil.ports), 3, "el movil acumula 3 puertos historicos (22, 80, 443)")
        puerto80 = movil.ports.get("tcp/80")
        if check(puerto80 is not None, "el puerto 80 esta registrado"):
            equals(len(puerto80.windows), 2, "el puerto 80 tiene dos ventanas de apertura")
            check(puerto80.currently_open, "el puerto 80 esta abierto al final")
            check(puerto80.windows[0][1] is not None, "la primera ventana del 80 esta cerrada")
        puerto443 = movil.ports.get("tcp/443")
        if check(puerto443 is not None, "el puerto 443 esta registrado"):
            equals(puerto443.service, "ssl/http", "servicio con tunel ssl detectado")

    aleatoria = devices.get(RANDOM_MAC)
    if check(aleatoria is not None, "el dispositivo con MAC aleatoria existe"):
        equals(
            aleatoria.vendor,
            "MAC aleatoria (privacidad)",
            "las MAC localmente administradas no se atribuyen a ningun fabricante",
        )

    section("Eventos")
    events = state.snapshot_events()
    kinds = [event.kind for event in events]
    equals(kinds.count(EVT_DEVICE_JOIN), 5, "eventos de ENTRADA")
    equals(kinds.count(EVT_DEVICE_LEAVE), 1, "eventos de SALIDA")
    equals(kinds.count(EVT_PORT_OPEN), 4, "eventos de PUERTO NUEVO")
    equals(kinds.count(EVT_PORT_CLOSE), 1, "eventos de PUERTO CERRADO")
    check(
        all(
            events[index].timestamp <= events[index + 1].timestamp
            for index in range(len(events) - 1)
        ),
        "los eventos estan en orden cronologico",
    )

    section("Estadisticas y ranking")
    until = base + 9 * 60
    stats = state.statistics(until)
    equals(stats["presence_scans"], 6, "escaneos de presencia contabilizados")
    equals(stats["presence_failures"], 1, "escaneo de presencia fallido contabilizado")
    equals(stats["deep_scans"], 3, "escaneos profundos contabilizados")
    equals(stats["deep_scan_failures"], 1, "fallo de escaneo profundo contabilizado")
    equals(stats["unique_devices"], 4, "dispositivos unicos en estadisticas")
    equals(int(stats["max_simultaneous"]), 4, "maximo de dispositivos simultaneos")
    check(0 < stats["average_simultaneous"] < 4, "promedio de simultaneos en rango")

    ranking = state.ranking(until)
    equals(len(ranking), 4, "el ranking incluye a todos los dispositivos")
    check(
        all(ranking[i][1] >= ranking[i + 1][1] for i in range(len(ranking) - 1)),
        "el ranking esta ordenado por % de presencia descendente",
    )
    check(ranking[0][0].key == MOVIL, "el movil lidera el ranking de presencia")
    check(all(0.0 <= ratio <= 1.0 for _, ratio in ranking), "todos los % estan entre 0 y 100")


def verify_checkpoint(state: StateManager, store: CheckpointStore, oui: OuiResolver) -> None:
    section("Checkpoint y reanudacion")
    check(store.save(state.to_dict()), "el checkpoint se guarda")
    check(store.path.is_file(), "el fichero de checkpoint existe en disco")
    size = store.path.stat().st_size
    check(size > 500, f"el checkpoint tiene contenido ({size} bytes)")

    restored = StateManager(oui=oui, absence_cycles=2)
    restored.load_dict(store.load())

    equals(len(restored.devices), len(state.devices), "dispositivos restaurados")
    equals(len(restored.events), len(state.events), "eventos restaurados")
    equals(restored.presence_scans, state.presence_scans, "contador de presencia restaurado")
    equals(restored.deep_scans, state.deep_scans, "contador de deep scan restaurado")
    check(restored.resumed, "el estado restaurado se marca como reanudado")
    equals(restored.resume_count, 1, "contador de reanudaciones")
    check(
        all(not device.present for device in restored.devices.values()),
        "al reanudar nadie se da por presente hasta reconfirmarlo",
    )
    check(
        all(
            all(not session.open for session in device.sessions)
            for device in restored.devices.values()
        ),
        "al reanudar no quedan estancias abiertas colgando",
    )

    original = state.devices[MOVIL]
    copy = restored.devices[MOVIL]
    equals(copy.vendor, original.vendor, "fabricante preservado tras el round-trip")
    equals(len(copy.ports), len(original.ports), "puertos preservados tras el round-trip")
    equals(
        len(copy.ports["tcp/80"].windows),
        2,
        "las ventanas de apertura sobreviven a la serializacion",
    )

    # Un checkpoint de otro esquema no debe cargarse silenciosamente.
    bad = dict(state.to_dict())
    bad["schema"] = 999
    try:
        StateManager(oui=oui).load_dict(bad)
        check(False, "un checkpoint con esquema incompatible debe rechazarse")
    except ValueError:
        check(True, "un checkpoint con esquema incompatible se rechaza")


def verify_excel(state: StateManager, path: Path, until: float) -> None:
    section("Reporte Excel")
    try:
        from openpyxl import load_workbook

        from noxguardian.exporters import excel as excel_exporter
    except ImportError as exc:
        check(False, f"openpyxl disponible ({exc})")
        return

    written = excel_exporter.export(state, path, {"prueba": "selftest"}, until)
    check(written.is_file(), f"el Excel se escribio en {written.name}")
    check(written.stat().st_size > 4000, "el Excel tiene tamano razonable")

    book = load_workbook(written)
    equals(
        book.sheetnames,
        ["Resumen", "Timeline", "Puertos", "Estadisticas"],
        "las cuatro hojas existen y en orden",
    )

    resumen = book["Resumen"]
    equals(resumen.max_row, 5, "Resumen: cabecera + 4 dispositivos")
    equals(resumen["A1"].value, "MAC", "Resumen: primera columna")
    equals(resumen["K1"].value, "% presencia", "Resumen: columna de porcentaje")
    percentages = [resumen.cell(row=row, column=11).value for row in range(2, 6)]
    # openpyxl devuelve los enteros exactos (1.0 -> 1) al releer, de ahi el
    # isinstance contra (int, float): lo que se comprueba es que Excel reciba
    # un numero con formato de porcentaje, no una cadena "100%".
    check(
        all(isinstance(value, (int, float)) and not isinstance(value, bool) for value in percentages),
        "Resumen: los porcentajes son numericos (no texto)",
    )
    check(
        resumen.cell(row=2, column=11).number_format == "0.0%",
        "Resumen: la columna de % lleva formato de porcentaje",
    )
    check(
        percentages == sorted(percentages, reverse=True),
        "Resumen: ordenado por % de presencia descendente",
    )
    equals(resumen["A2"].value, MOVIL, "Resumen: el mas presente encabeza la hoja")
    equals(resumen.freeze_panes, "A2", "Resumen: cabecera congelada")

    timeline = book["Timeline"]
    equals(timeline.max_row, 7, "Timeline: cabecera + 6 eventos de entrada/salida")
    tipos = [timeline.cell(row=row, column=2).value for row in range(2, 8)]
    equals(tipos.count("ENTRADA"), 5, "Timeline: entradas")
    equals(tipos.count("SALIDA"), 1, "Timeline: salidas")
    horas = [timeline.cell(row=row, column=1).value for row in range(2, 8)]
    check(horas == sorted(horas), "Timeline: ordenado cronologicamente")

    puertos = book["Puertos"]
    equals(puertos.max_row, 5, "Puertos: cabecera + 4 filas (dispositivo, puerto)")
    numeros = sorted(puertos.cell(row=row, column=6).value for row in range(2, 6))
    equals(numeros, [22, 80, 443, 8080], "Puertos: los cuatro puertos historicos")
    fila80 = next(
        row for row in range(2, 6) if puertos.cell(row=row, column=6).value == 80
    )
    equals(puertos.cell(row=fila80, column=11).value, 2, "Puertos: veces confirmado del 80")
    equals(puertos.cell(row=fila80, column=12).value, "SI", "Puertos: el 80 esta abierto al final")
    check(
        "->" in str(puertos.cell(row=fila80, column=13).value),
        "Puertos: la celda de ventanas describe los intervalos",
    )

    stats_sheet = book["Estadisticas"]
    metricas = {
        stats_sheet.cell(row=row, column=1).value: stats_sheet.cell(row=row, column=2).value
        for row in range(2, stats_sheet.max_row + 1)
    }
    equals(metricas.get("Escaneos de presencia realizados"), 6, "Estadisticas: escaneos presencia")
    equals(metricas.get("Escaneos profundos realizados"), 3, "Estadisticas: escaneos profundos")
    equals(metricas.get("Dispositivos unicos vistos"), 4, "Estadisticas: dispositivos unicos")
    check(
        "Dispositivo con mas entradas/salidas" in metricas,
        "Estadisticas: incluye el dispositivo con mas transiciones",
    )
    check(
        str(metricas.get("Dispositivo con mas puertos abiertos", "")).startswith(MOVIL),
        "Estadisticas: el dispositivo con mas puertos es el correcto",
    )


def verify_log(path: Path) -> None:
    section("Log de texto")
    check(path.is_file(), "el log .txt existe")
    content = path.read_text(encoding="utf-8")
    check("DEVICE_JOIN" in content, "el log contiene entradas de dispositivos")
    check("DEVICE_LEAVE" in content, "el log contiene salidas de dispositivos")
    check("PORT_OPEN" in content, "el log contiene aperturas de puerto")
    check("PORT_CLOSE" in content, "el log contiene cierres de puerto")
    check("[E] ERROR" in content, "el log registra los errores de escaneo")
    lines = [line for line in content.splitlines() if line.strip()]
    check(len(lines) > 20, f"el log tiene volumen razonable ({len(lines)} lineas)")
    check(
        all(line[:4].isdigit() or line.startswith("=") for line in lines),
        "todas las lineas del log empiezan por timestamp o separador",
    )


def verify_ports_profile() -> None:
    section("Perfil de puertos")
    total = ports_profile.DEFAULT_PORT_COUNT
    check(3500 <= total <= 4500, f"el perfil por defecto ronda los 4000 puertos ({total})")
    expanded = ports_profile.expand(ports_profile.DEFAULT_PORT_SPEC)
    equals(len(expanded), len(set(expanded)), "no hay puertos duplicados en la spec")
    check(all(1 <= port <= 65535 for port in expanded), "todos los puertos son validos")
    for port in (22, 80, 443, 445, 3389, 5900, 8080, 62078):
        check(port in expanded, f"el puerto {port} esta cubierto")
    equals(
        ports_profile.normalize("80,443,1-3,2"), "1-3,80,443", "la spec se normaliza y compacta"
    )
    for invalid in ("", "abc", "0-10", "70000", "80,,,"):
        try:
            ports_profile.expand(invalid)
            check(invalid == "80,,,", f"spec invalida rechazada: {invalid!r}")
        except ValueError:
            check(True, f"spec invalida rechazada: {invalid!r}")


def verify_oui_parser() -> None:
    """Los tres formatos de base OUI deben parsearse sin comerse palabras."""
    section("Parser de tablas OUI")
    from noxguardian.oui import OuiResolver

    cases = [
        # (linea, prefijo esperado, fabricante esperado)
        ("38A659 Sagemcom Broadband SAS", "38A659", "Sagemcom Broadband SAS"),
        ("70C932 Dreame Technology (Suzhou) Limited", "70C932",
         "Dreame Technology (Suzhou) Limited"),
        ("A0FF0C Hangzhou Hikvision Digital Technology", "A0FF0C",
         "Hangzhou Hikvision Digital Technology"),
        ("B827EB Raspberry Pi Foundation", "B827EB", "Raspberry Pi Foundation"),
        ("00:00:0C\tCisco\tCisco Systems, Inc", "00000C", "Cisco Systems, Inc"),
        ("00:1B:63\tApple", "001B63", "Apple"),
        ("AABBCC,Fabricante De Prueba", "AABBCC", "Fabricante De Prueba"),
        ("DD-EE-FF   (hex)\t\tOtro Fabricante SA", "DDEEFF", "Otro Fabricante SA"),
    ]
    for line, prefix, vendor in cases:
        parsed = OuiResolver._parse_line(line)  # noqa: SLF001
        equals(parsed, (prefix, vendor), f"parseo de {line.split()[0]!r}")

    for ignorable in ("", "  ", "# comentario", "00:00:0C/28\tAlgo", "basura"):
        equals(
            OuiResolver._parse_line(ignorable),  # noqa: SLF001
            None,
            f"linea ignorada: {ignorable!r}",
        )


def verify_deepscan_timestamps() -> None:
    """Cada host se fecha cuando acabo SU escaneo, no al inicio del ciclo."""
    section("Timestamps del escaneo profundo")
    oui = OuiResolver(use_system_sources=False)
    state = StateManager(oui=oui, absence_cycles=2)
    base = time.time() - 600
    state.run_started_at = base

    state.apply_presence(
        presence(
            [
                PresenceHost(ip="10.0.0.1", mac=MOVIL),
                PresenceHost(ip="10.0.0.2", mac=PORTATIL),
            ],
            base,
        )
    )

    # El ciclo empieza en base+60; el host .2 acaba a los 30s y el .1 a los 200s.
    # El diccionario los trae en el orden "equivocado" a proposito.
    result = ports_result(
        base + 60,
        {
            "10.0.0.1": HostPortScan(
                ip="10.0.0.1",
                open_ports=[OpenPort(22, "tcp", "ssh", "OpenSSH")],
                completed_at=base + 260,
            ),
            "10.0.0.2": HostPortScan(
                ip="10.0.0.2",
                open_ports=[OpenPort(80, "tcp", "http", "nginx")],
                completed_at=base + 90,
            ),
        },
    )
    result.finished_at = base + 260
    events = state.apply_ports(result)

    puertos = [event for event in events if event.kind == EVT_PORT_OPEN]
    equals(len(puertos), 2, "dos puertos nuevos detectados")
    equals(puertos[0].detail["port"], 80, "el host que acabo antes se registra primero")
    equals(puertos[0].timestamp, base + 90, "el puerto 80 lleva la hora real de su host")
    equals(puertos[1].timestamp, base + 260, "el puerto 22 lleva la hora real de su host")
    check(
        all(events[i].timestamp <= events[i + 1].timestamp for i in range(len(events) - 1)),
        "los eventos del ciclo profundo salen en orden cronologico",
    )
    equals(
        state.devices[MOVIL].ports["tcp/22"].first_seen,
        base + 260,
        "el first_seen del puerto es el momento real de deteccion",
    )


def verify_unreachable_not_error() -> None:
    """Un host que se fue entre ciclos no es un fallo de escaneo."""
    section("Host desaparecido entre ciclos")
    oui = OuiResolver(use_system_sources=False)
    state = StateManager(oui=oui, absence_cycles=2)
    base = time.time() - 600
    state.run_started_at = base

    state.apply_presence(presence([PresenceHost(ip="10.0.0.9", mac=IOT)], base))
    events = state.apply_ports(
        ports_result(
            base + 60,
            {"10.0.0.9": HostPortScan(ip="10.0.0.9", unreachable=True, completed_at=base + 70)},
        )
    )

    equals(state.deep_scan_failures, 0, "un host inalcanzable no cuenta como escaneo fallido")
    check(
        not any(event.kind == "ERROR" for event in events),
        "no se registra ERROR por un host que se fue de la red",
    )
    check(
        any(event.detail.get("unreachable") for event in events),
        "se registra como posible salida pendiente de confirmar",
    )
    check(state.devices[IOT].present, "el dispositivo sigue presente hasta que presencia lo confirme")


def verify_proc_net_route(workdir: Path) -> None:
    """Deteccion de subred sin el binario `ip` (la via de Termux minimalista)."""
    section("Deteccion de subred via /proc/net/route")
    from noxguardian.netinfo import _from_proc_net_route  # noqa: PLC2701

    # Formato real del kernel: hex little-endian, separado por tabuladores.
    sample = workdir / "route_sample"
    sample.write_text(
        "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
        "wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n"
        "lo\t0000007F\t00000000\t0001\t0\t0\t0\t000000FF\t0\t0\t0\n"
        "wlan0\t0001A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\t0\t0\t0\n",
        encoding="utf-8",
    )
    equals(
        _from_proc_net_route(sample),
        ("192.168.1.0/24", "wlan0"),
        "subred y interfaz extraidas del hex little-endian",
    )

    # Solo ruta por defecto y loopback: no hay subred que deducir.
    only_default = workdir / "route_default"
    only_default.write_text(
        "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
        "eth0\t00000000\t0101A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n",
        encoding="utf-8",
    )
    equals(_from_proc_net_route(only_default), None, "sin rutas de red utiles devuelve None")

    # Basura: no debe lanzar, solo devolver None.
    junk = workdir / "route_junk"
    junk.write_text("cabecera\nzzz\tnohex\tnada\t1\t2\t3\t4\ttampoco\n", encoding="utf-8")
    equals(_from_proc_net_route(junk), None, "un fichero corrupto no lanza excepcion")
    equals(
        _from_proc_net_route(workdir / "no_existe"), None, "un fichero inexistente devuelve None"
    )


def verify_helpers() -> None:
    section("Utilidades")
    equals(format_duration(0), "0s", "duracion cero")
    equals(format_duration(59.4), "59s", "duracion en segundos")
    equals(format_duration(125), "2m 05s", "duracion en minutos")
    equals(format_duration(3725), "1h 02m 05s", "duracion en horas")
    equals(format_duration(90061), "1d 01h 01m 01s", "duracion en dias")

    from noxguardian.netinfo import _normalize_override  # noqa: PLC2701

    equals(_normalize_override("192.168.1.5"), "192.168.1.0/24", "IP suelta se asume /24")
    equals(_normalize_override("10.0.0.0/8"), "10.0.0.0/8", "CIDR explicito respetado")
    equals(_normalize_override("192.168.1.37/24"), "192.168.1.0/24", "CIDR no estricto")
    try:
        _normalize_override("no-es-una-red")
        check(False, "subred invalida rechazada")
    except ValueError:
        check(True, "subred invalida rechazada")


# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keep", type=Path, default=None, help="conservar la salida en esta ruta")
    args = parser.parse_args()

    workdir = Path(args.keep) if args.keep else Path(tempfile.mkdtemp(prefix="noxguardian-test-"))
    workdir.mkdir(parents=True, exist_ok=True)
    print(f"NoxGuardian selftest -> {workdir}")

    base = time.time() - 3600  # la sesion simulada empezo hace una hora
    oui = OuiResolver(use_system_sources=False)
    state = StateManager(oui=oui, absence_cycles=2)
    state.run_started_at = base
    state.session_started_at = base

    log = EventLog(workdir / "eventos.log", echo_console=False)
    try:
        run_scenario(state, log, base)
        verify_state(state, base)
        verify_checkpoint(state, CheckpointStore(workdir / "estado.json"), oui)
        verify_excel(state, workdir / "reporte.xlsx", base + 9 * 60)
    finally:
        log.close()
    verify_log(workdir / "eventos.log")
    verify_ports_profile()
    verify_oui_parser()
    verify_deepscan_timestamps()
    verify_unreachable_not_error()
    verify_proc_net_route(workdir)
    verify_helpers()

    print(f"\n{'=' * 60}")
    if FAILURES:
        print(f"RESULTADO: {len(FAILURES)} FALLO(S) de {CHECKS} comprobaciones")
        for failure in FAILURES:
            print(f"  - {failure}")
        status = 1
    else:
        print(f"RESULTADO: OK - {CHECKS}/{CHECKS} comprobaciones superadas")
        status = 0
    print("=" * 60)

    if args.keep:
        print(f"ficheros conservados en {workdir}")
    else:
        shutil.rmtree(workdir, ignore_errors=True)
    return status


if __name__ == "__main__":
    sys.exit(main())
