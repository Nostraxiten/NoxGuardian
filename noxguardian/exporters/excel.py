"""Generacion del reporte final en Excel con openpyxl.

Cuatro hojas:
  Resumen       - una fila por dispositivo, ordenado por % de presencia desc.
  Timeline      - eventos de entrada/salida en orden cronologico.
  Puertos       - una fila por (dispositivo, puerto) con su historico.
  Estadisticas  - agregados de la sesion completa.

El libro se construye entero en memoria y se guarda de una sola vez, asi que
o se escribe completo o no se escribe: nunca queda un .xlsx a medias.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from ..state import (
    PRESENCE_EVENTS,
    EVT_DEVICE_JOIN,
    Device,
    StateManager,
    format_duration,
    format_timestamp,
)

try:  # openpyxl es la unica dependencia externa del proyecto
    from openpyxl import Workbook
    from openpyxl.formatting.rule import DataBarRule
    from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
    from openpyxl.utils import get_column_letter
    from openpyxl.worksheet.worksheet import Worksheet

    OPENPYXL_AVAILABLE = True
except ImportError:  # pragma: no cover - se avisa en tiempo de ejecucion
    OPENPYXL_AVAILABLE = False
    Workbook = None  # type: ignore[assignment]
    Worksheet = Any  # type: ignore[misc,assignment]


class ExcelExportError(RuntimeError):
    """El reporte Excel no se pudo generar."""


# Paleta discreta, legible al imprimir en blanco y negro.
_HEADER_FILL = "1F3B4D"
_HEADER_FONT_COLOR = "FFFFFF"
_ZEBRA_FILL = "F2F6F8"
_PRESENT_FILL = "DFF3E3"
_ABSENT_FILL = "FDEDED"

_DATE_FORMAT = "yyyy-mm-dd hh:mm:ss"


def _dt(epoch: Optional[float]) -> Optional[datetime]:
    """Convierte epoch a datetime nativo para que Excel lo trate como fecha."""
    if not epoch:
        return None
    try:
        return datetime.fromtimestamp(epoch)
    except (OverflowError, OSError, ValueError):
        return None


class ExcelReport:
    """Construye y guarda el libro de resultados."""

    def __init__(self, state: StateManager, config_summary: Optional[Dict[str, Any]] = None):
        if not OPENPYXL_AVAILABLE:
            raise ExcelExportError(
                "openpyxl no esta instalado; instala con: pip install openpyxl"
            )
        self.state = state
        self.config_summary = config_summary or {}

    # -- API publica ---------------------------------------------------------

    def save(self, path: Path, until: Optional[float] = None) -> Path:
        """Genera el libro completo y lo escribe en `path`."""
        stats = self.state.statistics(until)
        moment = stats["session_end"]

        workbook = Workbook()
        workbook.remove(workbook.active)

        self._build_summary(workbook.create_sheet("Resumen"), moment, stats)
        self._build_timeline(workbook.create_sheet("Timeline"))
        self._build_ports(workbook.create_sheet("Puertos"))
        self._build_stats(workbook.create_sheet("Estadisticas"), stats)

        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            workbook.save(target)
        except OSError as exc:
            raise ExcelExportError(f"no se pudo escribir {target}: {exc}") from exc
        return target

    # -- hoja 1: Resumen -----------------------------------------------------

    def _build_summary(self, sheet: Worksheet, moment: float, stats: Dict[str, Any]) -> None:
        headers = [
            "MAC",
            "Fabricante",
            "Ultima IP",
            "Hostname",
            "Primera vez visto",
            "Ultima vez visto",
            "Entradas",
            "Salidas",
            "Tiempo presente",
            "Segundos presente",
            "% presencia",
            "Puertos vistos",
            "Puertos abiertos ahora",
            "Presente al final",
        ]
        self._write_header(sheet, headers)

        ranking = self.state.ranking(moment)
        for index, (device, ratio) in enumerate(ranking, start=2):
            present_seconds = device.present_seconds(moment)
            sheet.append(
                [
                    device.mac_display,
                    device.vendor,
                    device.ip or "-",
                    device.hostname or "-",
                    _dt(device.first_seen),
                    _dt(device.last_seen),
                    device.appearances,
                    device.departures,
                    format_duration(present_seconds),
                    round(present_seconds, 1),
                    ratio,
                    len(device.ports),
                    len(device.open_ports),
                    "SI" if device.present else "NO",
                ]
            )
            fill = _PRESENT_FILL if device.present else _ABSENT_FILL
            self._paint_row(sheet, index, len(headers), fill)

        last_row = sheet.max_row
        self._format_dates(sheet, ["E", "F"], last_row)
        for row in range(2, last_row + 1):
            sheet.cell(row=row, column=11).number_format = "0.0%"

        if last_row >= 2:
            sheet.conditional_formatting.add(
                f"K2:K{last_row}",
                DataBarRule(start_type="num", start_value=0, end_type="num", end_value=1,
                            color="4C9F70", showValue=True),
            )

        self._finish(sheet, headers, widths=[19, 24, 16, 26, 20, 20, 10, 9, 18, 18, 12, 15, 22, 17])

    # -- hoja 2: Timeline ----------------------------------------------------

    def _build_timeline(self, sheet: Worksheet) -> None:
        headers = [
            "Hora",
            "Evento",
            "MAC",
            "Fabricante",
            "IP",
            "Hostname",
            "Detalle",
        ]
        self._write_header(sheet, headers)

        devices = {device.key: device for device in self.state.snapshot_devices()}
        events = [
            event
            for event in self.state.snapshot_events()
            if event.kind in PRESENCE_EVENTS
        ]
        events.sort(key=lambda item: item.timestamp)

        for index, event in enumerate(events, start=2):
            device = devices.get(event.device_key or "")
            sheet.append(
                [
                    _dt(event.timestamp),
                    "ENTRADA" if event.kind == EVT_DEVICE_JOIN else "SALIDA",
                    (device.mac_display if device else event.detail.get("mac", "-")),
                    device.vendor if device else "-",
                    device.ip if device else "-",
                    (device.hostname if device and device.hostname else "-"),
                    event.message,
                ]
            )
            fill = _PRESENT_FILL if event.kind == EVT_DEVICE_JOIN else _ABSENT_FILL
            self._paint_row(sheet, index, len(headers), fill)

        self._format_dates(sheet, ["A"], sheet.max_row)
        self._finish(sheet, headers, widths=[20, 11, 19, 22, 16, 24, 70])

    # -- hoja 3: Puertos -----------------------------------------------------

    def _build_ports(self, sheet: Worksheet) -> None:
        headers = [
            "IP",
            "MAC",
            "Fabricante",
            "Hostname",
            "Protocolo",
            "Puerto",
            "Servicio",
            "Version detectada",
            "Primera vez abierto",
            "Ultima confirmacion",
            "Veces confirmado",
            "Abierto ahora",
            "Ventanas de apertura",
        ]
        self._write_header(sheet, headers)

        rows: List[Sequence[Any]] = []
        for device in self.state.snapshot_devices():
            for record in sorted(
                device.ports.values(), key=lambda item: (item.protocol, item.port)
            ):
                rows.append(
                    (
                        device.ip or "-",
                        device.mac_display,
                        device.vendor,
                        device.hostname or "-",
                        record.protocol,
                        record.port,
                        record.service or "desconocido",
                        record.version or "-",
                        _dt(record.first_seen),
                        _dt(record.last_seen),
                        record.times_seen,
                        "SI" if record.currently_open else "NO",
                        _format_windows(record.windows),
                    )
                )

        rows.sort(key=lambda row: (str(row[1]), str(row[4]), int(row[5])))
        for index, row in enumerate(rows, start=2):
            sheet.append(list(row))
            if index % 2 == 0:
                self._paint_row(sheet, index, len(headers), _ZEBRA_FILL)

        self._format_dates(sheet, ["I", "J"], sheet.max_row)
        self._finish(
            sheet, headers, widths=[16, 19, 22, 22, 10, 9, 20, 34, 20, 20, 17, 14, 46]
        )

    # -- hoja 4: Estadisticas ------------------------------------------------

    def _build_stats(self, sheet: Worksheet, stats: Dict[str, Any]) -> None:
        headers = ["Metrica", "Valor"]
        self._write_header(sheet, headers)

        busiest: Optional[Device] = stats["busiest_device"]
        most_ports: Optional[Device] = stats["most_ports_device"]
        longest: Optional[Device] = stats["longest_device"]

        rows: List[Sequence[Any]] = [
            ("Inicio de la sesion", format_timestamp(stats["session_start"])),
            ("Fin de la sesion", format_timestamp(stats["session_end"])),
            ("Duracion total de la sesion", format_duration(stats["total_runtime"])),
            ("Duracion total (segundos)", round(stats["total_runtime"], 1)),
            ("Sesion reanudada desde checkpoint", "SI" if stats["resumed"] else "NO"),
            ("Numero de reanudaciones", stats["resume_count"]),
            ("", ""),
            ("Escaneos de presencia realizados", stats["presence_scans"]),
            ("Escaneos de presencia fallidos", stats["presence_failures"]),
            ("Escaneos profundos realizados", stats["deep_scans"]),
            ("Hosts escaneados en profundidad (acumulado)", stats["deep_scan_hosts"]),
            ("Escaneos profundos fallidos", stats["deep_scan_failures"]),
            ("Eventos registrados", stats["total_events"]),
            ("", ""),
            ("Dispositivos unicos vistos", stats["unique_devices"]),
            ("Dispositivos presentes al finalizar", stats["devices_present_now"]),
            ("Maximo de dispositivos simultaneos", int(stats["max_simultaneous"])),
            ("Promedio de dispositivos simultaneos", round(stats["average_simultaneous"], 2)),
            ("", ""),
            ("Puertos distintos vistos abiertos (total)", stats["total_open_ports"]),
            ("Puertos abiertos al finalizar", stats["currently_open_ports"]),
            ("", ""),
            (
                "Dispositivo con mas entradas/salidas",
                _device_caption(busiest),
            ),
            ("  transiciones", stats["busiest_transitions"]),
            (
                "Dispositivo con mas puertos abiertos",
                _device_caption(most_ports),
            ),
            ("  puertos distintos", stats["most_ports_count"]),
            (
                "Dispositivo mas tiempo presente",
                _device_caption(longest),
            ),
            ("  tiempo presente", format_duration(stats["longest_seconds"])),
        ]

        if self.config_summary:
            rows.append(("", ""))
            rows.append(("--- Configuracion de la sesion ---", ""))
            for key, value in self.config_summary.items():
                rows.append((key, value))

        for index, (metric, value) in enumerate(rows, start=2):
            sheet.append([metric, value])
            if metric.startswith("---"):
                sheet.cell(row=index, column=1).font = Font(bold=True)
            elif metric and not metric.startswith("  "):
                sheet.cell(row=index, column=1).font = Font(bold=metric.isupper())

        self._finish(sheet, headers, widths=[46, 52], autofilter=False)

    # -- helpers de formato --------------------------------------------------

    @staticmethod
    def _write_header(sheet: Worksheet, headers: Sequence[str]) -> None:
        sheet.append(list(headers))
        fill = PatternFill("solid", fgColor=_HEADER_FILL)
        font = Font(bold=True, color=_HEADER_FONT_COLOR)
        alignment = Alignment(horizontal="left", vertical="center")
        for column in range(1, len(headers) + 1):
            cell = sheet.cell(row=1, column=column)
            cell.fill = fill
            cell.font = font
            cell.alignment = alignment
        sheet.row_dimensions[1].height = 20

    @staticmethod
    def _paint_row(sheet: Worksheet, row: int, columns: int, color: str) -> None:
        fill = PatternFill("solid", fgColor=color)
        for column in range(1, columns + 1):
            sheet.cell(row=row, column=column).fill = fill

    @staticmethod
    def _format_dates(sheet: Worksheet, columns: Sequence[str], last_row: int) -> None:
        for column in columns:
            for row in range(2, last_row + 1):
                sheet[f"{column}{row}"].number_format = _DATE_FORMAT

    @staticmethod
    def _finish(
        sheet: Worksheet,
        headers: Sequence[str],
        widths: Sequence[int],
        autofilter: bool = True,
    ) -> None:
        for index, width in enumerate(widths, start=1):
            sheet.column_dimensions[get_column_letter(index)].width = width
        sheet.freeze_panes = "A2"
        if autofilter and sheet.max_row >= 1:
            sheet.auto_filter.ref = (
                f"A1:{get_column_letter(len(headers))}{max(sheet.max_row, 1)}"
            )
        thin = Side(style="thin", color="D0D7DC")
        border = Border(bottom=thin)
        for column in range(1, len(headers) + 1):
            sheet.cell(row=1, column=column).border = border


def _device_caption(device: Optional[Device]) -> str:
    if device is None:
        return "-"
    parts = [device.mac_display, device.vendor]
    if device.hostname:
        parts.append(device.hostname)
    if device.ip:
        parts.append(device.ip)
    return " | ".join(part for part in parts if part and part != "-")


def _format_windows(windows: Sequence[Sequence[Optional[float]]]) -> str:
    """Resume los intervalos de apertura de un puerto en una celda legible."""
    if not windows:
        return "-"
    chunks = []
    for window in windows[-6:]:  # las ultimas 6 bastan para leer la celda
        start = format_timestamp(window[0], with_date=False)
        end = format_timestamp(window[1], with_date=False) if window[1] else "abierto"
        chunks.append(f"{start}->{end}")
    prefix = f"(+{len(windows) - 6} previas) " if len(windows) > 6 else ""
    return prefix + ", ".join(chunks)


def export(
    state: StateManager,
    path: Path,
    config_summary: Optional[Dict[str, Any]] = None,
    until: Optional[float] = None,
) -> Path:
    """Atajo funcional para el motor."""
    return ExcelReport(state, config_summary).save(path, until)
