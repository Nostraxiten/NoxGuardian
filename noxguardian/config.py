"""Configuracion de ejecucion de NoxGuardian."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

from . import ports_profile

# Valores por defecto (en minutos donde aplique, tal y como se exponen en CLI).
DEFAULT_PRESENCE_INTERVAL_MIN = 3.0
DEFAULT_DEEPSCAN_INTERVAL_MIN = 20.0
DEFAULT_CHECKPOINT_INTERVAL_MIN = 15.0

CHECKPOINT_FILENAME = "noxguardian_state.json"
LOG_FILENAME = "noxguardian_events.log"
EXCEL_FILENAME_TEMPLATE = "noxguardian_report_{stamp}.xlsx"


@dataclass
class Config:
    """Parametros efectivos de una sesion de monitorizacion.

    Los intervalos se guardan en SEGUNDOS; la CLI los recibe en minutos.
    """

    output_dir: Path
    subnet: Optional[str] = None
    presence_interval: float = DEFAULT_PRESENCE_INTERVAL_MIN * 60
    deepscan_interval: float = DEFAULT_DEEPSCAN_INTERVAL_MIN * 60
    checkpoint_interval: float = DEFAULT_CHECKPOINT_INTERVAL_MIN * 60
    ports: str = ports_profile.DEFAULT_PORT_SPEC

    # Comportamiento
    resume: bool = False
    absence_cycles: int = 2
    deepscan_workers: int = 2
    deepscan_enabled: bool = True
    excel_on_checkpoint: bool = False
    force_fallback: bool = False

    # Timeouts de subproceso, en segundos
    presence_timeout: float = 300.0
    deepscan_timeout: float = 900.0

    # OUI
    oui_file: Optional[Path] = None
    no_system_oui: bool = False

    # Presentacion
    verbose: bool = False

    # Rellenados en runtime por el motor (no vienen de la CLI)
    resolved_subnet: Optional[str] = field(default=None, repr=False)
    interface: Optional[str] = field(default=None, repr=False)
    local_ip: Optional[str] = field(default=None, repr=False)
    local_mac: Optional[str] = field(default=None, repr=False)
    privileged: bool = field(default=False, repr=False)
    scan_method: str = field(default="desconocido", repr=False)

    # -- rutas derivadas -----------------------------------------------------

    @property
    def checkpoint_path(self) -> Path:
        return self.output_dir / CHECKPOINT_FILENAME

    @property
    def log_path(self) -> Path:
        return self.output_dir / LOG_FILENAME

    def excel_path(self, stamp: str) -> Path:
        return self.output_dir / EXCEL_FILENAME_TEMPLATE.format(stamp=stamp)

    # -- serializacion -------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["output_dir"] = str(self.output_dir)
        data["oui_file"] = str(self.oui_file) if self.oui_file else None
        data["port_count"] = ports_profile.count(self.ports)
        return data

    def summary_lines(self) -> list[str]:
        return [
            f"subred          : {self.resolved_subnet or '(pendiente)'}"
            + (f"  [iface {self.interface}]" if self.interface else ""),
            f"este equipo     : {self.local_ip or '?'}"
            + (f"  MAC {self.local_mac}" if self.local_mac else "  MAC no disponible"),
            f"metodo presencia: {self.scan_method}"
            + ("  [root/privilegiado]" if self.privileged else "  [sin privilegios]"),
            f"presencia cada  : {self.presence_interval / 60:g} min",
            "deep scan cada  : "
            + (
                f"{self.deepscan_interval / 60:g} min"
                if self.deepscan_enabled
                else "DESACTIVADO"
            ),
            f"checkpoint cada : {self.checkpoint_interval / 60:g} min",
            f"puertos         : {ports_profile.count(self.ports)} puertos",
            f"salida          : {self.output_dir}",
            f"ciclos ausencia : {self.absence_cycles} (fallos seguidos antes de dar por ido)",
        ]
