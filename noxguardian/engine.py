"""Motor de NoxGuardian: orquesta los bucles de escaneo y el apagado limpio.

Hilos:
  * presencia  - ritmo rapido, descubre quien esta en la red.
  * profundo   - ritmo lento, escanea puertos SOLO de los hosts que presencia
                 confirmo vivos en ese momento.
  * checkpoint - guarda el estado completo en JSON cada N minutos.

El hilo principal se queda esperando la senal de parada. Cuando llega (Ctrl+C,
SIGTERM o fallo irrecuperable) se matan los nmap en vuelo, se cierran las
estancias abiertas, se guarda un ultimo checkpoint y se genera el Excel.

Ningun fallo de un escaneo individual puede tumbar el proceso: todo se captura,
se registra en el log y el bucle continua.
"""

from __future__ import annotations

import threading
import time
from typing import Callable, List, Optional

from .config import Config
from .exporters.checkpoint import CheckpointStore
from .exporters.txtlog import EventLog
from .scanners.nmap_runner import NmapRunner
from .scanners.ports import PortScanner
from .scanners.presence import PresenceScanner
from .state import (
    EVT_CHECKPOINT,
    EVT_ERROR,
    EVT_INFO,
    StateManager,
    format_duration,
    format_timestamp,
)

# Margen entre el arranque y el primer escaneo profundo, para que el ciclo de
# presencia haya tenido tiempo de poblar la lista de hosts vivos.
DEEP_SCAN_WARMUP = 5.0


class GuardianEngine:
    """Coordina hilos, estado y salidas de una sesion de monitorizacion."""

    def __init__(
        self,
        config: Config,
        state: StateManager,
        log: EventLog,
        checkpoints: CheckpointStore,
        runner: NmapRunner,
        presence: PresenceScanner,
        ports: Optional[PortScanner],
    ) -> None:
        self.config = config
        self.state = state
        self.log = log
        self.checkpoints = checkpoints
        self.runner = runner
        self.presence = presence
        self.ports = ports

        self._stop = threading.Event()
        self._first_presence = threading.Event()
        self._threads: List[threading.Thread] = []
        self._stop_reason = ""
        self._finalized = False
        self.exit_code = 0

    # -- control -------------------------------------------------------------

    @property
    def stopping(self) -> bool:
        return self._stop.is_set()

    def request_stop(self, reason: str = "parada solicitada") -> None:
        """Idempotente: se puede llamar desde un signal handler sin riesgo."""
        if self._stop.is_set():
            return
        self._stop_reason = reason
        self._stop.set()
        # Matar los nmap en vuelo evita esperar minutos a que acabe un escaneo
        # de 4000 puertos antes de poder generar el reporte.
        killed = self.runner.stop()
        if killed:
            self.log.note(f"cancelados {killed} escaneo(s) de nmap en curso")

    def _sleep(self, seconds: float) -> bool:
        """Espera interrumpible. Devuelve False si hay que parar."""
        return not self._stop.wait(max(0.0, seconds))

    # -- arranque ------------------------------------------------------------

    def start(self) -> None:
        self._spawn("nox-presence", self._presence_loop)
        if self.config.deepscan_enabled and self.ports is not None:
            self._spawn("nox-deepscan", self._deepscan_loop)
        else:
            self.state.note(EVT_INFO, "escaneo profundo desactivado por configuracion")
        self._spawn("nox-checkpoint", self._checkpoint_loop)

    def _spawn(self, name: str, target: Callable[[], None]) -> None:
        thread = threading.Thread(target=self._guarded(name, target), name=name, daemon=True)
        thread.start()
        self._threads.append(thread)

    def _guarded(self, name: str, target: Callable[[], None]) -> Callable[[], None]:
        """Envuelve un bucle para que una excepcion no anunciada no lo mate en silencio."""

        def wrapper() -> None:
            try:
                target()
            except Exception as exc:  # noqa: BLE001 - ultima linea de defensa
                event = self.state.note(
                    EVT_ERROR, f"el hilo '{name}' murio de forma inesperada: {exc!r}"
                )
                self.log.write_event(event)
                self.log.note(
                    f"AVISO: el hilo '{name}' se ha detenido; "
                    "la monitorizacion continua con los hilos restantes"
                )

        return wrapper

    def run_forever(self) -> None:
        """Bloquea el hilo principal hasta que se solicite la parada."""
        while not self._stop.wait(0.5):
            pass

    # -- bucles --------------------------------------------------------------

    def _presence_loop(self) -> None:
        while True:
            result = self.presence.scan()
            events = self.state.apply_presence(result)
            self.log.write_events(events)
            self._first_presence.set()

            if self.stopping:
                return
            if not self._sleep(self.config.presence_interval):
                return

    def _deepscan_loop(self) -> None:
        assert self.ports is not None
        # Esperar al primer ciclo de presencia: sin hosts confirmados no hay
        # nada que escanear, y escanear la subred a ciegas esta descartado.
        while not self._first_presence.wait(0.5):
            if self.stopping:
                return
        if not self._sleep(DEEP_SCAN_WARMUP):
            return

        while True:
            targets = sorted(set(self.state.live_ips()))
            if targets:
                self.log.note(
                    f"iniciando escaneo profundo de {len(targets)} host(s) vivos: "
                    + ", ".join(targets[:10])
                    + (" ..." if len(targets) > 10 else "")
                )
                self.state.begin_port_cycle()

                def on_host(scan) -> None:
                    # Se llama en cuanto acaba cada host: los puertos nuevos
                    # llegan al log al momento, no al final del ciclo.
                    self.log.write_events(self.state.apply_host_scan(scan.ip, scan))

                result = self.ports.scan_hosts(targets, on_host=on_host)
                self.log.write_events(self.state.finish_port_cycle(result))
            else:
                self.log.note("escaneo profundo omitido: ningun host vivo confirmado")

            if self.stopping:
                return
            if not self._sleep(self.config.deepscan_interval):
                return

    def _checkpoint_loop(self) -> None:
        while True:
            if not self._sleep(self.config.checkpoint_interval):
                return
            self.save_checkpoint(periodic=True)

    # -- persistencia --------------------------------------------------------

    def save_checkpoint(self, periodic: bool = False, final: bool = False) -> bool:
        """Guarda el estado. Un fallo se registra pero no interrumpe nada."""
        label = "final" if final else ("periodico" if periodic else "manual")
        payload = self.state.to_dict()
        ok = self.checkpoints.save(payload)
        if ok:
            event = self.state.note(
                EVT_CHECKPOINT,
                f"checkpoint {label} guardado en {self.checkpoints.path.name} "
                f"({len(payload.get('devices', []))} dispositivos, "
                f"{len(payload.get('events', []))} eventos)",
                detail={"path": str(self.checkpoints.path), "kind": label},
            )
        else:
            event = self.state.note(
                EVT_ERROR,
                f"NO se pudo guardar el checkpoint {label}: {self.checkpoints.last_error}",
            )
        self.log.write_event(event)

        if ok and self.config.excel_on_checkpoint and not final:
            self._export_excel(stamp=time.strftime("%Y%m%d_%H%M%S"), label="parcial")
        return ok

    def _export_excel(self, stamp: str, label: str, until: Optional[float] = None) -> Optional[str]:
        try:
            from .exporters import excel as excel_exporter
        except ImportError as exc:  # pragma: no cover
            self.log.write_event(
                self.state.note(EVT_ERROR, f"no se pudo importar el exportador Excel: {exc}")
            )
            return None

        path = self.config.excel_path(stamp)
        try:
            summary = {key: str(value) for key, value in self.config.to_dict().items()}
            written = excel_exporter.export(self.state, path, summary, until)
        except excel_exporter.ExcelExportError as exc:
            self.log.write_event(
                self.state.note(EVT_ERROR, f"reporte Excel {label} no generado: {exc}")
            )
            return None
        except Exception as exc:  # noqa: BLE001 - el reporte no puede tumbar el cierre
            self.log.write_event(
                self.state.note(
                    EVT_ERROR, f"error inesperado generando el Excel {label}: {exc!r}"
                )
            )
            return None

        self.log.write_event(
            self.state.note(EVT_INFO, f"reporte Excel {label} generado: {written}")
        )
        return str(written)

    # -- apagado -------------------------------------------------------------

    def shutdown(self, join_timeout: float = 20.0) -> Optional[str]:
        """Cierre ordenado. Devuelve la ruta del Excel final si se genero."""
        if self._finalized:
            return None
        self._finalized = True

        self.request_stop(self._stop_reason or "apagado")
        self.log.banner(
            "PARANDO NOXGUARDIAN",
            [
                f"motivo: {self._stop_reason or 'parada solicitada'}",
                "esperando a que los hilos de escaneo terminen...",
            ],
        )

        deadline = time.monotonic() + join_timeout
        for thread in self._threads:
            remaining = max(0.5, deadline - time.monotonic())
            thread.join(timeout=remaining)
        still_alive = [thread.name for thread in self._threads if thread.is_alive()]
        if still_alive:
            self.log.note(
                "hilos que no terminaron a tiempo (se continua igualmente): "
                + ", ".join(still_alive)
            )

        moment = time.time()
        self.log.write_events(self.state.close_all_sessions(moment))

        self.save_checkpoint(final=True)
        excel_path = self._export_excel(
            stamp=time.strftime("%Y%m%d_%H%M%S", time.localtime(moment)),
            label="final",
            until=moment,
        )

        self.print_summary(moment, excel_path)
        self.log.close()
        return excel_path

    # -- resumen de consola --------------------------------------------------

    def print_summary(self, moment: float, excel_path: Optional[str]) -> None:
        stats = self.state.statistics(moment)
        ranking = self.state.ranking(moment)

        lines: List[str] = [
            f"inicio            : {format_timestamp(stats['session_start'])}",
            f"fin               : {format_timestamp(stats['session_end'])}",
            f"duracion          : {format_duration(stats['total_runtime'])}",
            f"escaneos presencia: {stats['presence_scans']}"
            + (f" ({stats['presence_failures']} fallidos)" if stats["presence_failures"] else ""),
            f"escaneos puertos  : {stats['deep_scans']}"
            + (f" ({stats['deep_scan_failures']} fallidos)" if stats["deep_scan_failures"] else ""),
            f"dispositivos      : {stats['unique_devices']} unicos, "
            f"{stats['devices_present_now']} presentes al final",
            f"simultaneos       : max {int(stats['max_simultaneous'])}, "
            f"media {stats['average_simultaneous']:.2f}",
            f"puertos abiertos  : {stats['total_open_ports']} vistos, "
            f"{stats['currently_open_ports']} abiertos al final",
        ]

        self.log.banner("RESUMEN DE LA SESION", lines)

        if ranking:
            header = (
                f"{'MAC':<19} {'FABRICANTE':<24} {'IP':<16} "
                f"{'ENT/SAL':>8} {'PRESENTE':>14} {'%':>7}"
            )
            # Las filas van dentro del banner, no como notas sueltas: asi la
            # tabla sale alineada en vez de con un timestamp delante de cada fila.
            table = [header, "-" * len(header)]
            for device, ratio in ranking[:25]:
                transitions = f"{device.appearances}/{device.departures}"
                table.append(
                    f"{device.mac_display:<19} {device.vendor[:24]:<24} "
                    f"{(device.ip or '-'):<16} {transitions:>8} "
                    f"{format_duration(device.present_seconds(moment)):>14} "
                    f"{ratio * 100:>6.1f}%"
                )
            if len(ranking) > 25:
                table.append(f"... y {len(ranking) - 25} dispositivos mas (ver el Excel)")
            self.log.banner("RANKING DE PRESENCIA", table)

        outputs = [
            f"log de eventos : {self.config.log_path}",
            f"checkpoint     : {self.checkpoints.path}",
        ]
        outputs.append(
            f"reporte Excel  : {excel_path}" if excel_path else
            "reporte Excel  : NO GENERADO (revisa los errores del log)"
        )
        self.log.banner("FICHEROS GENERADOS", outputs)
