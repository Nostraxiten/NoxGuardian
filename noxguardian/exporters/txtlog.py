"""Log de eventos en texto plano, escrito en append e inmediatamente.

La premisa es que si el proceso muere de golpe (OOM, bateria, kill -9), el
fichero ya debe contener todo lo ocurrido hasta ese instante. Por eso cada
evento se escribe y se hace flush + fsync; no hay buffer que perder.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path
from typing import Iterable, Optional, TextIO

from ..state import (
    EVT_CHECKPOINT,
    EVT_DEVICE_JOIN,
    EVT_DEVICE_LEAVE,
    EVT_ERROR,
    EVT_INFO,
    EVT_IP_CHANGE,
    EVT_PORT_CLOSE,
    EVT_PORT_OPEN,
    EVT_PORT_REOPEN,
    EVT_SCAN,
    Event,
    format_timestamp,
)

# Marcador visual por tipo de evento, para que el .txt se lea de un vistazo.
_MARKERS = {
    EVT_DEVICE_JOIN: "[+]",
    EVT_DEVICE_LEAVE: "[-]",
    EVT_PORT_OPEN: "[!]",
    EVT_PORT_REOPEN: "[!]",
    EVT_PORT_CLOSE: "[x]",
    EVT_IP_CHANGE: "[~]",
    EVT_SCAN: "[*]",
    EVT_ERROR: "[E]",
    EVT_CHECKPOINT: "[S]",
    EVT_INFO: "[i]",
}

# Eventos que ademas se muestran por consola cuando no estamos en modo verboso.
_CONSOLE_ALWAYS = frozenset(
    {EVT_DEVICE_JOIN, EVT_DEVICE_LEAVE, EVT_PORT_OPEN, EVT_PORT_REOPEN, EVT_ERROR, EVT_CHECKPOINT}
)


class EventLog:
    """Escritor del log humano-legible. Thread-safe y a prueba de cortes."""

    def __init__(
        self,
        path: Path,
        echo_console: bool = True,
        verbose: bool = False,
        stream: Optional[TextIO] = None,
    ) -> None:
        self.path = Path(path)
        self.echo_console = echo_console
        self.verbose = verbose
        self._stream = stream or sys.stdout
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._handle: Optional[TextIO] = open(  # noqa: SIM115 - vive toda la sesion
            self.path, "a", encoding="utf-8", buffering=1
        )

    # -- escritura -----------------------------------------------------------

    def _write_raw(self, line: str) -> None:
        with self._lock:
            handle = self._handle
            if handle is None:
                return
            try:
                handle.write(line + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            except (OSError, ValueError):
                # Un fallo de disco no puede tumbar al guardian: se avisa por
                # consola y se sigue monitorizando.
                print(f"[E] no se pudo escribir en {self.path}", file=sys.stderr)

    def write_event(self, event: Event, force_console: bool = False) -> None:
        """Escribe un evento. `force_console` lo muestra aunque no sea verboso.

        Se usa para lo que el usuario tiene que ver si o si al arrancar
        (avisos de entorno, reanudacion), que de otro modo solo quedaria en el
        fichero y podria pasar desapercibido durante horas.
        """
        marker = _MARKERS.get(event.kind, "[i]")
        stamp = format_timestamp(event.timestamp)
        target = f" {event.device_label}" if event.device_label else ""
        line = f"{stamp} {marker} {event.kind:<13}{target} :: {event.message}"
        self._write_raw(line)

        if not self.echo_console:
            return
        if force_console or self.verbose or event.kind in _CONSOLE_ALWAYS:
            print(line, file=self._stream, flush=True)

    def write_events(self, events: Iterable[Event], force_console: bool = False) -> None:
        for event in events:
            self.write_event(event, force_console=force_console)

    def banner(self, title: str, lines: Iterable[str] = ()) -> None:
        """Bloque destacado (arranque, parada, resumen final)."""
        rule = "=" * 78
        stamp = format_timestamp(time.time())
        block = [rule, f"{stamp}  {title}", rule]
        block.extend(f"    {line}" for line in lines)
        for entry in block:
            self._write_raw(entry)
        if self.echo_console:
            for entry in block:
                print(entry, file=self._stream, flush=True)

    def note(self, message: str) -> None:
        """Linea suelta que no procede de un Event del estado."""
        line = f"{format_timestamp(time.time())} [i] {message}"
        self._write_raw(line)
        if self.echo_console:
            print(line, file=self._stream, flush=True)

    # -- ciclo de vida -------------------------------------------------------

    def close(self) -> None:
        with self._lock:
            if self._handle is not None:
                try:
                    self._handle.flush()
                    os.fsync(self._handle.fileno())
                    self._handle.close()
                except (OSError, ValueError):
                    pass
                self._handle = None

    def __enter__(self) -> "EventLog":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()
