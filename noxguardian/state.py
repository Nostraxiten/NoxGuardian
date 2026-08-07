"""Modelo de datos y gestor de estado de la sesion de monitorizacion.

Todo el estado vive aqui y esta protegido por un RLock, porque lo tocan tres
hilos: presencia, escaneo profundo y checkpoints.

Convencion de tiempos: todos los timestamps son epoch en segundos (float,
`time.time()`), lo que hace la serializacion trivial y el calculo de
duraciones exacto. El formateo a texto legible se hace solo en la capa de
salida (log/Excel).
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .oui import (
    VENDOR_UNAVAILABLE,
    OuiResolver,
    normalize_mac,
)
from .scanners.ports import PortResult
from .scanners.presence import PresenceHost, PresenceResult

STATE_SCHEMA_VERSION = 1

# Tipos de evento
EVT_DEVICE_JOIN = "DEVICE_JOIN"
EVT_DEVICE_LEAVE = "DEVICE_LEAVE"
EVT_PORT_OPEN = "PORT_OPEN"
EVT_PORT_REOPEN = "PORT_REOPEN"
EVT_PORT_CLOSE = "PORT_CLOSE"
EVT_IP_CHANGE = "IP_CHANGE"
EVT_SCAN = "SCAN"
EVT_ERROR = "ERROR"
EVT_INFO = "INFO"
EVT_CHECKPOINT = "CHECKPOINT"

# Eventos que forman el timeline de entradas/salidas del Excel
PRESENCE_EVENTS = (EVT_DEVICE_JOIN, EVT_DEVICE_LEAVE)


# ---------------------------------------------------------------------------
# Estructuras
# ---------------------------------------------------------------------------


@dataclass
class Session:
    """Una estancia continua del dispositivo en la red."""

    start: float
    end: Optional[float] = None

    @property
    def open(self) -> bool:
        return self.end is None

    def duration(self, until: Optional[float] = None) -> float:
        finish = self.end if self.end is not None else (until or time.time())
        return max(0.0, finish - self.start)

    def to_dict(self) -> Dict[str, Any]:
        return {"start": self.start, "end": self.end}

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "Session":
        return Session(start=float(data["start"]), end=data.get("end"))


@dataclass
class PortRecord:
    """Historico de un puerto concreto de un dispositivo.

    `windows` guarda los intervalos en los que el puerto se vio abierto, de
    modo que un puerto que se abre, se cierra y se vuelve a abrir queda
    reflejado con sus tres momentos, no solo con el ultimo.
    """

    port: int
    protocol: str = "tcp"
    service: str = ""
    version: str = ""
    first_seen: float = 0.0
    last_seen: float = 0.0
    times_seen: int = 0
    currently_open: bool = True
    windows: List[List[Optional[float]]] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.protocol}/{self.port}"

    @property
    def service_label(self) -> str:
        if self.service and self.version:
            return f"{self.service} {self.version}"
        return self.service or self.version or "desconocido"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "service": self.service,
            "version": self.version,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "times_seen": self.times_seen,
            "currently_open": self.currently_open,
            "windows": self.windows,
        }

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "PortRecord":
        return PortRecord(
            port=int(data["port"]),
            protocol=data.get("protocol", "tcp"),
            service=data.get("service", ""),
            version=data.get("version", ""),
            first_seen=float(data.get("first_seen", 0.0)),
            last_seen=float(data.get("last_seen", 0.0)),
            times_seen=int(data.get("times_seen", 0)),
            currently_open=bool(data.get("currently_open", False)),
            windows=[list(window) for window in data.get("windows", [])],
        )


@dataclass
class Device:
    """Un dispositivo unico, identificado preferentemente por su MAC."""

    key: str
    mac: Optional[str] = None
    vendor: str = VENDOR_UNAVAILABLE
    ip: str = ""
    hostname: Optional[str] = None
    first_seen: float = 0.0
    last_seen: float = 0.0
    present: bool = False
    misses: int = 0
    appearances: int = 0
    departures: int = 0
    sessions: List[Session] = field(default_factory=list)
    ports: Dict[str, PortRecord] = field(default_factory=dict)
    ip_history: List[List[Any]] = field(default_factory=list)
    deep_scans: int = 0
    last_deep_scan: Optional[float] = None

    # -- calculos ------------------------------------------------------------

    def present_seconds(self, until: float) -> float:
        return sum(session.duration(until) for session in self.sessions)

    def uptime_ratio(self, session_start: float, until: float) -> float:
        window = max(1e-9, until - session_start)
        return min(1.0, self.present_seconds(until) / window)

    @property
    def open_ports(self) -> List[PortRecord]:
        return [record for record in self.ports.values() if record.currently_open]

    @property
    def label(self) -> str:
        """Identificador amigable para logs y consola."""
        name = self.hostname or self.vendor
        base = self.mac or self.key
        return f"{self.ip} [{base}]" + (f" {name}" if name and name != VENDOR_UNAVAILABLE else "")

    @property
    def mac_display(self) -> str:
        return self.mac or VENDOR_UNAVAILABLE

    # -- serializacion -------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key,
            "mac": self.mac,
            "vendor": self.vendor,
            "ip": self.ip,
            "hostname": self.hostname,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "present": self.present,
            "misses": self.misses,
            "appearances": self.appearances,
            "departures": self.departures,
            "sessions": [session.to_dict() for session in self.sessions],
            "ports": {key: record.to_dict() for key, record in self.ports.items()},
            "ip_history": self.ip_history,
            "deep_scans": self.deep_scans,
            "last_deep_scan": self.last_deep_scan,
        }

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "Device":
        return Device(
            key=data["key"],
            mac=data.get("mac"),
            vendor=data.get("vendor", VENDOR_UNAVAILABLE),
            ip=data.get("ip", ""),
            hostname=data.get("hostname"),
            first_seen=float(data.get("first_seen", 0.0)),
            last_seen=float(data.get("last_seen", 0.0)),
            present=bool(data.get("present", False)),
            misses=int(data.get("misses", 0)),
            appearances=int(data.get("appearances", 0)),
            departures=int(data.get("departures", 0)),
            sessions=[Session.from_dict(item) for item in data.get("sessions", [])],
            ports={
                key: PortRecord.from_dict(value)
                for key, value in (data.get("ports") or {}).items()
            },
            ip_history=[list(item) for item in data.get("ip_history", [])],
            deep_scans=int(data.get("deep_scans", 0)),
            last_deep_scan=data.get("last_deep_scan"),
        )


@dataclass
class Event:
    """Una entrada del historial cronologico."""

    timestamp: float
    kind: str
    message: str
    device_key: Optional[str] = None
    device_label: str = ""
    detail: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "kind": self.kind,
            "message": self.message,
            "device_key": self.device_key,
            "device_label": self.device_label,
            "detail": self.detail,
        }

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "Event":
        return Event(
            timestamp=float(data["timestamp"]),
            kind=data.get("kind", EVT_INFO),
            message=data.get("message", ""),
            device_key=data.get("device_key"),
            device_label=data.get("device_label", ""),
            detail=data.get("detail") or {},
        )


# ---------------------------------------------------------------------------
# Gestor
# ---------------------------------------------------------------------------


class StateManager:
    """Estado compartido de la sesion. Todos los metodos publicos son thread-safe."""

    def __init__(self, oui: OuiResolver, absence_cycles: int = 2) -> None:
        self._lock = threading.RLock()
        self.oui = oui
        self.absence_cycles = max(1, absence_cycles)

        self.devices: Dict[str, Device] = {}
        self.events: List[Event] = []

        self.run_started_at: float = time.time()
        self.session_started_at: float = self.run_started_at
        self.carried_runtime: float = 0.0  # segundos de ejecuciones previas (--resume)

        self.presence_scans: int = 0
        self.presence_failures: int = 0
        self.deep_scans: int = 0
        self.deep_scan_hosts: int = 0
        self.deep_scan_failures: int = 0
        self.presence_samples: List[List[float]] = []  # [timestamp, n_dispositivos]
        self.resumed: bool = False
        self.resume_count: int = 0

    # -- utilidades internas (asumen lock tomado) ----------------------------

    def _record(
        self,
        kind: str,
        message: str,
        device: Optional[Device] = None,
        detail: Optional[Dict[str, Any]] = None,
        timestamp: Optional[float] = None,
    ) -> Event:
        event = Event(
            timestamp=timestamp if timestamp is not None else time.time(),
            kind=kind,
            message=message,
            device_key=device.key if device else None,
            device_label=device.label if device else "",
            detail=detail or {},
        )
        self.events.append(event)
        return event

    def _find_by_ip(self, ip: str) -> Optional[Device]:
        """Dispositivo presente cuya IP actual coincide. Preferimos los presentes."""
        fallback: Optional[Device] = None
        for device in self.devices.values():
            if device.ip != ip:
                continue
            if device.present:
                return device
            fallback = fallback or device
        return fallback

    def _resolve_device(self, host: PresenceHost, now: float) -> Tuple[Device, List[Event]]:
        """Localiza o crea el Device de un host, fusionando registros si procede."""
        events: List[Event] = []
        mac = normalize_mac(host.mac)
        key = mac if mac else f"ip:{host.ip}"

        device = self.devices.get(key)

        # Un host que antes solo conociamos por IP y ahora ha revelado su MAC:
        # se fusiona el registro provisional en el definitivo para no duplicar.
        if mac:
            provisional = self.devices.get(f"ip:{host.ip}")
            if provisional is not None and provisional.key != key:
                if device is None:
                    device = self._promote(provisional, key, mac)
                    events.append(
                        self._record(
                            EVT_INFO,
                            f"MAC resuelta para {host.ip}: el registro provisional "
                            f"pasa a identificarse por {mac}",
                            device,
                            timestamp=now,
                        )
                    )
                else:
                    self._merge(device, provisional)
                    events.append(
                        self._record(
                            EVT_INFO,
                            f"registro provisional de {host.ip} fusionado en {mac}",
                            device,
                            timestamp=now,
                        )
                    )
                self.devices.pop(f"ip:{host.ip}", None)

        if device is None:
            device = Device(
                key=key,
                mac=mac,
                vendor=self.oui.lookup_with_hint(mac, host.nmap_vendor),
                ip=host.ip,
                hostname=host.hostname,
                first_seen=now,
                last_seen=now,
            )
            self.devices[key] = device

        return device, events

    def _promote(self, provisional: Device, new_key: str, mac: str) -> Device:
        """Reasigna un registro provisional (por IP) a su clave definitiva (MAC)."""
        provisional.key = new_key
        provisional.mac = mac
        provisional.vendor = self.oui.lookup(mac)
        self.devices[new_key] = provisional
        return provisional

    @staticmethod
    def _merge(target: Device, source: Device) -> None:
        """Absorbe el historico de `source` dentro de `target`."""
        target.first_seen = min(
            value for value in (target.first_seen, source.first_seen) if value
        )
        target.last_seen = max(target.last_seen, source.last_seen)
        target.sessions.extend(source.sessions)
        target.sessions.sort(key=lambda item: item.start)
        target.appearances += source.appearances
        target.departures += source.departures
        target.ip_history.extend(source.ip_history)
        target.deep_scans += source.deep_scans
        for key, record in source.ports.items():
            existing = target.ports.get(key)
            if existing is None:
                target.ports[key] = record
                continue
            existing.first_seen = min(existing.first_seen, record.first_seen)
            existing.last_seen = max(existing.last_seen, record.last_seen)
            existing.times_seen += record.times_seen
            existing.windows.extend(record.windows)
            existing.currently_open = existing.currently_open or record.currently_open

    # -- aplicacion de resultados -------------------------------------------

    def apply_presence(self, result: PresenceResult) -> List[Event]:
        """Integra un ciclo de presencia y devuelve los eventos generados."""
        now = result.started_at or time.time()
        events: List[Event] = []

        with self._lock:
            self.presence_scans += 1

            if result.errors and not result.hosts:
                # Un ciclo fallido no puede hacer "desaparecer" a todo el mundo.
                self.presence_failures += 1
                for message in result.errors:
                    events.append(
                        self._record(
                            EVT_ERROR,
                            f"escaneo de presencia fallido: {message}",
                            timestamp=now,
                        )
                    )
                events.append(
                    self._record(
                        EVT_INFO,
                        "ciclo sin resultados: no se evalua la ausencia de nadie",
                        timestamp=now,
                    )
                )
                return events

            for message in result.errors:
                events.append(
                    self._record(
                        EVT_ERROR, f"aviso del escaneo de presencia: {message}", timestamp=now
                    )
                )

            seen: set[str] = set()
            for host in result.hosts:
                device, merge_events = self._resolve_device(host, now)
                events.extend(merge_events)
                seen.add(device.key)
                events.extend(self._mark_seen(device, host, now))

            events.extend(self._evaluate_absences(seen, now))

            self.presence_samples.append([now, float(len(seen))])
            events.append(
                self._record(
                    EVT_SCAN,
                    f"escaneo de presencia #{self.presence_scans}: {len(seen)} dispositivos "
                    f"activos, {result.macs_resolved} con MAC, {result.duration:.1f}s "
                    f"({result.method})",
                    detail={
                        "scan": "presence",
                        "index": self.presence_scans,
                        "devices": len(seen),
                        "duration": round(result.duration, 2),
                    },
                    timestamp=now + result.duration,
                )
            )
        return events

    def _mark_seen(self, device: Device, host: PresenceHost, now: float) -> List[Event]:
        events: List[Event] = []

        if host.ip and device.ip != host.ip:
            if device.ip:
                events.append(
                    self._record(
                        EVT_IP_CHANGE,
                        f"cambio de IP: {device.ip} -> {host.ip}",
                        device,
                        detail={"from": device.ip, "to": host.ip},
                        timestamp=now,
                    )
                )
            device.ip_history.append([host.ip, now])
            device.ip = host.ip

        if host.hostname and host.hostname != device.hostname:
            device.hostname = host.hostname

        if device.vendor in (VENDOR_UNAVAILABLE,) and device.mac:
            device.vendor = self.oui.lookup_with_hint(device.mac, host.nmap_vendor)

        device.misses = 0
        device.last_seen = now
        if not device.first_seen:
            device.first_seen = now

        if not device.present:
            device.present = True
            device.appearances += 1
            device.sessions.append(Session(start=now))
            events.append(
                self._record(
                    EVT_DEVICE_JOIN,
                    f"ENTRA en la red: {device.ip} ({device.vendor})"
                    + (f" hostname={device.hostname}" if device.hostname else "")
                    + f" [aparicion #{device.appearances}]",
                    device,
                    detail={"appearance": device.appearances, "mac": device.mac_display},
                    timestamp=now,
                )
            )
        return events

    def _evaluate_absences(self, seen: set[str], now: float) -> List[Event]:
        events: List[Event] = []
        for device in self.devices.values():
            if device.key in seen or not device.present:
                continue
            device.misses += 1
            if device.misses < self.absence_cycles:
                events.append(
                    self._record(
                        EVT_INFO,
                        f"no responde ({device.misses}/{self.absence_cycles} ciclos); "
                        "aun no se considera ausente",
                        device,
                        timestamp=now,
                    )
                )
                continue

            device.present = False
            device.departures += 1
            open_session = next(
                (session for session in reversed(device.sessions) if session.open), None
            )
            # La estancia termina en la ultima confirmacion real, no en el
            # momento de detectar la ausencia: asi el % de presencia no se infla.
            end_at = device.last_seen or now
            if open_session is not None:
                open_session.end = max(open_session.start, end_at)
                stay = open_session.duration()
            else:
                stay = 0.0
            events.append(
                self._record(
                    EVT_DEVICE_LEAVE,
                    f"SALE de la red: {device.ip} ({device.vendor}) tras "
                    f"{format_duration(stay)} [salida #{device.departures}]",
                    device,
                    detail={
                        "departure": device.departures,
                        "stay_seconds": round(stay, 2),
                        "mac": device.mac_display,
                    },
                    timestamp=now,
                )
            )
        return events

    # El ciclo profundo se integra en tres fases para que el motor pueda
    # registrar cada host en el log en cuanto termina, sin esperar a que
    # acabe el ciclo entero (con 4000 puertos eso serian muchos minutos).

    def begin_port_cycle(self) -> int:
        """Abre un ciclo profundo. Devuelve su numero de orden."""
        with self._lock:
            self.deep_scans += 1
            return self.deep_scans

    def apply_host_scan(
        self, ip_addr: str, scan, default_timestamp: Optional[float] = None
    ) -> List[Event]:
        """Integra el resultado de UN host. Se fecha cuando acabo ese host.

        Fechar con el inicio del ciclo desordenaria el log y falsearia el
        first_seen de los puertos hasta en varios minutos. `default_timestamp`
        solo se usa si el escaneo no trae hora propia.
        """
        seen_at = scan.completed_at or default_timestamp or time.time()
        events: List[Event] = []

        with self._lock:
            device = self._find_by_ip(ip_addr)
            if device is None:
                events.append(
                    self._record(
                        EVT_INFO,
                        f"escaneo de puertos de {ip_addr} sin dispositivo asociado "
                        "(pudo cambiar de IP entre ciclos)",
                        timestamp=seen_at,
                    )
                )
                return events

            device.deep_scans += 1
            device.last_deep_scan = seen_at

            if scan.error:
                self.deep_scan_failures += 1
                events.append(
                    self._record(
                        EVT_ERROR,
                        f"escaneo profundo fallido en {ip_addr}: {scan.error}",
                        device,
                        timestamp=seen_at,
                    )
                )
                return events

            if scan.unreachable:
                events.append(
                    self._record(
                        EVT_INFO,
                        "no respondio al escaneo profundo: posible salida, "
                        "pendiente de confirmar por el ciclo de presencia",
                        device,
                        detail={"unreachable": True},
                        timestamp=seen_at,
                    )
                )
                return events

            events.extend(self._apply_host_ports(device, scan.open_ports, seen_at))
        return events

    def finish_port_cycle(self, result: PortResult) -> List[Event]:
        """Cierra el ciclo profundo con su evento de resumen."""
        with self._lock:
            self.deep_scan_hosts += result.targets
            return [
                self._record(
                    EVT_SCAN,
                    f"escaneo profundo #{self.deep_scans}: {result.targets} hosts, "
                    f"{result.total_open} puertos abiertos, {result.duration:.1f}s"
                    + (" [interrumpido]" if result.aborted else ""),
                    detail={
                        "scan": "ports",
                        "index": self.deep_scans,
                        "targets": result.targets,
                        "open_ports": result.total_open,
                        "duration": round(result.duration, 2),
                    },
                    timestamp=result.finished_at or result.started_at or time.time(),
                )
            ]

    def apply_ports(self, result: PortResult) -> List[Event]:
        """Integra un ciclo profundo ya completo, de una sola vez.

        Equivale a begin + un apply_host_scan por host + finish. El motor usa
        la version incremental; esto queda para uso programatico y tests.
        """
        fallback = result.started_at or time.time()
        self.begin_port_cycle()
        events: List[Event] = []
        for ip_addr, scan in sorted(
            result.scans.items(), key=lambda item: item[1].completed_at or fallback
        ):
            events.extend(self.apply_host_scan(ip_addr, scan, default_timestamp=fallback))
        events.extend(self.finish_port_cycle(result))
        return events

    def _apply_host_ports(self, device: Device, open_ports, now: float) -> List[Event]:
        events: List[Event] = []
        found: set[str] = set()

        for port in open_ports:
            port_key = f"{port.protocol}/{port.port}"
            found.add(port_key)
            record = device.ports.get(port_key)

            if record is None:
                record = PortRecord(
                    port=port.port,
                    protocol=port.protocol,
                    service=port.service,
                    version=port.version,
                    first_seen=now,
                    last_seen=now,
                    times_seen=1,
                    currently_open=True,
                    windows=[[now, None]],
                )
                device.ports[port_key] = record
                events.append(
                    self._record(
                        EVT_PORT_OPEN,
                        f"PUERTO NUEVO {port_key} abierto en {device.ip} -> {port.label}",
                        device,
                        detail={
                            "port": port.port,
                            "protocol": port.protocol,
                            "service": port.service,
                            "version": port.version,
                        },
                        timestamp=now,
                    )
                )
                continue

            record.times_seen += 1
            record.last_seen = now
            if port.service:
                record.service = port.service
            if port.version:
                record.version = port.version

            if not record.currently_open:
                record.currently_open = True
                record.windows.append([now, None])
                events.append(
                    self._record(
                        EVT_PORT_REOPEN,
                        f"puerto {port_key} vuelve a estar abierto en {device.ip} "
                        f"-> {port.label}",
                        device,
                        detail={"port": port.port, "protocol": port.protocol},
                        timestamp=now,
                    )
                )

        for port_key, record in device.ports.items():
            if not record.currently_open or port_key in found:
                continue
            record.currently_open = False
            if record.windows and record.windows[-1][1] is None:
                record.windows[-1][1] = record.last_seen or now
            events.append(
                self._record(
                    EVT_PORT_CLOSE,
                    f"puerto {port_key} ya NO esta abierto en {device.ip}",
                    device,
                    detail={"port": record.port, "protocol": record.protocol},
                    timestamp=now,
                )
            )
        return events

    # -- cierre --------------------------------------------------------------

    def close_all_sessions(self, now: Optional[float] = None) -> List[Event]:
        """Cierra las estancias abiertas al terminar la monitorizacion."""
        moment = now if now is not None else time.time()
        events: List[Event] = []
        with self._lock:
            for device in self.devices.values():
                for session in device.sessions:
                    if session.open:
                        session.end = max(session.start, moment)
                if device.present:
                    events.append(
                        self._record(
                            EVT_INFO,
                            f"presente al finalizar la sesion ({format_duration(device.present_seconds(moment))} acumulados)",
                            device,
                            timestamp=moment,
                        )
                    )
        return events

    def note(self, kind: str, message: str, detail: Optional[Dict[str, Any]] = None) -> Event:
        """Registra un evento suelto (arranque, checkpoint, error global...)."""
        with self._lock:
            return self._record(kind, message, detail=detail)

    # -- consultas -----------------------------------------------------------

    def live_ips(self) -> List[str]:
        """IPs de los dispositivos actualmente presentes (objetivo del deep scan)."""
        with self._lock:
            return [device.ip for device in self.devices.values() if device.present and device.ip]

    def snapshot_devices(self) -> List[Device]:
        with self._lock:
            return list(self.devices.values())

    def snapshot_events(self) -> List[Event]:
        with self._lock:
            return list(self.events)

    @property
    def total_runtime(self) -> float:
        return self.carried_runtime + (time.time() - self.run_started_at)

    def statistics(self, until: Optional[float] = None) -> Dict[str, Any]:
        """Agregados para la hoja de estadisticas y el resumen de consola."""
        moment = until if until is not None else time.time()
        with self._lock:
            devices = list(self.devices.values())
            elapsed = self.carried_runtime + (moment - self.run_started_at)
            window_start = moment - elapsed

            samples = [row[1] for row in self.presence_samples]
            average_simultaneous = sum(samples) / len(samples) if samples else 0.0

            def top(metric) -> Optional[Device]:
                candidates = [device for device in devices if metric(device) > 0]
                return max(candidates, key=metric, default=None)

            busiest = top(lambda device: device.appearances + device.departures)
            most_ports = top(lambda device: len(device.ports))
            longest = max(
                devices, key=lambda device: device.present_seconds(moment), default=None
            )

            present_now = [device for device in devices if device.present]

            return {
                "session_start": window_start,
                "session_end": moment,
                "total_runtime": elapsed,
                "resumed": self.resumed,
                "resume_count": self.resume_count,
                "presence_scans": self.presence_scans,
                "presence_failures": self.presence_failures,
                "deep_scans": self.deep_scans,
                "deep_scan_hosts": self.deep_scan_hosts,
                "deep_scan_failures": self.deep_scan_failures,
                "unique_devices": len(devices),
                "devices_present_now": len(present_now),
                "max_simultaneous": max(samples) if samples else 0,
                "average_simultaneous": average_simultaneous,
                "total_events": len(self.events),
                "total_open_ports": sum(len(device.ports) for device in devices),
                "currently_open_ports": sum(len(device.open_ports) for device in devices),
                "busiest_device": busiest,
                "busiest_transitions": (
                    busiest.appearances + busiest.departures if busiest else 0
                ),
                "most_ports_device": most_ports,
                "most_ports_count": len(most_ports.ports) if most_ports else 0,
                "longest_device": longest,
                "longest_seconds": longest.present_seconds(moment) if longest else 0.0,
            }

    def ranking(self, until: Optional[float] = None) -> List[Tuple[Device, float]]:
        """Dispositivos ordenados por % de presencia descendente."""
        moment = until if until is not None else time.time()
        with self._lock:
            elapsed = self.carried_runtime + (moment - self.run_started_at)
            window_start = moment - elapsed
            rows = [
                (device, device.uptime_ratio(window_start, moment))
                for device in self.devices.values()
            ]
        rows.sort(key=lambda row: (-row[1], row[0].ip))
        return rows

    # -- serializacion -------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "schema": STATE_SCHEMA_VERSION,
                "saved_at": time.time(),
                "run_started_at": self.run_started_at,
                "session_started_at": self.session_started_at,
                "total_runtime": self.total_runtime,
                "absence_cycles": self.absence_cycles,
                "counters": {
                    "presence_scans": self.presence_scans,
                    "presence_failures": self.presence_failures,
                    "deep_scans": self.deep_scans,
                    "deep_scan_hosts": self.deep_scan_hosts,
                    "deep_scan_failures": self.deep_scan_failures,
                    "resume_count": self.resume_count,
                },
                "presence_samples": self.presence_samples,
                "devices": [device.to_dict() for device in self.devices.values()],
                "events": [event.to_dict() for event in self.events],
            }

    def load_dict(self, data: Dict[str, Any]) -> None:
        """Restaura un checkpoint previo sobre este gestor (--resume)."""
        schema = int(data.get("schema", 0))
        if schema != STATE_SCHEMA_VERSION:
            raise ValueError(
                f"checkpoint con esquema {schema}, incompatible con "
                f"esta version ({STATE_SCHEMA_VERSION})"
            )
        with self._lock:
            self.devices = {}
            for entry in data.get("devices", []):
                device = Device.from_dict(entry)
                self.devices[device.key] = device
            self.events = [Event.from_dict(entry) for entry in data.get("events", [])]

            counters = data.get("counters", {})
            self.presence_scans = int(counters.get("presence_scans", 0))
            self.presence_failures = int(counters.get("presence_failures", 0))
            self.deep_scans = int(counters.get("deep_scans", 0))
            self.deep_scan_hosts = int(counters.get("deep_scan_hosts", 0))
            self.deep_scan_failures = int(counters.get("deep_scan_failures", 0))
            self.resume_count = int(counters.get("resume_count", 0)) + 1

            self.presence_samples = [list(row) for row in data.get("presence_samples", [])]
            self.session_started_at = float(
                data.get("session_started_at", self.run_started_at)
            )
            self.carried_runtime = float(data.get("total_runtime", 0.0))
            self.run_started_at = time.time()
            self.resumed = True

            # Un dispositivo marcado como presente en el checkpoint puede haberse
            # ido durante la parada. Se cierra su estancia en el ultimo dato real
            # y se le obliga a re-anunciarse en el proximo ciclo de presencia.
            for device in self.devices.values():
                for session in device.sessions:
                    if session.open:
                        session.end = max(session.start, device.last_seen or session.start)
                device.present = False
                device.misses = 0


# ---------------------------------------------------------------------------
# Formateo compartido
# ---------------------------------------------------------------------------


def format_duration(seconds: float) -> str:
    """Duracion legible: `2d 03h 15m 04s`, omitiendo las unidades a cero."""
    total = int(max(0, round(seconds)))
    days, remainder = divmod(total, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, secs = divmod(remainder, 60)
    if days:
        return f"{days}d {hours:02d}h {minutes:02d}m {secs:02d}s"
    if hours:
        return f"{hours}h {minutes:02d}m {secs:02d}s"
    if minutes:
        return f"{minutes}m {secs:02d}s"
    return f"{secs}s"


def format_timestamp(epoch: Optional[float], with_date: bool = True) -> str:
    if not epoch:
        return "-"
    pattern = "%Y-%m-%d %H:%M:%S" if with_date else "%H:%M:%S"
    return time.strftime(pattern, time.localtime(epoch))


def iter_all_ports(devices: Iterable[Device]) -> Iterable[Tuple[Device, PortRecord]]:
    for device in devices:
        for record in sorted(device.ports.values(), key=lambda item: (item.protocol, item.port)):
            yield device, record
