"""Escaneo profundo de puertos sobre los hosts confirmados vivos.

Nunca se escanea la subred entera a ciegas: el motor pasa la lista de IPs que
el ciclo de presencia confirmo activas, y aqui se lanza un nmap por host.

Comando por host:  nmap -p <spec> -sV -T4 -Pn <ip>

  -Pn  porque la presencia ya esta confirmada; ahorra el host discovery y
       evita falsos negativos en dispositivos que ignoran ICMP.
  -sV  para identificar servicio y version.

Solo se reportan puertos en estado "open"; filtered/closed se descartan.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from .nmap_runner import (
    NmapAborted,
    NmapError,
    NmapRunner,
    NmapTimeout,
    format_service,
    host_addresses,
)


@dataclass(frozen=True)
class OpenPort:
    """Un puerto encontrado abierto en un host."""

    port: int
    protocol: str
    service: str
    version: str

    @property
    def label(self) -> str:
        if self.service and self.version:
            return f"{self.service} {self.version}"
        return self.service or self.version or "desconocido"


@dataclass
class HostPortScan:
    """Resultado del escaneo de un host concreto."""

    ip: str
    open_ports: List[OpenPort] = field(default_factory=list)
    error: Optional[str] = None
    unreachable: bool = False
    duration: float = 0.0
    mac: Optional[str] = None
    # Momento real en que termino el escaneo DE ESTE host. Un ciclo profundo
    # puede durar minutos, asi que fechar sus eventos con el inicio del ciclo
    # desordenaria el log y falsearia el first_seen de los puertos.
    completed_at: float = 0.0

    @property
    def ok(self) -> bool:
        return self.error is None


@dataclass
class PortResult:
    """Resultado de un ciclo completo de escaneo profundo."""

    scans: Dict[str, HostPortScan] = field(default_factory=dict)
    duration: float = 0.0
    started_at: float = 0.0
    finished_at: float = 0.0
    targets: int = 0
    aborted: bool = False

    @property
    def total_open(self) -> int:
        return sum(len(scan.open_ports) for scan in self.scans.values())

    @property
    def failures(self) -> List[HostPortScan]:
        return [scan for scan in self.scans.values() if not scan.ok]

    @property
    def unreachable_hosts(self) -> List[str]:
        return [ip for ip, scan in self.scans.items() if scan.unreachable]


class PortScanner:
    """Lanza el escaneo profundo con un pool acotado de nmaps simultaneos."""

    def __init__(
        self,
        runner: NmapRunner,
        ports: str,
        timeout: float = 900.0,
        workers: int = 2,
        should_stop: Optional[Callable[[], bool]] = None,
    ) -> None:
        self.runner = runner
        self.ports = ports
        self.timeout = timeout
        self.workers = max(1, workers)
        self._should_stop = should_stop or (lambda: False)

    # -- API publica ---------------------------------------------------------

    def scan_hosts(
        self,
        ips: List[str],
        on_host: Optional[Callable[[HostPortScan], None]] = None,
    ) -> PortResult:
        """Escanea una lista de IPs. Un fallo por host no aborta el resto.

        `on_host` se invoca en cuanto termina CADA host, para que el motor
        pueda registrar sus puertos en el log al momento en vez de esperar a
        que acabe el ciclo entero (que con 4000 puertos puede durar minutos).
        """
        result = PortResult(started_at=time.time(), targets=len(ips))
        started = time.monotonic()
        if not ips:
            result.duration = 0.0
            result.finished_at = result.started_at
            return result

        workers = min(self.workers, len(ips))
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="nox-deep") as pool:
            futures = {pool.submit(self.scan_host, ip): ip for ip in ips}
            for future in as_completed(futures):
                ip_addr = futures[future]
                try:
                    scan = future.result()
                except Exception as exc:  # noqa: BLE001 - aislar fallo por host
                    scan = HostPortScan(
                        ip=ip_addr,
                        error=f"fallo interno: {exc!r}",
                        completed_at=time.time(),
                    )
                result.scans[ip_addr] = scan

                if on_host is not None:
                    try:
                        on_host(scan)
                    except Exception as exc:  # noqa: BLE001
                        # Un fallo escribiendo el log no puede abortar el ciclo:
                        # el resultado ya esta en `result` y se procesara igual.
                        scan.error = scan.error or f"fallo notificando el resultado: {exc!r}"

                if self._should_stop():
                    result.aborted = True

        result.duration = time.monotonic() - started
        result.finished_at = time.time()
        return result

    def scan_host(self, ip: str) -> HostPortScan:
        """Escanea un unico host. Devuelve el fallo en el objeto, no lo lanza."""
        started = time.monotonic()
        scan = HostPortScan(ip=ip)

        def finish(current: HostPortScan) -> HostPortScan:
            current.completed_at = time.time()
            if not current.duration:
                current.duration = time.monotonic() - started
            return current

        if self._should_stop():
            scan.error = "cancelado antes de empezar (parada solicitada)"
            return finish(scan)

        try:
            run = self.runner.run_xml(
                ["-p", self.ports, "-sV", "-T4", "-Pn", "-n", ip],
                timeout=self.timeout,
            )
        except NmapTimeout as exc:
            scan.error = f"timeout: {exc}"
            return finish(scan)
        except NmapAborted as exc:
            scan.error = f"cancelado: {exc}"
            return finish(scan)
        except NmapError as exc:
            scan.error = str(exc)
            return finish(scan)

        scan.duration = run.duration
        host_elements = run.hosts
        if not host_elements:
            # Con -Pn nmap omite el <host> por completo cuando no consigue
            # hablar con el destino en capa 2 (el host se fue de la red entre
            # el ciclo de presencia y este escaneo): el XML trae hosts up="0"
            # y exit="success". No es un error del escaneo, es una posible
            # salida, y como tal se registra para que presencia lo confirme.
            scan.unreachable = True
            return finish(scan)

        host_element = host_elements[0]
        _ip, mac, _vendor = host_addresses(host_element)
        scan.mac = mac

        status = host_element.find("status")
        state = status.get("state") if status is not None else None
        # Con -Pn nmap marca casi todo como "up"; el sintoma real de host
        # ausente es que ni un solo puerto haya respondido (todos filtered).
        if state == "down":
            scan.unreachable = True
            return finish(scan)

        ports_element = host_element.find("ports")
        if ports_element is None:
            scan.unreachable = True
            return finish(scan)

        responded = False
        for port_element in ports_element.findall("port"):
            state_element = port_element.find("state")
            if state_element is None:
                continue
            port_state = state_element.get("state")
            if port_state in ("closed", "open"):
                responded = True
            if port_state != "open":
                continue
            try:
                port_number = int(port_element.get("portid", ""))
            except ValueError:
                continue
            service, version = format_service(port_element)
            scan.open_ports.append(
                OpenPort(
                    port=port_number,
                    protocol=port_element.get("protocol", "tcp"),
                    service=service,
                    version=version,
                )
            )

        # Si ningun puerto individual respondio y los agregados de <extraports>
        # son todos "filtered", el host no dio senales de vida: posible salida.
        extraports = ports_element.findall("extraports")
        only_filtered = (
            all(entry.get("state") == "filtered" for entry in extraports)
            if extraports
            else False
        )
        if not responded and not scan.open_ports and only_filtered:
            scan.unreachable = True

        scan.open_ports.sort(key=lambda item: (item.protocol, item.port))
        return finish(scan)
