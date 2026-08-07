"""Escaneo de presencia: quien esta ahora mismo en la red.

Dos modos:

  * `nmap -sn <subred>`  -> barrido ARP en LAN local. Rapido y devuelve MAC
    real. Requiere root o cap_net_raw.
  * fallback sin privilegios -> barrido TCP connect() con sockets de stdlib
    contra un grupo de puertos habituales, en paralelo. Un `connect` que
    responde ACK **o** RST prueba que el host existe. Las MAC se intentan
    recuperar de /proc/net/arp (legible sin root en Linux/Android); las que no
    aparezcan quedan como "no disponible".

Ambos modos devuelven la misma estructura, de modo que el resto del sistema
no necesita saber cual se uso.
"""

from __future__ import annotations

import errno
import ipaddress
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from .. import netinfo
from ..oui import normalize_mac
from .nmap_runner import (
    NmapError,
    NmapRunner,
    host_addresses,
    host_hostname,
    host_is_up,
)

# Puertos usados por el barrido sin privilegios. Se buscan servicios que
# practicamente cualquier clase de dispositivo tenga expuesto: web de admin,
# SMB de Windows, SSH, impresion, servicios Apple, DVR/camaras...
FALLBACK_PROBE_PORTS = (
    80, 443, 22, 445, 139, 8080, 53, 5000, 631, 62078, 8443, 7, 9100, 23, 3389,
)
FALLBACK_CONNECT_TIMEOUT = 0.45
FALLBACK_MAX_WORKERS = 128

METHOD_ARP = "nmap -sn (barrido ARP)"
METHOD_FALLBACK = "TCP connect sweep (sin privilegios)"


@dataclass
class PresenceHost:
    """Un host visto vivo en un ciclo de presencia."""

    ip: str
    mac: Optional[str] = None
    hostname: Optional[str] = None
    nmap_vendor: Optional[str] = None

    @property
    def identity(self) -> str:
        """Clave estable del dispositivo: la MAC si la hay, si no la IP."""
        return self.mac if self.mac else f"ip:{self.ip}"


@dataclass
class PresenceResult:
    """Resultado completo de un ciclo de presencia."""

    hosts: List[PresenceHost] = field(default_factory=list)
    method: str = ""
    duration: float = 0.0
    started_at: float = 0.0
    errors: List[str] = field(default_factory=list)
    macs_resolved: int = 0

    @property
    def ok(self) -> bool:
        return not self.errors or bool(self.hosts)


class PresenceScanner:
    """Encapsula el ciclo de presencia y la eleccion de metodo."""

    def __init__(
        self,
        subnet: str,
        runner: NmapRunner,
        privileged: bool,
        timeout: float = 300.0,
        force_fallback: bool = False,
        should_stop: Optional[Callable[[], bool]] = None,
        local_ip: Optional[str] = None,
        local_mac: Optional[str] = None,
    ) -> None:
        self.subnet = subnet
        self.runner = runner
        self.timeout = timeout
        self._should_stop = should_stop or (lambda: False)
        self.local_ip = local_ip
        self.local_mac = normalize_mac(local_mac)
        self.use_nmap = runner.available and privileged and not force_fallback
        self.method = METHOD_ARP if self.use_nmap else METHOD_FALLBACK
        if not runner.available and not force_fallback:
            self.method = METHOD_FALLBACK + " [nmap no encontrado]"

    # -- API publica ---------------------------------------------------------

    def scan(self) -> PresenceResult:
        """Ejecuta un ciclo. Nunca lanza: los fallos van en `result.errors`."""
        started = time.monotonic()
        result = PresenceResult(method=self.method, started_at=time.time())
        try:
            if self.use_nmap:
                result.hosts = self._scan_with_nmap()
            else:
                result.hosts = self._scan_fallback()
        except NmapError as exc:
            result.errors.append(str(exc))
        except OSError as exc:
            result.errors.append(f"error de red durante el barrido: {exc}")
        except Exception as exc:  # noqa: BLE001 - el guardian no puede caerse
            result.errors.append(f"error inesperado en el escaneo de presencia: {exc!r}")
        result.duration = time.monotonic() - started
        result.macs_resolved = sum(1 for host in result.hosts if host.mac)
        return result

    # -- modo privilegiado ---------------------------------------------------

    def _scan_with_nmap(self) -> List[PresenceHost]:
        run = self.runner.run_xml(["-sn", "-n", "-T4", self.subnet], timeout=self.timeout)
        hosts: List[PresenceHost] = []
        for host_element in run.hosts:
            if not host_is_up(host_element):
                continue
            ip_addr, mac, vendor = host_addresses(host_element)
            if not ip_addr:
                continue
            hosts.append(
                PresenceHost(
                    ip=ip_addr,
                    mac=normalize_mac(mac),
                    hostname=host_hostname(host_element),
                    nmap_vendor=vendor,
                )
            )
        return self._enrich_macs(hosts)

    # -- modo sin privilegios ------------------------------------------------

    def _scan_fallback(self) -> List[PresenceHost]:
        network = ipaddress.ip_network(self.subnet, strict=False)
        targets = [str(ip) for ip in network.hosts()]
        if not targets:
            targets = [str(network.network_address)]

        alive: List[str] = []
        workers = min(FALLBACK_MAX_WORKERS, max(8, len(targets)))
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="nox-sweep") as pool:
            for ip_addr, is_alive in zip(targets, pool.map(self._probe_host, targets)):
                if is_alive:
                    alive.append(ip_addr)

        hosts = [PresenceHost(ip=ip_addr) for ip_addr in alive]
        return self._enrich_macs(hosts)

    def _probe_host(self, ip_addr: str) -> bool:
        """True si el host responde en algun puerto sonda (abierto o cerrado)."""
        for port in FALLBACK_PROBE_PORTS:
            if self._should_stop():
                return False
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(FALLBACK_CONNECT_TIMEOUT)
            try:
                sock.connect((ip_addr, port))
                return True  # ACK: hay algo escuchando
            except socket.timeout:
                continue  # filtrado o host ausente: seguimos probando
            except OSError as exc:
                # ECONNREFUSED / ECONNRESET significan que la pila TCP del host
                # respondio: el dispositivo existe aunque el puerto este cerrado.
                if exc.errno in (errno.ECONNREFUSED, errno.ECONNRESET):
                    return True
                continue
            finally:
                sock.close()
        return False

    # -- comun ---------------------------------------------------------------

    def _enrich_macs(self, hosts: List[PresenceHost]) -> List[PresenceHost]:
        """Rellena las MACs que el barrido no pudo obtener.

        Dos fuentes, ambas best-effort:
          * la MAC de nuestra propia interfaz, porque el equipo que monitoriza
            nunca aparece con MAC en su propio barrido ARP;
          * la cache ARP del kernel, legible sin root en Linux y Android y que
            suele estar fresca justo despues de haber hablado con el host.

        Lo que no se consiga rellenar se queda a None y acaba reportandose como
        "no disponible", que es preferible a inventarselo.
        """
        missing = [host for host in hosts if not host.mac]
        if not missing:
            return hosts

        if self.local_ip and self.local_mac:
            for host in missing:
                if host.ip == self.local_ip:
                    host.mac = self.local_mac

        still_missing = [host for host in missing if not host.mac]
        if not still_missing:
            return hosts

        arp_table = netinfo.read_arp_table()
        if not arp_table:
            return hosts
        for host in still_missing:
            candidate = normalize_mac(arp_table.get(host.ip))
            if candidate:
                host.mac = candidate
        return hosts
