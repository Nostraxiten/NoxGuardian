"""Ejecucion del binario `nmap` y parseo directo de su XML.

No se usa ninguna libreria wrapper de nmap: se lanza el binario con `-oX -` y
se parsea la salida con `xml.etree.ElementTree`. Es mas robusto frente a
cambios de version y no anade dependencias.

El runner mantiene un registro de los procesos vivos para poder matarlos al
recibir SIGINT, de modo que el apagado sea inmediato y no haya que esperar a
que termine un escaneo de 4000 puertos.
"""

from __future__ import annotations

import shutil
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import List, Optional, Set

DEFAULT_NMAP_TIMEOUT = 600.0


class NmapError(RuntimeError):
    """Fallo recuperable de un escaneo concreto. Nunca debe tumbar el proceso."""


class NmapTimeout(NmapError):
    """El escaneo excedio el timeout configurado."""


class NmapAborted(NmapError):
    """El escaneo fue cancelado por una parada solicitada (Ctrl+C)."""


@dataclass(frozen=True)
class NmapRun:
    """Resultado crudo de una ejecucion: raiz XML + metadatos utiles."""

    root: ET.Element
    command: str
    duration: float
    stderr: str

    @property
    def hosts(self) -> List[ET.Element]:
        return self.root.findall("host")


def find_nmap() -> Optional[str]:
    """Ruta absoluta del binario nmap, o None si no esta instalado."""
    return shutil.which("nmap")


def nmap_version(path: Optional[str] = None) -> Optional[str]:
    binary = path or find_nmap()
    if not binary:
        return None
    try:
        proc = subprocess.run(
            [binary, "--version"], capture_output=True, text=True, timeout=15, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    first_line = (proc.stdout or "").splitlines()
    return first_line[0].strip() if first_line else None


class NmapRunner:
    """Lanza nmap de forma segura y concurrente, con parada limpia."""

    def __init__(self, nmap_path: Optional[str] = None) -> None:
        self.path = nmap_path or find_nmap()
        self._processes: Set[subprocess.Popen] = set()
        self._lock = threading.Lock()
        self._stopping = False

    @property
    def available(self) -> bool:
        return self.path is not None

    # -- ciclo de vida -------------------------------------------------------

    def stop(self) -> int:
        """Marca parada y mata cualquier nmap en vuelo. Devuelve cuantos mato."""
        with self._lock:
            self._stopping = True
            victims = list(self._processes)
        for proc in victims:
            try:
                proc.kill()
            except OSError:
                pass
        return len(victims)

    @property
    def stopping(self) -> bool:
        return self._stopping

    # -- ejecucion -----------------------------------------------------------

    def run_xml(self, args: List[str], timeout: float = DEFAULT_NMAP_TIMEOUT) -> NmapRun:
        """Ejecuta `nmap <args> -oX -` y devuelve el XML parseado.

        Lanza NmapError/NmapTimeout/NmapAborted; nunca deja procesos huerfanos.
        """
        if not self.path:
            raise NmapError("nmap no esta instalado o no esta en el PATH")
        if self._stopping:
            raise NmapAborted("parada solicitada: escaneo no iniciado")

        command = [self.path, *args, "-oX", "-"]
        started = time.monotonic()
        try:
            proc = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except OSError as exc:
            raise NmapError(f"no se pudo lanzar nmap: {exc}") from exc

        with self._lock:
            self._processes.add(proc)

        try:
            try:
                stdout, stderr = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout, stderr = proc.communicate()
                raise NmapTimeout(
                    f"timeout de {timeout:g}s superado en: {' '.join(command)}"
                )
        finally:
            with self._lock:
                self._processes.discard(proc)

        duration = time.monotonic() - started

        if self._stopping and not (stdout or "").strip():
            raise NmapAborted("escaneo cancelado por parada solicitada")

        if not (stdout or "").strip():
            detail = (stderr or "").strip().splitlines()
            hint = detail[-1] if detail else f"codigo de salida {proc.returncode}"
            raise NmapError(f"nmap no devolvio salida XML ({hint})")

        try:
            root = ET.fromstring(stdout)
        except ET.ParseError as exc:
            # nmap escribe el XML de forma incremental: si lo matamos a mitad,
            # el documento queda sin cerrar. Se intenta un cierre manual antes
            # de darlo por perdido.
            root = _salvage_partial_xml(stdout)
            if root is None:
                raise NmapError(f"XML de nmap ilegible: {exc}") from exc

        return NmapRun(
            root=root,
            command=" ".join(command),
            duration=duration,
            stderr=(stderr or "").strip(),
        )


def _salvage_partial_xml(payload: str) -> Optional[ET.Element]:
    """Intenta recuperar un XML de nmap truncado cerrando la etiqueta raiz."""
    if "<nmaprun" not in payload:
        return None
    truncated = payload
    # Descartar la ultima linea, que casi seguro esta cortada a media etiqueta.
    if not truncated.rstrip().endswith(">"):
        truncated = truncated.rsplit("\n", 1)[0]
    for suffix in ("</nmaprun>", "</host></nmaprun>", "</ports></host></nmaprun>"):
        try:
            return ET.fromstring(truncated + suffix)
        except ET.ParseError:
            continue
    return None


# ---------------------------------------------------------------------------
# Helpers de extraccion sobre elementos <host>
# ---------------------------------------------------------------------------


def host_is_up(host: ET.Element) -> bool:
    status = host.find("status")
    return status is not None and status.get("state") == "up"


def host_addresses(host: ET.Element) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Devuelve (ipv4, mac, vendor_segun_nmap) de un elemento <host>."""
    ipv4: Optional[str] = None
    mac: Optional[str] = None
    vendor: Optional[str] = None
    for address in host.findall("address"):
        kind = address.get("addrtype")
        if kind == "ipv4":
            ipv4 = address.get("addr")
        elif kind == "mac":
            mac = address.get("addr")
            vendor = address.get("vendor")
    return ipv4, mac, vendor


def host_hostname(host: ET.Element) -> Optional[str]:
    """Primer hostname util (PTR o el que sea) del elemento <host>."""
    hostnames = host.find("hostnames")
    if hostnames is None:
        return None
    candidates = hostnames.findall("hostname")
    for entry in candidates:
        if entry.get("type") == "PTR" and entry.get("name"):
            return entry.get("name")
    for entry in candidates:
        if entry.get("name"):
            return entry.get("name")
    return None


def format_service(port_element: ET.Element) -> tuple[str, str]:
    """Devuelve (nombre_servicio, descripcion_version) para un <port>.

    La descripcion combina product + version + extrainfo tal y como los muestra
    nmap, sin inventar nada: si nmap no identifico la version, queda vacia.
    """
    service = port_element.find("service")
    if service is None:
        return "", ""
    name = (service.get("name") or "").strip()
    pieces = [
        (service.get("product") or "").strip(),
        (service.get("version") or "").strip(),
    ]
    extra = (service.get("extrainfo") or "").strip()
    description = " ".join(piece for piece in pieces if piece)
    if extra:
        description = f"{description} ({extra})".strip()
    tunnel = (service.get("tunnel") or "").strip()
    if tunnel and tunnel not in name:
        name = f"{tunnel}/{name}" if name else tunnel
    return name, description
