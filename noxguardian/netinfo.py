"""Deteccion de la red local, de la interfaz por defecto y de privilegios.

Todo con stdlib + comandos del sistema. Se prueban varias estrategias en
cascada porque `ip` no siempre esta disponible (Termux minimalista, imagenes
docker reducidas, macOS...).
"""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Rutas de la tabla ARP del kernel (Linux / Android). Legible sin root, lo que
# permite recuperar MACs incluso en el modo fallback de Termux.
_ARP_TABLE_PATHS = (
    "/proc/net/arp",
    "/data/data/com.termux/files/usr/../../../../proc/net/arp",
)

_ARP_FLAG_COMPLETE = 0x2
_PLACEHOLDER_MACS = {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}


@dataclass(frozen=True)
class NetworkInfo:
    """Resultado de la autodeteccion de red."""

    cidr: str
    interface: Optional[str]
    local_ip: Optional[str]
    method: str

    @property
    def host_count(self) -> int:
        return ipaddress.ip_network(self.cidr, strict=False).num_addresses


# ---------------------------------------------------------------------------
# Utilidades de subproceso
# ---------------------------------------------------------------------------


def _run(cmd: List[str], timeout: float = 8.0) -> Optional[str]:
    """Ejecuta un comando y devuelve stdout, o None si falla por cualquier motivo."""
    if not shutil.which(cmd[0]):
        return None
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return proc.stdout if proc.returncode == 0 else None


# ---------------------------------------------------------------------------
# Deteccion de subred
# ---------------------------------------------------------------------------


def _default_interface_from_ip_route() -> Optional[str]:
    out = _run(["ip", "route", "show", "default"]) or _run(["ip", "route"])
    if not out:
        return None
    for line in out.splitlines():
        match = re.search(r"^default\s+.*?\bdev\s+(\S+)", line.strip())
        if match:
            return match.group(1)
    return None


def _cidr_for_interface(iface: str) -> Optional[Tuple[str, str]]:
    """Devuelve (cidr_de_red, ip_local) para una interfaz, via `ip addr`."""
    out = _run(["ip", "-o", "-f", "inet", "addr", "show", "dev", iface])
    if not out:
        return None
    for line in out.splitlines():
        match = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+/\d+)", line)
        if not match:
            continue
        iface_cidr = match.group(1)
        try:
            interface = ipaddress.ip_interface(iface_cidr)
        except ValueError:
            continue
        if interface.ip.is_loopback:
            continue
        return str(interface.network), str(interface.ip)
    return None


def _from_ip_route_scope_link() -> Optional[Tuple[str, str, str]]:
    """Extrae (cidr, iface, ip) de las lineas `proto kernel scope link src X`."""
    out = _run(["ip", "route"])
    if not out:
        return None
    for line in out.splitlines():
        match = re.match(
            r"^(\d+\.\d+\.\d+\.\d+/\d+)\s+dev\s+(\S+).*?\bsrc\s+(\d+\.\d+\.\d+\.\d+)",
            line.strip(),
        )
        if not match:
            continue
        cidr, iface, src = match.groups()
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if network.is_loopback or network.prefixlen >= 31:
            continue
        return str(network), iface, src
    return None


def _from_proc_net_route(path: Optional[Path] = None) -> Optional[Tuple[str, str]]:
    """Lee /proc/net/route (hex little-endian) sin depender del binario `ip`.

    Es la via que acaba usandose en Termux minimalista, donde puede no haber
    ni `ip` ni `ifconfig`.
    """
    source = Path(path) if path is not None else Path("/proc/net/route")
    if not source.is_file():
        return None
    try:
        lines = source.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    for line in lines[1:]:
        fields = line.split()
        if len(fields) < 8:
            continue
        iface, dest_hex, mask_hex = fields[0], fields[1], fields[7]
        if iface == "lo":
            continue
        try:
            dest = struct.unpack("<I", bytes.fromhex(dest_hex))[0]
            mask = struct.unpack("<I", bytes.fromhex(mask_hex))[0]
        except (ValueError, struct.error):
            continue
        if mask in (0, 0xFFFFFFFF):  # ruta por defecto o ruta de host
            continue
        try:
            # ip_network exige que la mascara sea texto o entero: pasarle un
            # IPv4Address como segundo elemento de la tupla revienta.
            network = ipaddress.ip_network(
                f"{ipaddress.IPv4Address(dest)}/{ipaddress.IPv4Address(mask)}",
                strict=False,
            )
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
            continue
        if network.is_loopback:
            continue
        return str(network), iface
    return None


def _from_ifconfig() -> Optional[Tuple[str, str, str]]:
    """Ultimo recurso en sistemas con `ifconfig` pero sin `ip` (BSD/macOS/Termux)."""
    out = _run(["ifconfig"])
    if not out:
        return None
    current_iface: Optional[str] = None
    for line in out.splitlines():
        header = re.match(r"^(\S+?):?\s", line)
        if header and not line.startswith((" ", "\t")):
            current_iface = header.group(1).rstrip(":")
        match = re.search(
            r"inet\s+(?:addr:)?(\d+\.\d+\.\d+\.\d+).*?(?:netmask|Mask:)\s*"
            r"(0x[0-9a-fA-F]{8}|\d+\.\d+\.\d+\.\d+)",
            line,
        )
        if not (match and current_iface and current_iface != "lo"):
            continue
        ip_str, mask_str = match.groups()
        try:
            mask = (
                str(ipaddress.IPv4Address(int(mask_str, 16)))
                if mask_str.startswith("0x")
                else mask_str
            )
            network = ipaddress.ip_network(f"{ip_str}/{mask}", strict=False)
        except ValueError:
            continue
        if network.is_loopback:
            continue
        return str(network), current_iface, ip_str
    return None


def interface_mac(iface: Optional[str]) -> Optional[str]:
    """MAC de una interfaz local, leida de sysfs.

    El propio equipo que monitoriza nunca aparece en su barrido ARP con MAC
    (no habla ARP consigo mismo), asi que sin esto se reportaria a si mismo
    como 'no disponible' en todas las ejecuciones.
    """
    if not iface:
        return None
    path = Path(f"/sys/class/net/{iface}/address")
    try:
        mac = path.read_text(encoding="utf-8").strip().lower()
    except OSError:
        return None
    return mac if mac and mac not in _PLACEHOLDER_MACS else None


def local_ip_via_udp() -> Optional[str]:
    """IP local que el SO usaria para salir a Internet. No envia trafico real."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(1.0)
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()


def _attempt(func):
    """Ejecuta una estrategia de deteccion; None si falla por lo que sea.

    Ninguna heuristica de deteccion puede impedir el arranque: siempre queda
    la siguiente, y en ultimo termino el flag --subnet.
    """
    try:
        return func()
    except Exception:  # noqa: BLE001 - se degrada a la siguiente estrategia
        return None


def detect_network(override: Optional[str] = None) -> NetworkInfo:
    """Determina la subred a monitorizar.

    Con `override` se valida y se usa tal cual (acepta CIDR o una IP suelta,
    en cuyo caso se asume /24). Sin override se prueban, en orden:
    ruta por defecto + `ip addr`, `ip route` scope link, /proc/net/route,
    `ifconfig` y, como ultimo recurso, IP local via socket UDP asumiendo /24.
    """
    if override:
        cidr = _normalize_override(override)
        # Aunque la subred venga a mano, seguimos necesitando saber por que
        # interfaz salimos: de ahi sale la MAC de este mismo equipo, que si no
        # acabaria reportandose a si mismo como "no disponible".
        return NetworkInfo(
            cidr=cidr,
            interface=_attempt(_default_interface_from_ip_route),
            local_ip=local_ip_via_udp(),
            method="manual (--subnet)",
        )

    # Cada estrategia se prueba aislada: si una revienta por un formato
    # inesperado, se pasa a la siguiente en vez de tumbar el arranque.
    attempt = _attempt
    iface = attempt(_default_interface_from_ip_route)
    if iface:
        found = attempt(lambda: _cidr_for_interface(iface))
        if found:
            cidr, local = found
            return NetworkInfo(cidr, iface, local, "ip route + ip addr")

    scope_link = attempt(_from_ip_route_scope_link)
    if scope_link:
        cidr, iface_name, local = scope_link
        return NetworkInfo(cidr, iface_name, local, "ip route (scope link)")

    proc_route = attempt(_from_proc_net_route)
    if proc_route:
        cidr, iface_name = proc_route
        return NetworkInfo(cidr, iface_name, local_ip_via_udp(), "/proc/net/route")

    ifcfg = attempt(_from_ifconfig)
    if ifcfg:
        cidr, iface_name, local = ifcfg
        return NetworkInfo(cidr, iface_name, local, "ifconfig")

    local = local_ip_via_udp()
    if local:
        network = ipaddress.ip_network(f"{local}/24", strict=False)
        return NetworkInfo(str(network), None, local, "socket UDP (asumiendo /24)")

    raise RuntimeError(
        "no se pudo autodetectar la subred local; usa --subnet 192.168.1.0/24"
    )


def _normalize_override(value: str) -> str:
    text = value.strip()
    try:
        if "/" in text:
            return str(ipaddress.ip_network(text, strict=False))
        return str(ipaddress.ip_network(f"{text}/24", strict=False))
    except ValueError as exc:
        raise ValueError(f"subred invalida: '{value}' ({exc})") from exc


# ---------------------------------------------------------------------------
# Privilegios
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PrivilegeInfo:
    is_root: bool
    nmap_has_caps: bool
    reason: str

    @property
    def can_arp_scan(self) -> bool:
        return self.is_root or self.nmap_has_caps


def detect_privileges(nmap_path: Optional[str] = None) -> PrivilegeInfo:
    """Comprueba si podemos hacer barrido ARP (requiere raw sockets)."""
    if os.name != "posix":
        # En Windows nmap usa Npcap; asumimos que si esta instalado, funciona.
        return PrivilegeInfo(False, bool(nmap_path), "plataforma no POSIX (se asume Npcap)")

    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    if is_root:
        return PrivilegeInfo(True, True, "proceso ejecutandose como root (euid=0)")

    caps = False
    binary = nmap_path or shutil.which("nmap")
    if binary:
        out = _run(["getcap", binary])
        if out and "cap_net_raw" in out:
            caps = True

    reason = (
        "nmap tiene cap_net_raw (barrido ARP disponible sin root)"
        if caps
        else "sin root ni cap_net_raw: el barrido ARP no esta disponible"
    )
    return PrivilegeInfo(False, caps, reason)


# ---------------------------------------------------------------------------
# Tabla ARP del kernel
# ---------------------------------------------------------------------------


def read_arp_table() -> Dict[str, str]:
    """Mapa {ip: mac} leido de /proc/net/arp. Vacio si no existe o no aporta.

    Solo se devuelven entradas con el flag ATF_COM (0x2) puesto, es decir,
    resoluciones completas; las incompletas traen la MAC a ceros.
    """
    table: Dict[str, str] = {}
    for raw_path in _ARP_TABLE_PATHS:
        path = Path(raw_path)
        if not path.is_file():
            continue
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in content.splitlines()[1:]:
            fields = line.split()
            if len(fields) < 4:
                continue
            ip_addr, flags_hex, mac = fields[0], fields[2], fields[3]
            try:
                flags = int(flags_hex, 16)
            except ValueError:
                continue
            if not flags & _ARP_FLAG_COMPLETE:
                continue
            mac_lower = mac.lower()
            if mac_lower in _PLACEHOLDER_MACS:
                continue
            table[ip_addr] = mac_lower
        if table:
            break
    return table


# ---------------------------------------------------------------------------
# Entorno
# ---------------------------------------------------------------------------


def is_termux() -> bool:
    return "com.termux" in os.environ.get("PREFIX", "") or Path(
        "/data/data/com.termux/files/usr"
    ).is_dir()


def platform_label() -> str:
    if is_termux():
        return "Termux (Android)"
    if sys.platform.startswith("linux"):
        return "Linux"
    if sys.platform == "darwin":
        return "macOS"
    if os.name == "nt":
        return "Windows"
    return sys.platform
