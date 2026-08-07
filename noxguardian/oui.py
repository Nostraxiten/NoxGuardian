"""Resolucion de fabricante a partir de la MAC (prefijo OUI), 100% offline.

Estrategia de carga, de menor a mayor prioridad (las fuentes posteriores
sobreescriben a las anteriores):

  1. Tabla curada incluida en el proyecto (`data/oui_prefixes.csv`).
  2. Bases de datos del sistema, si existen (nmap y wireshark las traen):
       /usr/share/nmap/nmap-mac-prefixes
       /usr/share/wireshark/manuf
       $PREFIX/share/nmap/nmap-mac-prefixes   (Termux)
  3. Fichero pasado por el usuario con --oui-file.

Nunca se consulta una API externa.

Ademas se detectan MACs localmente administradas (bit U/L del primer octeto),
que es lo que usan iOS/Android/Windows para la aleatorizacion de MAC por
privacidad: en esos casos el prefijo OUI no identifica a ningun fabricante y
reportarlo seria enganoso.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Dict, Iterable, List, Optional

VENDOR_UNKNOWN = "Desconocido"
VENDOR_RANDOMIZED = "MAC aleatoria (privacidad)"
VENDOR_UNAVAILABLE = "no disponible"

_DATA_FILE = Path(__file__).with_name("data") / "oui_prefixes.csv"

_SYSTEM_SOURCES: tuple[str, ...] = (
    "/usr/share/nmap/nmap-mac-prefixes",
    "/usr/local/share/nmap/nmap-mac-prefixes",
    "/data/data/com.termux/files/usr/share/nmap/nmap-mac-prefixes",
    "/usr/share/wireshark/manuf",
    "/usr/share/ieee-data/oui.txt",
)

_MAC_RE = re.compile(r"^[0-9a-fA-F]{2}([:-]?[0-9a-fA-F]{2}){5}$")
_HEX6_RE = re.compile(r"^[0-9A-F]{6}$")


def normalize_mac(mac: Optional[str]) -> Optional[str]:
    """Devuelve la MAC en formato canonico `aa:bb:cc:dd:ee:ff`, o None."""
    if not mac:
        return None
    candidate = mac.strip()
    if not _MAC_RE.match(candidate):
        return None
    hexonly = re.sub(r"[:-]", "", candidate).lower()
    return ":".join(hexonly[i : i + 2] for i in range(0, 12, 2))


def mac_prefix(mac: str) -> str:
    """Primeros 3 octetos de la MAC en hexadecimal mayusculas, sin separadores."""
    return re.sub(r"[:-]", "", mac).upper()[:6]


def is_locally_administered(mac: str) -> bool:
    """True si el bit U/L esta puesto -> MAC aleatorizada / asignada localmente."""
    try:
        first_octet = int(re.sub(r"[:-]", "", mac)[:2], 16)
    except (ValueError, IndexError):
        return False
    return bool(first_octet & 0b10)


def is_multicast(mac: str) -> bool:
    try:
        first_octet = int(re.sub(r"[:-]", "", mac)[:2], 16)
    except (ValueError, IndexError):
        return False
    return bool(first_octet & 0b1)


class OuiResolver:
    """Tabla de prefijos OUI -> fabricante, cargada en memoria una sola vez."""

    def __init__(
        self,
        extra_file: Optional[Path] = None,
        use_system_sources: bool = True,
    ) -> None:
        self._table: Dict[str, str] = {}
        self.sources: List[str] = []
        self._load_bundled()
        if use_system_sources:
            self._load_system()
        if extra_file:
            self._load_file(Path(extra_file), label=str(extra_file))

    # -- carga ---------------------------------------------------------------

    def _load_bundled(self) -> None:
        if _DATA_FILE.exists():
            self._load_file(_DATA_FILE, label="bundled")

    def _load_system(self) -> None:
        candidates = list(_SYSTEM_SOURCES)
        prefix = os.environ.get("PREFIX")  # Termux
        if prefix:
            candidates.insert(0, f"{prefix}/share/nmap/nmap-mac-prefixes")
        seen: set[str] = set()
        for raw in candidates:
            path = Path(raw)
            key = str(path)
            if key in seen:
                continue
            seen.add(key)
            if path.is_file():
                self._load_file(path, label=key)

    def _load_file(self, path: Path, label: str) -> None:
        """Carga un fichero de prefijos. Tolera los 3 formatos habituales."""
        loaded = 0
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    entry = self._parse_line(line)
                    if entry is None:
                        continue
                    prefix, vendor = entry
                    self._table[prefix] = vendor
                    loaded += 1
        except OSError:
            return
        if loaded:
            self.sources.append(f"{label} ({loaded})")

    @staticmethod
    def _parse_line(line: str) -> Optional[tuple[str, str]]:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return None

        # Formato bundled: "AABBCC,Vendor Name"
        if "," in stripped and "\t" not in stripped:
            raw_prefix, _, vendor = stripped.partition(",")
            prefix = re.sub(r"[:\-.]", "", raw_prefix.strip()).upper()
            vendor = vendor.strip()
            if _HEX6_RE.match(prefix) and vendor:
                return prefix, vendor
            return None

        # Formato IEEE oui.txt: "AA-BB-CC   (hex)\t\tVendor Name"
        if "(hex)" in stripped:
            raw_prefix, _, vendor = stripped.partition("(hex)")
            prefix = re.sub(r"[:\-.]", "", raw_prefix.strip()).upper()
            vendor = vendor.strip()
            if _HEX6_RE.match(prefix) and vendor:
                return prefix, vendor
            return None

        # Los dos formatos restantes se distinguen por el separador, y hay que
        # tratarlos por separado: en manuf los campos van con TAB y el nombre
        # del fabricante es el tercero, mientras que en nmap-mac-prefixes solo
        # hay un espacio y TODO lo que sigue al prefijo es el nombre. Partir
        # nmap-mac-prefixes por espacios se comeria la primera palabra
        # ("Sagemcom Broadband SAS" -> "Broadband SAS").
        if "\t" in stripped:
            # wireshark manuf: "AA:BB:CC\tAbreviatura\tNombre largo"
            fields = [field.strip() for field in stripped.split("\t") if field.strip()]
            if len(fields) < 2:
                return None
            raw_prefix = fields[0]
            vendor = fields[2] if len(fields) > 2 else fields[1]
        else:
            # nmap-mac-prefixes: "AABBCC Nombre completo del fabricante"
            raw_prefix, _, vendor = stripped.partition(" ")
            vendor = vendor.strip()

        # Los prefijos con mascara (/28, /36) de manuf no son OUI de 3 octetos.
        if "/" in raw_prefix:
            return None
        prefix = re.sub(r"[:\-.]", "", raw_prefix).upper()
        if not _HEX6_RE.match(prefix):
            return None
        vendor = vendor.split("#")[0].strip()
        return (prefix, vendor) if vendor else None

    # -- consulta ------------------------------------------------------------

    def lookup(self, mac: Optional[str]) -> str:
        """Fabricante para una MAC. Nunca lanza; devuelve una etiqueta legible."""
        normalized = normalize_mac(mac)
        if normalized is None:
            return VENDOR_UNAVAILABLE
        if is_locally_administered(normalized):
            return VENDOR_RANDOMIZED
        return self._table.get(mac_prefix(normalized), VENDOR_UNKNOWN)

    def lookup_with_hint(self, mac: Optional[str], nmap_vendor: Optional[str]) -> str:
        """Como `lookup`, pero acepta el vendor que ya reporto nmap como respaldo.

        La tabla local manda; el dato de nmap solo se usa si la tabla no conoce
        el prefijo. Para MACs aleatorizadas ninguna de las dos fuentes es fiable.
        """
        resolved = self.lookup(mac)
        if resolved in (VENDOR_UNKNOWN,) and nmap_vendor:
            return nmap_vendor.strip()
        return resolved

    def __len__(self) -> int:
        return len(self._table)

    def describe(self) -> str:
        if not self.sources:
            return "sin fuentes OUI (todos los fabricantes saldran como desconocidos)"
        return f"{len(self._table)} prefijos desde: " + ", ".join(self.sources)


def iter_known_prefixes(resolver: OuiResolver) -> Iterable[tuple[str, str]]:
    """Utilidad para herramientas de mantenimiento (tools/build_oui.py)."""
    return sorted(resolver._table.items())  # noqa: SLF001 - uso interno controlado
