#!/usr/bin/env python3
"""Regenera la tabla OUI incluida a partir de las bases del sistema.

Util cuando se despliega NoxGuardian en un equipo sin nmap/wireshark (Termux
minimalista): se ejecuta en una maquina que SI las tenga y se copia el CSV
resultante junto al proyecto.

    python3 tools/build_oui.py                       # sobrescribe la tabla incluida
    python3 tools/build_oui.py --output /tmp/oui.csv # a otro sitio
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from noxguardian.oui import OuiResolver, iter_known_prefixes  # noqa: E402

DEFAULT_OUTPUT = (
    Path(__file__).resolve().parent.parent / "noxguardian" / "data" / "oui_prefixes.csv"
)

HEADER = """\
# NoxGuardian - tabla de prefijos OUI (offline).
# Formato: AABBCC,Nombre del fabricante
# Generado por tools/build_oui.py a partir de las bases del sistema.
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--extra", type=Path, default=None, help="fichero OUI adicional a fusionar"
    )
    args = parser.parse_args()

    resolver = OuiResolver(extra_file=args.extra, use_system_sources=True)
    entries = list(iter_known_prefixes(resolver))
    if not entries:
        print("[E] no se encontro ninguna fuente OUI en este sistema", file=sys.stderr)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        handle.write(HEADER)
        for prefix, vendor in entries:
            handle.write(f"{prefix},{vendor}\n")

    print(f"[+] {len(entries)} prefijos escritos en {args.output}")
    print(f"    fuentes: {resolver.describe()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
