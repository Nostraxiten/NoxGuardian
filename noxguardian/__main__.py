"""Permite ejecutar `python3 -m noxguardian`."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
