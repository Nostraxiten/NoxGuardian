"""Persistencia del estado completo en JSON (checkpoints y --resume).

El guardado es atomico: se escribe a un `.tmp` en el mismo directorio, se
sincroniza a disco y se hace `os.replace`. Asi un corte de corriente a mitad
de escritura nunca deja el checkpoint corrupto: o esta el anterior intacto, o
esta el nuevo completo.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
from pathlib import Path
from typing import Any, Dict, Optional


class CheckpointError(RuntimeError):
    """Fallo al leer o escribir un checkpoint."""


class CheckpointStore:
    """Lector/escritor del fichero de estado JSON."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self.saves = 0
        self.last_error: Optional[str] = None

    @property
    def exists(self) -> bool:
        return self.path.is_file()

    # -- escritura -----------------------------------------------------------

    def save(self, payload: Dict[str, Any]) -> bool:
        """Guarda el estado de forma atomica. Devuelve True si tuvo exito."""
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            handle = None
            tmp_path: Optional[str] = None
            try:
                descriptor, tmp_path = tempfile.mkstemp(
                    dir=str(self.path.parent),
                    prefix=self.path.stem + ".",
                    suffix=".tmp",
                )
                handle = os.fdopen(descriptor, "w", encoding="utf-8")
                json.dump(payload, handle, ensure_ascii=False, indent=1, default=_fallback)
                handle.flush()
                os.fsync(handle.fileno())
                handle.close()
                handle = None
                os.replace(tmp_path, self.path)
                tmp_path = None
                self.saves += 1
                self.last_error = None
                return True
            except (OSError, TypeError, ValueError) as exc:
                self.last_error = str(exc)
                return False
            finally:
                if handle is not None:
                    try:
                        handle.close()
                    except OSError:
                        pass
                if tmp_path and os.path.exists(tmp_path):
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass

    # -- lectura -------------------------------------------------------------

    def load(self) -> Dict[str, Any]:
        """Carga el checkpoint. Lanza CheckpointError si no existe o no es valido."""
        if not self.path.is_file():
            raise CheckpointError(f"no existe ningun checkpoint en {self.path}")
        try:
            with self.path.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            raise CheckpointError(f"checkpoint ilegible ({exc})") from exc
        if not isinstance(data, dict):
            raise CheckpointError("el checkpoint no contiene un objeto JSON valido")
        return data


def _fallback(value: Any) -> Any:
    """Serializa lo que json no sepa manejar (Path, sets...) sin romper el guardado."""
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (set, frozenset, tuple)):
        return list(value)
    return str(value)
