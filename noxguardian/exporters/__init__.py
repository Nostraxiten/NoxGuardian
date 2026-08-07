"""Capas de salida: log de texto, checkpoints JSON y reporte Excel."""

from .checkpoint import CheckpointStore
from .txtlog import EventLog

__all__ = ["EventLog", "CheckpointStore"]
