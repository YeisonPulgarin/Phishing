"""Contrato base de conectores externos (inteligencia de terceros).

Cada conector produce un sub-score 0-100 y motivos. Si el conector no tiene API key
configurada o la llamada externa falla, reporta `no_disponible` para que el pipeline lo
ignore sin bloquear el análisis local.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Protocol, runtime_checkable


class ConnectorStatus(str, Enum):
    OK = "ok"
    ERROR = "error"
    NO_DISPONIBLE = "no_disponible"


@dataclass
class ConnectorResult:
    """Resultado de un conector externo."""

    sub_score: float
    motivos: List[str] = field(default_factory=list)
    estado: ConnectorStatus = ConnectorStatus.OK

    @property
    def normalized_score(self) -> float:
        return max(0.0, min(100.0, self.sub_score))


@runtime_checkable
class Transport(Protocol):
    """Abstracción de transporte HTTP, inyectable para testear sin red."""

    def post(self, url, *, json=None, headers=None, timeout=5): ...
    def get(self, url, *, headers=None, timeout=5): ...


@runtime_checkable
class Connector(Protocol):
    """Interfaz común de los conectores externos."""

    name: str
    enabled: bool

    def check(self, url: str) -> ConnectorResult: ...


class RequestsTransport:
    """Transporte HTTP real basado en requests."""

    def post(self, url, *, json=None, headers=None, timeout=5):
        import requests

        return requests.post(url, json=json, headers=headers, timeout=timeout)

    def get(self, url, *, headers=None, timeout=5):
        import requests

        return requests.get(url, headers=headers, timeout=timeout)
