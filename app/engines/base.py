"""Contrato base de motores de análisis y contexto compartido.

Cada motor produce un sub-score 0-100 y motivos en lenguaje natural. El pipeline
orquesta los motores y tolera fallos: un motor puede reportar `estado` distinto de "ok"
sin romper el análisis.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Protocol, runtime_checkable

from tldextract import TLDExtract
from urllib.parse import urlsplit

_extract = TLDExtract()


class EngineStatus(str, Enum):
    OK = "ok"
    ERROR = "error"
    NO_DISPONIBLE = "no_disponible"


@dataclass
class EngineResult:
    """Resultado de un motor de análisis."""

    sub_score: float
    motivos: List[str] = field(default_factory=list)
    estado: EngineStatus = EngineStatus.OK

    @property
    def normalized_score(self) -> float:
        return max(0.0, min(100.0, self.sub_score))


@dataclass
class AnalysisContext:
    """Datos compartidos del análisis de una URL."""

    url: str
    scheme: str = ""
    host: str = ""
    path: str = ""
    query: str = ""
    username: str = ""
    port: str = ""
    registered_domain: str = ""
    subdomain: str = ""
    suffix: str = ""

    @classmethod
    def from_url(cls, url: str) -> "AnalysisContext":
        parts = urlsplit(url)
        ext = _extract(parts.hostname or "")
        return cls(
            url=url,
            scheme=parts.scheme,
            host=parts.hostname or "",
            path=parts.path,
            query=parts.query,
            username=parts.username or "",
            port=str(parts.port) if parts.port else "",
            registered_domain=ext.top_domain_under_public_suffix,
            subdomain=ext.subdomain,
            suffix=ext.suffix,
        )


@runtime_checkable
class Engine(Protocol):
    """Interfaz común de los motores de análisis."""

    name: str

    def analyze(self, ctx: AnalysisContext) -> EngineResult: ...
