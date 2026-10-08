"""Orquestación del análisis de URLs.

Normaliza la URL, ejecuta los motores y conectores disponibles, combina los sub-scores con
el `ScoreCombiner` y produce un `AnalysisReport` completo. Tolera fallos: un motor o
conector que falla o no está disponible se omite sin romper el análisis.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List

from urllib.parse import urlparse

from app.core.config import Settings
from app.core.scoring import ScoreCombiner, ScoringOutput
from app.engines.base import AnalysisContext, EngineStatus
from app.engines.heuristic import HeuristicEngine
from app.engines.reputation import ReputationList
from app.engines.ml import MlEngine, load_model
from app.engines.red import NetworkEngine


@dataclass
class AnalysisReport:
    url: str
    veredicto: str
    score: float
    confianza: float
    motivos: List[str] = field(default_factory=list)
    desglose: Dict[str, float] = field(default_factory=dict)


def normalize_url(url: str) -> str:
    """Agrega https:// si la URL no trae esquema."""
    url = url.strip()
    if not urlparse(url).scheme:
        return f"https://{url}"
    return url


class AnalysisPipeline:
    """Ejecuta los motores de análisis y combina el resultado."""

    def __init__(
        self,
        settings: Settings,
        engines: list | None = None,
        connectors: list | None = None,
    ) -> None:
        self._settings = settings
        self._combiner = ScoreCombiner(settings)
        self._engines = engines if engines is not None else self._default_engines(settings)
        self._connectors = connectors if connectors is not None else self._default_connectors(settings)

    @property
    def ml_model(self):
        """Modelo del motor ML (para explicarlo con SHAP), o None si no hay motor ML."""
        for engine in self._engines:
            if isinstance(engine, MlEngine):
                return engine.model
        return None

    @staticmethod
    def _default_engines(settings: Settings) -> list:
        return [
            HeuristicEngine(),
            NetworkEngine(),
            MlEngine(load_model(settings.model_path), ReputationList.from_files(
                settings.known_domains_path,
                Path(settings.known_domains_path).with_name("known_domains_tranco.txt"),
            )),
        ]

    @staticmethod
    def _default_connectors(settings: Settings) -> list:
        from app.connectors.googlesafebrowsing import GoogleSafeBrowsingConnector
        from app.connectors.virustotal import VirusTotalConnector

        return [
            GoogleSafeBrowsingConnector(settings.gsb_api_key),
            VirusTotalConnector(settings.vt_api_key),
        ]

    def analyze(self, url: str) -> AnalysisReport:
        normalized = normalize_url(url)
        ctx = AnalysisContext.from_url(normalized)

        # Motores y conectores corren en paralelo con un tiempo máximo total (RNF2). Lo que
        # no responde a tiempo se omite y se informa; el resto del análisis sigue.
        jobs = [("engine", e, lambda e=e: e.analyze(ctx)) for e in self._engines]
        for c in self._connectors:
            if c.enabled:
                jobs.append(("connector", c, lambda c=c: c.check(normalized)))
            else:
                jobs.append(("disabled", c, None))

        pool = ThreadPoolExecutor(max_workers=max(len(jobs), 1))
        futures = [(kind, obj, pool.submit(fn) if fn else None) for kind, obj, fn in jobs]
        wait([f for _, _, f in futures if f], timeout=self._settings.analysis_timeout)
        pool.shutdown(wait=False, cancel_futures=True)

        sub_scores: Dict[str, float] = {}
        motivos: List[str] = []
        for kind, obj, fut in futures:
            if kind == "disabled":
                motivos.append(f"{obj.name} no disponible (sin API key)")
                continue
            if not fut.done():
                motivos.append(f"{obj.name} no respondió a tiempo y se omitió")
                continue
            try:
                result = fut.result()
            except Exception:
                # Un motor o conector que lanza excepción se omite en silencio.
                continue
            motivos.extend(result.motivos if kind == "engine" or result.estado == EngineStatus.OK else [])
            if result.estado == EngineStatus.OK:
                sub_scores[obj.name] = result.normalized_score

        out: ScoringOutput = self._combiner.combine(sub_scores)
        if not motivos:
            motivos.append("Sin señales destacables")

        return AnalysisReport(
            url=normalized,
            veredicto=out.veredicto,
            score=out.score,
            confianza=out.confianza,
            motivos=motivos,
            desglose=sub_scores,
        )
