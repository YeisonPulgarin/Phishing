"""Combinador de scoring: pondera los sub-scores de los motores y produce el veredicto.

Recibe los sub-scores de los motores disponibles (los no disponibles se omiten) y aplica
los pesos de configuración re-normalizados sobre los motores presentes. Devuelve el score
final 0-100, la banda de veredicto y una confianza que crece con la cantidad de motores que
aportaron evidencia.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict

from app.core.config import Settings


@dataclass
class ScoringOutput:
    score: float
    veredicto: str
    confianza: float


class ScoreCombiner:
    """Pesos + bandas + confianza a partir de sub-scores por motor."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def _weights(self, available: set[str]) -> Dict[str, float]:
        base = {
            "ml": self._settings.ml_weight,
            "heuristica": self._settings.heuristic_weight,
            "red": self._settings.network_weight,
        }
        # Conectores comparten el peso de conectores.
        connectors = ["google_safe_browsing", "virustotal"]
        conn_per = self._settings.connector_weight / max(len(connectors), 1)
        for c in connectors:
            base[c] = conn_per

        kept = {k: v for k, v in base.items() if k in available}
        total = sum(kept.values())
        if total <= 0:
            return {}
        return {k: v / total for k, v in kept.items()}

    def combine(self, sub_scores: Dict[str, float]) -> ScoringOutput:
        available = {k for k, v in sub_scores.items() if v is not None}
        weights = self._weights(available)
        if not weights:
            return ScoringOutput(score=0.0, veredicto="seguro", confianza=0.0)

        score = sum(v * weights[k] for k, v in sub_scores.items() if k in weights)
        score = max(0.0, min(100.0, score))
        veredicto = self._settings.band_name(int(round(score)))

        # Confianza: crece con la cantidad de motores que aportaron.
        n = len(weights)
        confianza = min(1.0, 0.3 + 0.18 * n)

        # Overrides de banda ya vienen aplicados dentro de cada motor (sub-score alto).
        return ScoringOutput(score=round(score, 1), veredicto=veredicto, confianza=round(confianza, 2))
