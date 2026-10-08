"""Explicación de la predicción del modelo ML con SHAP (RF7).

Para una URL calcula cuánto aportó cada característica del dominio a la probabilidad de
phishing que estima el modelo. Con modelos de árbol (Random Forest) usa `shap.TreeExplainer`
(valores exactos, en puntos de probabilidad); con Regresión Logística usa la forma cerrada
de SHAP para modelos lineales (en log-odds). Solo explica el componente ML: las reglas
heurísticas y de red ya traen sus propios motivos en el análisis.
"""
from __future__ import annotations

from typing import Any

import numpy as np

from app.engines.base import AnalysisContext
from app.engines.ml import FEATURE_LABELS, ML_FEATURES, FeatureExtractor, canonical_ml_url

_BOOLEAN = {
    "is_ip", "has_at", "short_host", "hyphen_in_subdomain", "digit_in_subdomain",
    "tld_com", "tld_org_net_edu_gov", "multi_level_suffix",
}
_RATIO = {"digit_ratio", "vowel_ratio"}


def _format_value(name: str, value: float) -> str:
    if name in _BOOLEAN:
        return "sí" if value >= 0.5 else "no"
    if name in _RATIO:
        return f"{value * 100:.0f}%"
    return f"{value:g}" if float(value).is_integer() else f"{value:.2f}"


class ModelExplainer:
    """Calcula contribuciones SHAP por característica para una URL."""

    def __init__(self, model: Any) -> None:
        self._model = model
        self._extractor = FeatureExtractor()
        self._estimator = model[-1] if hasattr(model, "steps") else model
        self._scaler = model[0] if hasattr(model, "steps") and len(model.steps) > 1 else None
        self._tree = None  # shap.TreeExplainer, se crea en el primer uso

    @property
    def kind(self) -> str:
        if hasattr(self._estimator, "estimators_") or hasattr(self._estimator, "tree_"):
            return "arbol"
        if hasattr(self._estimator, "coef_"):
            return "lineal"
        raise TypeError("Modelo no soportado para explicación SHAP")

    def _contributions(self, x: np.ndarray) -> tuple[np.ndarray, float, str]:
        """Devuelve (contribuciones por feature, valor base, unidad)."""
        if self.kind == "lineal":
            xs = self._scaler.transform(x) if self._scaler is not None else x
            # Con features estandarizadas la media es 0: shap_i = coef_i * x_i (log-odds).
            return self._estimator.coef_[0] * xs[0], float(self._estimator.intercept_[0]), "log-odds"

        if self._tree is None:
            import shap

            self._tree = shap.TreeExplainer(self._estimator)
        raw = self._tree.shap_values(x, check_additivity=False)
        if isinstance(raw, list):                      # versiones viejas: lista por clase
            values = np.asarray(raw[1])[0]
        else:
            arr = np.asarray(raw)
            values = arr[0, :, 1] if arr.ndim == 3 else arr[0]
        base = np.atleast_1d(self._tree.expected_value)
        base_value = float(base[1] if base.size > 1 else base[0])
        return values, base_value, "probabilidad"

    def explain(self, url: str, top: int = 6) -> dict:
        canonical = AnalysisContext.from_url(canonical_ml_url(url))
        vector = self._extractor.extract_domain(canonical)
        x = np.array([vector])
        values, base, unit = self._contributions(x)
        prob = float(self._model.predict_proba(x)[0][1])

        order = np.argsort(-np.abs(values))
        scale = 100.0 if unit == "probabilidad" else 1.0   # puntos porcentuales o log-odds
        contributions = []
        for i in order[:top]:
            name = ML_FEATURES[i]
            c = float(values[i])
            contributions.append({
                "caracteristica": name,
                "descripcion": FEATURE_LABELS.get(name, name),
                "valor": float(vector[i]),
                "valor_texto": _format_value(name, vector[i]),
                "contribucion": round(c * scale, 2),
                "efecto": "sube el riesgo" if c > 0 else "baja el riesgo",
            })
        rest = float(values[order[top:]].sum()) if len(order) > top else 0.0
        return {
            "dominio": canonical.host,
            "probabilidad_phishing": round(prob, 4),
            "valor_base": round(base * (100.0 if unit == "probabilidad" else 1.0), 2),
            "unidad": "puntos porcentuales" if unit == "probabilidad" else "log-odds",
            "contribuciones": contributions,
            "resto_contribucion": round(rest * scale, 2),
            "nota": "Explica solo el componente de aprendizaje automático; considera "
                    "únicamente la estructura del dominio.",
        }
