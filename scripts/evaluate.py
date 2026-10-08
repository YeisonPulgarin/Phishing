"""Evaluación comparativa (RNF6): reglas heurísticas vs ML vs puntaje combinado.

Uso:
    python scripts/evaluate.py [ruta/al/PhiUSIIL_Phishing_URL_Dataset.csv]

Usa exactamente el mismo test que `train_model.py` (80/20 por dominio, semilla fija), de modo
que el modelo no vio ninguno de esos dominios. Compara cinco sistemas con precisión, recall,
F1, accuracy y AUC-ROC, en dos umbrales de alerta:
  - umbral 35: se alerta si el veredicto sería `sospechoso` o `phishing`;
  - umbral 60: se alerta solo si el veredicto sería `phishing`.

Sistemas:
  - heurística (URL completa): las reglas tal como corren en producción;
  - heurística (solo dominio): las mismas reglas sobre la URL canónica del ML;
  - ML: el modelo entrenado, sobre la estructura del dominio;
  - combinado (heurística completa + ML) y combinado (heurística solo dominio + ML), con los
    pesos configurados (`ScoreCombiner`).
El motor de red y los conectores no se incluyen: dependen de consultas en vivo (DNS, RDAP,
certificados) y no se pueden repetir sobre decenas de miles de URLs.

Salida: `data/evaluation_report.json` y `docs/evaluacion.md`.
"""
from __future__ import annotations

import json
import sys

import numpy as np
from sklearn.metrics import (
    accuracy_score, confusion_matrix, f1_score, precision_score, recall_score,
    roc_auc_score, roc_curve,
)

from dataset_utils import ROOT, load_dataset, resolve_dataset, split_indices
from app.core.config import Settings
from app.core.scoring import ScoreCombiner
from app.engines.base import AnalysisContext
from app.engines.heuristic import HeuristicEngine
from app.engines.ml import canonical_ml_url, load_model

REPORT = ROOT / "data/evaluation_report.json"
DOC = ROOT / "docs/evaluacion.md"
THRESHOLDS = {"umbral_35": 35, "umbral_60": 60}
NAMES = {
    "heuristica_url_completa": "Reglas heurísticas (URL completa)",
    "heuristica_solo_dominio": "Reglas heurísticas (solo dominio)",
    "ml": "Modelo ML",
    "combinado_url_completa": "Combinado: heurística (URL completa) + ML",
    "combinado_solo_dominio": "Combinado: heurística (solo dominio) + ML",
}


def heuristic_scores(urls, canonical: bool) -> np.ndarray:
    engine = HeuristicEngine()
    out = np.empty(len(urls))
    for i, url in enumerate(urls):
        ctx = AnalysisContext.from_url(canonical_ml_url(url) if canonical else url)
        out[i] = engine.analyze(ctx).normalized_score
    return out


def combine(settings: Settings, heuristic: np.ndarray, ml: np.ndarray) -> np.ndarray:
    combiner = ScoreCombiner(settings)
    return np.array([combiner.combine({"heuristica": h, "ml": m}).score for h, m in zip(heuristic, ml)])


def evaluate(y, score) -> dict:
    out = {"auc": float(roc_auc_score(y, score))}
    for label, thr in THRESHOLDS.items():
        pred = (score >= thr).astype(int)
        tn, fp, fn, tp = confusion_matrix(y, pred).ravel()
        out[label] = {
            "accuracy": float(accuracy_score(y, pred)),
            "precision": float(precision_score(y, pred, zero_division=0)),
            "recall": float(recall_score(y, pred)),
            "f1": float(f1_score(y, pred)),
            "matriz": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        }
    fpr, tpr, _ = roc_curve(y, score)
    idx = np.unique(np.linspace(0, len(fpr) - 1, 200).astype(int))
    out["roc"] = {"fpr": [round(float(v), 4) for v in fpr[idx]], "tpr": [round(float(v), 4) for v in tpr[idx]]}
    return out


def markdown(report: dict) -> str:
    lines = [
        "# Evaluación comparativa: reglas vs ML vs combinado", "",
        f"Test: {report['filas_test']} URLs de dominios que el modelo no vio "
        f"({report['phishing_test']} phishing, {report['legitimas_test']} legítimas). "
        "Generado con `python scripts/evaluate.py`.", "",
        "El motor de red y los conectores quedan fuera: dependen de consultas en vivo.", "",
    ]
    for label, thr in THRESHOLDS.items():
        what = "sospechoso o phishing" if thr == 35 else "solo phishing"
        lines += [f"## Alerta desde score {thr} ({what})", "",
                  "| Sistema | Accuracy | Precisión | Recall | F1 | AUC-ROC |", "|---|---|---|---|---|---|"]
        for key, name in NAMES.items():
            r = report["sistemas"][key]
            m = r[label]
            lines.append(f"| {name} | {m['accuracy']:.3f} | {m['precision']:.3f} | {m['recall']:.3f} "
                         f"| {m['f1']:.3f} | {r['auc']:.3f} |")
        lines.append("")
    return "\n".join(lines)


def main() -> None:
    path = resolve_dataset(sys.argv)
    urls, y, groups, X, _ = load_dataset(path)
    _, te = split_indices(X, y, groups)
    urls_te, y_te, X_te = urls[te], y[te], X[te]
    print(f"Test: {len(y_te)} URLs ({int(y_te.sum())} phishing, {int((1 - y_te).sum())} legítimas)")

    ml = load_model(str(ROOT / "data/model.joblib")).predict_proba(X_te)[:, 1] * 100
    print("Calculando reglas heurísticas (URL completa)...", flush=True)
    h_full = heuristic_scores(urls_te, canonical=False)
    print("Calculando reglas heurísticas (solo dominio)...", flush=True)
    h_dom = heuristic_scores(urls_te, canonical=True)

    settings = Settings()
    systems = {
        "heuristica_url_completa": h_full,
        "heuristica_solo_dominio": h_dom,
        "ml": ml,
        "combinado_url_completa": combine(settings, h_full, ml),
        "combinado_solo_dominio": combine(settings, h_dom, ml),
    }
    report = {"filas_test": int(len(y_te)), "phishing_test": int(y_te.sum()),
              "legitimas_test": int((1 - y_te).sum()), "pesos": {
                  "heuristica": settings.heuristic_weight, "ml": settings.ml_weight},
              "sistemas": {k: evaluate(y_te, v) for k, v in systems.items()}}

    REPORT.write_text(json.dumps(report, indent=2, ensure_ascii=False))
    DOC.parent.mkdir(parents=True, exist_ok=True)
    DOC.write_text(markdown(report))
    print("\n" + markdown(report))
    print(f"Guardado: {REPORT.name} y {DOC.name}")


if __name__ == "__main__":
    main()
