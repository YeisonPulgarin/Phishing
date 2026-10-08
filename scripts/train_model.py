"""Entrena el modelo ML con el dataset real PhiUSIIL y persiste `data/model.joblib`.

Uso:
    python scripts/train_model.py [ruta/al/PhiUSIIL_Phishing_URL_Dataset.csv]

Por defecto lee `data/dataset/PhiUSIIL_Phishing_URL_Dataset.csv` (descarga manual desde
https://archive.ics.uci.edu/dataset/967, no se versiona por tamaño).

Qué hace:
1. Lee URL y label (se invierte para que la clase positiva sea phishing) y quita duplicados.
2. Canonicaliza cada URL con `canonical_ml_url` (la misma función que usa el motor en
   producción, para evitar train/serve skew) y extrae las `ML_FEATURES`.
3. Separa 80/20 por dominio registrado (el mismo dominio nunca cae en train y test).
4. Compara Regresión Logística y Random Forest con validación cruzada agrupada por dominio
   (accuracy, precision, recall, F1 y AUC), elige por F1 medio y evalúa ambos en el test.
5. Guarda el modelo elegido y `data/model_report.json` con todas las métricas.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import joblib
import numpy as np
from sklearn.base import clone
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score,
)
from sklearn.model_selection import GroupKFold
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from dataset_utils import ROOT, SEED, load_dataset, resolve_dataset, split_indices
from app.engines.ml import ML_FEATURES

MODEL = ROOT / "data/model.joblib"
REPORT = ROOT / "data/model_report.json"


def metrics(y_true, y_pred, proba) -> dict:
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred)),
        "recall": float(recall_score(y_true, y_pred)),
        "f1": float(f1_score(y_true, y_pred)),
        "auc": float(roc_auc_score(y_true, proba)),
    }


def candidates() -> dict:
    return {
        "regresion_logistica": make_pipeline(
            StandardScaler(),
            LogisticRegression(max_iter=2000, class_weight="balanced", random_state=SEED),
        ),
        # Profundidad y hojas mínimas acotadas: el modelo queda liviano (versionable) y
        # generaliza mejor que un bosque sin límite.
        "random_forest": RandomForestClassifier(
            n_estimators=100, max_depth=14, min_samples_leaf=10,
            class_weight="balanced", n_jobs=-1, random_state=SEED,
        ),
    }


def cross_validate(model, X, y, groups, folds: int = 5) -> dict:
    rows = []
    for tr, va in GroupKFold(n_splits=folds).split(X, y, groups):
        m = clone(model).fit(X[tr], y[tr])
        proba = m.predict_proba(X[va])[:, 1]
        rows.append(metrics(y[va], (proba >= 0.5).astype(int), proba))
    out = {k: float(np.mean([r[k] for r in rows])) for k in rows[0]}
    out["f1_std"] = float(np.std([r["f1"] for r in rows]))
    return out


def main() -> None:
    path = resolve_dataset(sys.argv)
    _, y, groups, X, dups = load_dataset(path)
    print(f"Filas usadas: {len(y)} (duplicadas descartadas: {dups}) | "
          f"phishing: {int(y.sum())} | legítimas: {int((1 - y).sum())} | "
          f"features: {len(ML_FEATURES)}")

    tr, te = split_indices(X, y, groups)
    X_tr, y_tr, g_tr, X_te, y_te = X[tr], y[tr], groups[tr], X[te], y[te]

    report = {"dataset": path.name, "filas": int(len(y)), "duplicadas_descartadas": dups,
              "features": ML_FEATURES, "cv": {}, "test": {}, "matriz_confusion_test": {}}
    fitted, best_name, best_f1 = {}, None, -1.0
    for name, model in candidates().items():
        cv = cross_validate(model, X_tr, y_tr, g_tr)
        report["cv"][name] = cv
        print(f"[CV 5 pliegues] {name}: F1={cv['f1']:.4f} (±{cv['f1_std']:.4f}) "
              f"acc={cv['accuracy']:.4f} prec={cv['precision']:.4f} "
              f"rec={cv['recall']:.4f} auc={cv['auc']:.4f}")
        fitted[name] = clone(model).fit(X_tr, y_tr)
        proba = fitted[name].predict_proba(X_te)[:, 1]
        pred = (proba >= 0.5).astype(int)
        report["test"][name] = metrics(y_te, pred, proba)
        report["matriz_confusion_test"][name] = confusion_matrix(y_te, pred).tolist()  # [[TN,FP],[FN,TP]]
        if cv["f1"] > best_f1:
            best_name, best_f1 = name, cv["f1"]

    final = fitted[best_name]
    report["modelo_elegido"] = best_name

    # Baseline: ¿qué tan buena es la regla trivial "tiene subdominio => phishing"?
    sub = X_te[:, ML_FEATURES.index("num_subdomains")] > 0
    report["baseline_subdominio_test"] = metrics(y_te, sub.astype(int), sub.astype(float))

    est = final[-1] if hasattr(final, "steps") else final
    imp = np.abs(est.coef_[0]) if hasattr(est, "coef_") else est.feature_importances_
    report["importancia_features"] = {n: float(v) for n, v in zip(ML_FEATURES, imp)}

    MODEL.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(final, MODEL, compress=3)
    REPORT.write_text(json.dumps(report, indent=2, ensure_ascii=False))

    print(f"\nModelo elegido: {best_name}")
    for name, t in report["test"].items():
        mark = " <- elegido" if name == best_name else ""
        print(f"TEST {name:20} acc={t['accuracy']:.4f} prec={t['precision']:.4f} "
              f"rec={t['recall']:.4f} f1={t['f1']:.4f} auc={t['auc']:.4f}{mark}")
    b = report["baseline_subdominio_test"]
    print(f"Baseline 'tiene subdominio => phishing': acc={b['accuracy']:.4f} f1={b['f1']:.4f}")
    top = sorted(report["importancia_features"].items(), key=lambda kv: -kv[1])[:5]
    print("Importancia (top 5):", {k: round(v, 3) for k, v in top})
    print(f"Guardado: {MODEL} ({MODEL.stat().st_size / 1e6:.1f} MB) y {REPORT.name}")


if __name__ == "__main__":
    main()
