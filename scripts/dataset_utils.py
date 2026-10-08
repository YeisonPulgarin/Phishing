"""Utilidades compartidas por `train_model.py` y `evaluate.py` (dataset PhiUSIIL).

Garantizan que entrenamiento y evaluación usen exactamente los mismos datos y la misma
partición train/test (por dominio registrado, semilla fija).
"""
from __future__ import annotations

import csv
import sys
from pathlib import Path

import numpy as np
from sklearn.model_selection import GroupShuffleSplit

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.engines.base import AnalysisContext  # noqa: E402
from app.engines.ml import FeatureExtractor, canonical_ml_url  # noqa: E402

DEFAULT_DATASET = ROOT / "data/dataset/PhiUSIIL_Phishing_URL_Dataset.csv"
SEED = 42


def resolve_dataset(argv: list[str]) -> Path:
    path = Path(argv[1]) if len(argv) > 1 else DEFAULT_DATASET
    if not path.exists():
        sys.exit(
            f"No encuentro el dataset en {path}. Descargalo de "
            "https://archive.ics.uci.edu/dataset/967 y pasá la ruta como argumento."
        )
    return path


def load_dataset(path: Path):
    """Devuelve (urls, y, groups, X, duplicadas).

    `y` = 1 si es phishing (en PhiUSIIL, label 1 = legítima y 0 = phishing, se invierte).
    `X` son las `ML_FEATURES` calculadas sobre la URL canónica. `groups` = dominio registrado.
    """
    extractor = FeatureExtractor()
    seen, urls, X, y, groups, dups = set(), [], [], [], [], 0
    with path.open(newline="", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            url = row["URL"].strip()
            if url in seen:
                dups += 1
                continue
            seen.add(url)
            ctx = AnalysisContext.from_url(canonical_ml_url(url))
            urls.append(url)
            X.append(extractor.extract_domain(ctx))
            y.append(1 - int(row["label"]))
            groups.append(ctx.registered_domain or ctx.host)
    return np.array(urls, dtype=object), np.array(y), np.array(groups, dtype=object), np.array(X), dups


def split_indices(X, y, groups):
    """Partición 80/20 por dominio: un mismo dominio nunca está en train y test."""
    return next(GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=SEED).split(X, y, groups))
