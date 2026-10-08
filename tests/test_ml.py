"""Tests del motor ML (app.engines.ml)."""
import numpy as np
import pytest

from app.engines.base import AnalysisContext
from app.engines.ml import FeatureExtractor, MlEngine, canonical_ml_url


class FakeClassifier:
    """Clasificador simulado: probabilidad de phishing configurable."""

    def __init__(self, proba):
        self._proba = proba

    def predict_proba(self, X):
        n = len(X)
        return np.full((n, 2), [1 - self._proba, self._proba])


@pytest.fixture()
def extractor():
    return FeatureExtractor()


def test_feature_extractor_shapes(extractor):
    ctx = AnalysisContext.from_url("https://www.google.com/login")
    feats = extractor.extract(ctx)
    assert isinstance(feats, list)
    assert len(feats) > 5
    assert all(isinstance(x, float) for x in feats)


def test_feature_extractor_distinguishes(extractor):
    benign = extractor.extract(AnalysisContext.from_url("https://www.google.com"))
    malicious = extractor.extract(
        AnalysisContext.from_url("http://user@192.168.1.1/secure/login/verify-1"
                                 "23-abc-def-ghi-jkl-mno-pqr-stu-vwx-yz-very-long-path")
    )
    # El extractor produce vectores con suficientes diferencias
    assert malicious != benign


def test_ml_engine_uses_probability_as_score():
    model = FakeClassifier(proba=0.87)
    engine = MlEngine(model)
    result = engine.analyze(AnalysisContext.from_url("https://something.com"))
    assert result.normalized_score == pytest.approx(87.0, abs=1.0)


def test_ml_engine_low_probability():
    model = FakeClassifier(proba=0.05)
    engine = MlEngine(model)
    result = engine.analyze(AnalysisContext.from_url("https://www.wikipedia.org"))
    assert result.normalized_score < 20


def test_ml_engine_returns_motivo(extractor):
    model = FakeClassifier(proba=0.7)
    engine = MlEngine(model)
    result = engine.analyze(AnalysisContext.from_url("https://x.com"))
    assert result.motivos
    assert isinstance(result.motivos[0], str)


def test_trained_model_load_and_predict():
    """El modelo versionado carga y distingue una URL maligna de una benigna."""
    from app.core.config import Settings
    from app.engines.ml import MlEngine, load_model

    model = load_model(Settings().model_path)
    engine = MlEngine(model)

    benign = engine.analyze(
        AnalysisContext.from_url("https://www.google.com/about")
    ).normalized_score
    malicious = engine.analyze(
        AnalysisContext.from_url("http://user@192.168.1.1/secure/login/verify-account")
    ).normalized_score

    assert malicious > benign


class RecordingClassifier:
    """Guarda las features recibidas para comprobar qué ve el modelo."""

    def __init__(self):
        self.seen = []

    def predict_proba(self, X):
        self.seen.extend(X)
        return np.full((len(X), 2), [0.5, 0.5])


def test_canonical_ml_url_keeps_only_domain_structure():
    assert canonical_ml_url("https://www.Google.com:443/a/b?x=1") == "https://google.com"
    assert canonical_ml_url("http://example.com/") == "https://example.com"
    assert canonical_ml_url("example.com/login") == "https://example.com"
    # El truco del @ y la IP son estructura de dominio: se conservan.
    assert canonical_ml_url("http://user@192.168.1.1/x") == "https://user@192.168.1.1"


def test_ml_engine_ignores_scheme_www_and_path():
    """Esquema, www y ruta no deben cambiar lo que ve el modelo (atajos del dataset)."""
    rec_a, rec_b = RecordingClassifier(), RecordingClassifier()
    MlEngine(rec_a).analyze(AnalysisContext.from_url("http://www.example.com/a/b/c?q=1"))
    MlEngine(rec_b).analyze(AnalysisContext.from_url("https://example.com"))
    assert rec_a.seen == rec_b.seen


def test_domain_features_match_declared_names_and_values():
    from app.engines.ml import ML_FEATURES

    ctx = AnalysisContext.from_url(canonical_ml_url("http://www.login-secure1.paypal-verify.tk/x?y=1"))
    named = dict(zip(ML_FEATURES, FeatureExtractor().extract_domain(ctx)))
    assert len(named) == len(ML_FEATURES) == 25
    assert named["hyphens_in_domain"] == 1.0          # paypal-verify
    assert named["hyphen_in_subdomain"] == 1.0         # login-secure1
    assert named["digit_in_subdomain"] == 1.0
    assert named["tld_com"] == 0.0 and named["tld_len"] == 2.0
    assert named["is_ip"] == 0.0 and named["has_at"] == 0.0


def test_load_model_rejects_model_with_different_feature_count(tmp_path):
    import joblib
    from sklearn.ensemble import RandomForestClassifier

    from app.engines.ml import load_model

    X = np.random.default_rng(0).random((30, 3))
    y = np.array([0, 1] * 15)
    path = tmp_path / "viejo.joblib"
    joblib.dump(RandomForestClassifier(n_estimators=3).fit(X, y), path)
    with pytest.raises(RuntimeError, match="Reentrená"):
        load_model(str(path))
