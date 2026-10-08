"""Tests de la explicación SHAP del modelo ML (app.engines.explain)."""
import numpy as np
import pytest
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from app.engines.explain import ModelExplainer
from app.engines.ml import FEATURE_LABELS, ML_FEATURES, load_model

SUBDOMAINS = ML_FEATURES.index("num_subdomains")


def _toy_data():
    rng = np.random.default_rng(0)
    X = rng.random((400, len(ML_FEATURES)))
    y = (X[:, SUBDOMAINS] > 0.5).astype(int)   # el riesgo depende de los subdominios
    return X, y


@pytest.fixture(scope="module")
def forest():
    X, y = _toy_data()
    return RandomForestClassifier(n_estimators=15, max_depth=5, random_state=0).fit(X, y)


def test_every_feature_has_a_plain_language_label():
    assert set(ML_FEATURES) == set(FEATURE_LABELS)


def test_tree_explanation_structure_and_order(forest):
    out = ModelExplainer(forest).explain("https://a.b.c.example.com", top=5)
    assert out["unidad"] == "puntos porcentuales"
    assert len(out["contribuciones"]) == 5
    sizes = [abs(c["contribucion"]) for c in out["contribuciones"]]
    assert sizes == sorted(sizes, reverse=True)           # de mayor a menor aporte
    for c in out["contribuciones"]:
        assert c["efecto"] in {"sube el riesgo", "baja el riesgo"}
        assert c["descripcion"] == FEATURE_LABELS[c["caracteristica"]]


def test_tree_explanation_is_additive(forest):
    """valor base + todas las contribuciones = probabilidad de phishing (propiedad de SHAP)."""
    out = ModelExplainer(forest).explain("https://a.b.c.example.com", top=5)
    total = out["valor_base"] + sum(c["contribucion"] for c in out["contribuciones"]) + out["resto_contribucion"]
    assert total == pytest.approx(out["probabilidad_phishing"] * 100, abs=1.5)


def test_tree_explanation_points_to_the_feature_that_matters(forest):
    out = ModelExplainer(forest).explain("https://a.b.c.d.example.com")
    assert out["contribuciones"][0]["caracteristica"] == "num_subdomains"
    assert out["contribuciones"][0]["efecto"] == "sube el riesgo"


def test_linear_model_explanation():
    from app.engines.base import AnalysisContext
    from app.engines.ml import FeatureExtractor, canonical_ml_url

    X, y = _toy_data()
    model = make_pipeline(StandardScaler(), LogisticRegression(max_iter=500)).fit(X, y)
    url = "https://a.b.c.example.com"
    out = ModelExplainer(model).explain(url, top=4)
    assert out["unidad"] == "log-odds"
    vector = FeatureExtractor().extract_domain(AnalysisContext.from_url(canonical_ml_url(url)))
    logit = float(model.decision_function([vector])[0])
    total = out["valor_base"] + sum(c["contribucion"] for c in out["contribuciones"]) + out["resto_contribucion"]
    assert total == pytest.approx(logit, abs=0.05)   # aditividad exacta en el espacio log-odds


def test_unsupported_model_raises():
    class Odd:
        def predict_proba(self, X):
            return np.array([[0.5, 0.5]])

    with pytest.raises(TypeError):
        ModelExplainer(Odd()).explain("https://example.com")


def test_explains_the_real_trained_model():
    out = ModelExplainer(load_model("data/model.joblib")).explain("https://login.secure-bank.evil.tk/verify")
    assert 0.0 <= out["probabilidad_phishing"] <= 1.0
    assert out["contribuciones"] and out["dominio"] == "login.secure-bank.evil.tk"
    total = out["valor_base"] + sum(c["contribucion"] for c in out["contribuciones"]) + out["resto_contribucion"]
    assert total == pytest.approx(out["probabilidad_phishing"] * 100, abs=1.5)
