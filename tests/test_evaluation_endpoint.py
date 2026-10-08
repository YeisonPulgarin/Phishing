"""Tests de GET /api/evaluation (reportes que muestra la pestaña Evaluación)."""
import json

import pytest
from fastapi.testclient import TestClient

import app.core.security as security
from app.api.deps import get_settings
from app.core.config import Settings
from app.engines.ml import FEATURE_LABELS
from app.main import app

H = {"X-API-Key": "k"}


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setattr(security, "_get_validator", lambda: security.APIKeyValidator(Settings(api_keys={"k"})))
    yield TestClient(app)
    app.dependency_overrides.clear()


def use_dir(directory):
    app.dependency_overrides[get_settings] = lambda: Settings(model_path=str(directory / "model.joblib"))


def test_requires_api_key(client):
    assert client.get("/api/evaluation").status_code == 401


def test_returns_both_reports_and_feature_labels(client):
    r = client.get("/api/evaluation", headers=H)
    assert r.status_code == 200
    body = r.json()
    assert body["evaluacion"]["filas_test"] > 0 and set(body["evaluacion"]["sistemas"]) >= {"ml", "combinado_url_completa"}
    assert body["modelo"]["modelo_elegido"] in body["modelo"]["test"]
    assert body["etiquetas"] == FEATURE_LABELS


def test_missing_reports_are_null_not_an_error(client, tmp_path):
    use_dir(tmp_path)
    body = client.get("/api/evaluation", headers=H).json()
    assert body["evaluacion"] is None and body["modelo"] is None and body["etiquetas"]


def test_corrupt_report_is_treated_as_missing(client, tmp_path):
    (tmp_path / "evaluation_report.json").write_text("{no es json", encoding="utf-8")
    (tmp_path / "model_report.json").write_text(json.dumps({"modelo_elegido": "random_forest"}), encoding="utf-8")
    use_dir(tmp_path)
    body = client.get("/api/evaluation", headers=H).json()
    assert body["evaluacion"] is None and body["modelo"] == {"modelo_elegido": "random_forest"}
