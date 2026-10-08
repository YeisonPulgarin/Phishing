"""Tests de los endpoints /api/analyze-email, /api/analyze-message y /api/explain."""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

from app.api.deps import get_db, get_pipeline
from app.core.config import Settings
from app.core.pipeline import AnalysisReport
from app.engines.ml import load_model
from app.main import app

H = {"X-API-Key": "k"}
EML = ("From: PayPal <soporte@paypa1-alertas.tk>\nSubject: Verifique su cuenta\n"
       "Content-Type: text/plain\n\nHaga clic: http://paypa1-alertas.tk/login")


class FakePipeline:
    ml_model = None

    def analyze(self, url):
        score = 80.0 if "paypa1" in url else 10.0
        return AnalysisReport(url=url, veredicto="phishing" if score >= 60 else "seguro",
                              score=score, confianza=0.8, motivos=["mock"], desglose={})


class RealModelPipeline(FakePipeline):
    ml_model = load_model("data/model.joblib")


@pytest.fixture()
def make_client(monkeypatch):
    import app.core.security as security

    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(engine)

    def _db():
        with Session(engine) as s:
            yield s

    monkeypatch.setattr(security, "_get_validator",
                        lambda: security.APIKeyValidator(Settings(api_keys={"k"})))
    app.dependency_overrides[get_db] = _db

    def _make(pipeline_cls=FakePipeline):
        app.dependency_overrides[get_pipeline] = lambda: pipeline_cls()
        return TestClient(app)

    yield _make
    app.dependency_overrides.clear()


def test_endpoints_require_auth(make_client):
    c = make_client()
    for path, body in [("/api/analyze-email", {"raw": EML}), ("/api/analyze-message", {"text": "hola"}),
                       ("/api/explain", {"url": "https://x.com"})]:
        assert c.post(path, json=body).status_code == 401


def test_analyze_email_from_raw_eml_and_saved_in_history(make_client):
    c = make_client()
    r = c.post("/api/analyze-email", json={"raw": EML}, headers=H)
    assert r.status_code == 200
    body = r.json()
    assert body["tipo"] == "correo" and body["veredicto"] == "phishing"
    assert body["remitente"]["dominio"] == "paypa1-alertas.tk"
    assert body["enlaces"][0]["url"] == "http://paypa1-alertas.tk/login"
    history = c.get("/api/analyses", headers=H).json()
    assert history[0]["id"] == body["id"] and history[0]["url"].startswith("correo: Verifique su cuenta")


def test_analyze_email_from_pasted_fields(make_client):
    r = make_client().post("/api/analyze-email", headers=H, json={
        "subject": "Hola", "sender": "Ana <ana@universidad.edu.co>", "body": "Nos vemos mañana."})
    assert r.status_code == 200 and r.json()["veredicto"] == "seguro"


def test_analyze_email_rejects_empty_input(make_client):
    c = make_client()
    assert c.post("/api/analyze-email", json={}, headers=H).status_code == 422
    assert c.post("/api/analyze-email", json={"raw": "   ", "body": " "}, headers=H).status_code == 422
    assert c.post("/api/analyze-email", json={"body": "x" * 200_001}, headers=H).status_code == 422


def test_analyze_email_with_garbage_does_not_crash(make_client):
    r = make_client().post("/api/analyze-email", json={"raw": "\x00\x01 basura ???"}, headers=H)
    assert r.status_code == 200 and r.json()["veredicto"] == "seguro"


def test_analyze_message(make_client):
    c = make_client()
    r = c.post("/api/analyze-message", headers=H,
               json={"text": "Su cuenta sera bloqueada. Entre a http://paypa1-alertas.tk/x"})
    assert r.status_code == 200 and r.json()["tipo"] == "mensaje" and r.json()["veredicto"] == "phishing"
    assert c.post("/api/analyze-message", json={"text": "  "}, headers=H).status_code == 422
    assert c.post("/api/analyze-message", json={"text": "x" * 5001}, headers=H).status_code == 422


def test_explain_endpoint_with_real_model(make_client):
    r = make_client(RealModelPipeline).post("/api/explain", json={"url": "https://login.secure-bank.evil.tk/verify"}, headers=H)
    assert r.status_code == 200
    body = r.json()
    assert body["contribuciones"] and 0 <= body["probabilidad_phishing"] <= 1


def test_explain_without_model_is_503(make_client):
    r = make_client().post("/api/explain", json={"url": "https://example.com"}, headers=H)
    assert r.status_code == 503
