"""Tests de los endpoints de la API (app.api)."""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel, create_engine

from app.api.deps import get_db, get_pipeline
from app.core.pipeline import AnalysisPipeline, AnalysisReport
from app.db.models import Analysis
from app.db.repository import AnalysisRepository
from app.main import app


@pytest.fixture()
def client(monkeypatch):
    """Cliente con pipeline stub y DB en memoria, y auth desactivada."""
    import app.core.security as security
    from app.core.config import Settings

    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)

    def _db():
        from sqlmodel import Session
        with Session(engine) as s:
            yield s

    class StubPipeline:
        def analyze(self, url):
            return AnalysisReport(url=url, veredicto="sospechoso", score=45.5,
                                  confianza=0.7, motivos=["mock"], desglose={"heuristica": 50})

    monkeypatch.setattr(security, "_get_validator", lambda: security.APIKeyValidator(Settings(api_keys={"k"})))
    app.dependency_overrides[get_db] = _db
    app.dependency_overrides[get_pipeline] = lambda: StubPipeline()
    return TestClient(app)


def test_analyze_requires_auth(client):
    resp = client.post("/api/analyze", json={"url": "https://x.com"})
    assert resp.status_code == 401


def test_analyze_returns_report(client):
    resp = client.post(
        "/api/analyze", json={"url": "https://x.com"}, headers={"X-API-Key": "k"}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["veredicto"] == "sospechoso"
    assert "url" in body and "score" in body and "confianza" in body
    assert "desglose" in body


def test_analyze_invalid_url_returns_422(client):
    resp = client.post("/api/analyze", json={"url": ""}, headers={"X-API-Key": "k"})
    assert resp.status_code == 422


def test_analyze_persists_and_lists(client):
    # Analiza primero (persiste), luego lista
    client.post("/api/analyze", json={"url": "https://persisted.com"}, headers={"X-API-Key": "k"})
    resp = client.get("/api/analyses", headers={"X-API-Key": "k"})
    assert resp.status_code == 200
    items = resp.json()
    assert isinstance(items, list)
    assert any(a["url"] == "https://persisted.com" for a in items)


def test_get_single_analysis(client):
    client.post("/api/analyze", json={"url": "https://single.com"}, headers={"X-API-Key": "k"})
    items = client.get("/api/analyses", headers={"X-API-Key": "k"}).json()
    a_id = items[0]["id"]
    resp = client.get(f"/api/analyses/{a_id}", headers={"X-API-Key": "k"})
    assert resp.status_code == 200
    assert resp.json()["url"] == "https://single.com"


def test_auth_login_valid(client):
    resp = client.post("/api/auth", json={"api_key": "k"})
    assert resp.status_code == 200


def test_auth_login_invalid(client):
    resp = client.post("/api/auth", json={"api_key": "wrong"})
    assert resp.status_code == 401


def test_analyze_same_url_repeatedly_keeps_history(client):
    """Re-analizar la misma URL no falla y deja una fila de historial por análisis."""
    for _ in range(3):
        resp = client.post(
            "/api/analyze", json={"url": "https://repeat.com"}, headers={"X-API-Key": "k"}
        )
        assert resp.status_code == 200
    items = client.get("/api/analyses", headers={"X-API-Key": "k"}).json()
    rows = [a for a in items if a["url"] == "https://repeat.com"]
    assert len(rows) == 3
    assert len({a["id"] for a in rows}) == 3
