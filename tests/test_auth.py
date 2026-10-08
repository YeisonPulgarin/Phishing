"""Tests de la autenticación por API key (app.core.security)."""
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.core.security import APIKeyValidator, require_api_key


def test_validator_accepts_valid_key():
    v = APIKeyValidator(Settings(api_keys={"secret-1", "secret-2"}))
    assert v.is_valid("secret-1")
    assert v.is_valid("secret-2")


def test_validator_rejects_unknown_key():
    v = APIKeyValidator(Settings(api_keys={"secret-1"}))
    assert not v.is_valid("wrong-key")
    assert not v.is_valid("")


def test_endpoint_requires_api_key(monkeypatch):
    settings = Settings(api_keys={"my-key"})
    import app.core.security as security

    monkeypatch.setattr(security, "_get_validator", lambda: APIKeyValidator(settings))

    app = FastAPI()

    @app.get("/protected")
    def protected(_=Depends(require_api_key)):
        return {"ok": True}

    client = TestClient(app)

    # Sin key -> 401
    assert client.get("/protected").status_code == 401
    # Key inválida -> 401
    assert client.get("/protected", headers={"X-API-Key": "bad"}).status_code == 401
    # Key válida -> 200
    resp = client.get("/protected", headers={"X-API-Key": "my-key"})
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}
