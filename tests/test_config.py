"""Tests de la configuración de la aplicación (app.core.config)."""
import pytest
from app.core.config import Settings


def test_settings_defaults(monkeypatch):
    """Los valores por defecto aplican cuando no hay env vars."""
    import os

    # Limpiar env para que apliquen defaults
    for k in list(os.environ):
        if k.startswith("PD_"):
            monkeypatch.delenv(k)

    s = Settings.from_env()
    assert s.app_name == "phishing-detector"
    assert s.db_path == "phishing.db"
    assert s.api_keys == {"dev-key"}
    assert s.heuristic_weight == 0.25
    assert s.ml_weight == 0.45
    assert s.network_weight == 0.20
    assert s.connector_weight == 0.10
    assert s.bands == {"seguro": 0, "sospechoso": 35, "phishing": 60}
    assert s.analysis_timeout == 4.5


def test_settings_from_env(monkeypatch):
    """Las env vars PD_ sobrescriben los defaults."""
    monkeypatch.setenv("PD_DB_PATH", "/tmp/custom.db")
    monkeypatch.setenv("PD_API_KEYS", "key-a,key-b")
    monkeypatch.setenv("PD_GSB_API_KEY", "gsb-secret")

    s = Settings.from_env()
    assert s.db_path == "/tmp/custom.db"
    assert s.api_keys == {"key-a", "key-b"}
    assert s.gsb_api_key == "gsb-secret"
    assert s.vt_api_key is None


def test_band_name_mapping():
    """El mapeo de score a banda respeta los umbrales de cada banda."""
    s = Settings()
    assert s.band_name(0) == "seguro"
    assert s.band_name(34) == "seguro"
    assert s.band_name(35) == "sospechoso"
    assert s.band_name(59) == "sospechoso"
    assert s.band_name(60) == "phishing"
    assert s.band_name(79) == "phishing"
    assert s.band_name(100) == "phishing"
