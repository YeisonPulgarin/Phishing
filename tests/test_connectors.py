"""Tests de los conectores externos (app.connectors)."""
import pytest

from app.connectors.googlesafebrowsing import GoogleSafeBrowsingConnector
from app.connectors.virustotal import VirusTotalConnector


class FakeTransport:
    """Transporte HTTP simulado para los conectores (sin red real)."""

    def __init__(self, payload=None, *, post_payload=None, get_payload=None, status=200):
        self._payload = payload
        self._post_payload = post_payload if post_payload is not None else payload
        self._get_payload = get_payload if get_payload is not None else payload
        self._status = status
        self.calls = []

    def post(self, url, *, json=None, headers=None, timeout=5):
        self.calls.append(("POST", url))
        return _FakeResp(self._status, self._post_payload)

    def get(self, url, *, headers=None, timeout=5):
        self.calls.append(("GET", url))
        return _FakeResp(self._status, self._get_payload)


class _FakeResp:
    def __init__(self, status, payload):
        self.status_code = status
        self._payload = payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self._payload


def test_gsb_disabled_without_key():
    c = GoogleSafeBrowsingConnector(api_key=None)
    result = c.check("https://evil.com")
    assert result.estado == "no_disponible"


def test_gsb_match_flags_phishing():
    fake = FakeTransport(payload={
        "matches": [{"threatType": "MALWARE", "threat.url": "https://evil.com"}]
    })
    c = GoogleSafeBrowsingConnector(api_key="key", transport=fake)
    result = c.check("https://evil.com")
    assert result.normalized_score >= 80


def test_gsb_no_match_low_score():
    fake = FakeTransport(payload={})
    c = GoogleSafeBrowsingConnector(api_key="key", transport=fake)
    result = c.check("https://good.com")
    assert result.normalized_score < 20


def test_vt_disabled_without_key():
    c = VirusTotalConnector(api_key=None)
    result = c.check("https://evil.com")
    assert result.estado == "no_disponible"


def _vt_transport(stats):
    return FakeTransport(
        post_payload={"data": {"id": "analysis-123"}},
        get_payload={"data": {"attributes": {"last_analysis_stats": stats}}},
    )


def test_vt_malicious_score():
    fake = _vt_transport({"malicious": 30, "suspicious": 5, "harmless": 3, "undetected": 2})
    c = VirusTotalConnector(api_key="key", transport=fake)
    result = c.check("https://evil.com")
    assert result.normalized_score >= 60


def test_vt_clean_score():
    fake = _vt_transport({"malicious": 0, "suspicious": 0, "harmless": 40, "undetected": 5})
    c = VirusTotalConnector(api_key="key", transport=fake)
    result = c.check("https://good.com")
    assert result.normalized_score < 40
