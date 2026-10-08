"""Conector a Google Safe Browsing v4 (threatMatches:find).

Degrada a `no_disponible` si no hay API key o si la llamada externa falla.
"""
from __future__ import annotations

from app.connectors.base import (
    ConnectorResult,
    ConnectorStatus,
    RequestsTransport,
    Transport,
)

_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


class GoogleSafeBrowsingConnector:
    """Chequea reputación de la URL contra Google Safe Browsing."""

    name = "google_safe_browsing"

    def __init__(self, api_key: str | None, transport: Transport | None = None) -> None:
        self._api_key = api_key
        self._transport: Transport = transport or RequestsTransport()

    @property
    def enabled(self) -> bool:
        return bool(self._api_key)

    def check(self, url: str) -> ConnectorResult:
        if not self.enabled:
            return ConnectorResult(
                sub_score=0.0,
                motivos=["Google Safe Browsing sin API key"],
                estado=ConnectorStatus.NO_DISPONIBLE,
            )
        try:
            payload = {
                "client": {"clientId": "phishing-detector", "clientVersion": "1.0.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}],
                },
            }
            # GSB recibe la API key como query param.
            resp = self._transport.post(
                f"{_ENDPOINT}?key={self._api_key}", json=payload, timeout=8
            )
            matches = resp.json().get("matches", [])
            if matches:
                types = ", ".join(m.get("threatType", "?") for m in matches)
                return ConnectorResult(
                    sub_score=90.0,
                    motivos=[f"Google Safe Browsing lo marca como amenaza: {types}"],
                )
            return ConnectorResult(sub_score=5.0, motivos=["No registrado por Google Safe Browsing"])
        except Exception:
            return ConnectorResult(
                sub_score=0.0,
                motivos=["Google Safe Browsing no disponible"],
                estado=ConnectorStatus.NO_DISPONIBLE,
            )
