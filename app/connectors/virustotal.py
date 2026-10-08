"""Conector a VirusTotal v3 (análisis de URL).

Degrada a `no_disponible` si no hay API key o si la llamada externa falla.
"""
from __future__ import annotations

from app.connectors.base import (
    ConnectorResult,
    ConnectorStatus,
    RequestsTransport,
    Transport,
)

_UPLOAD = "https://www.virustotal.com/api/v3/urls"


class VirusTotalConnector:
    """Consulta el reporte de la URL en VirusTotal."""

    name = "virustotal"

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
                motivos=["VirusTotal sin API key"],
                estado=ConnectorStatus.NO_DISPONIBLE,
            )
        headers = {"x-apikey": self._api_key}
        try:
            upload = self._transport.post(
                f"{_UPLOAD}?url={url}", headers=headers, timeout=8
            )
            analysis_id = upload.json()["data"]["id"]
            analysis = self._transport.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers,
                timeout=8,
            )
            attrs = analysis.json()["data"]["attributes"]
            stats = attrs.get("last_analysis_stats", {}) or attrs.get("stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values())
            ratio = (malicious + suspicious) / total if total else 0.0

            score = min(100.0, malicious * 5 + ratio * 40)
            if malicious >= 5:
                score = max(score, 70.0)
            reasons = [
                f"VirusTotal: {malicious} motores lo marcan como malicioso, {suspicious} sospechoso"
            ]
            return ConnectorResult(sub_score=score, motivos=reasons)
        except Exception:
            return ConnectorResult(
                sub_score=0.0,
                motivos=["VirusTotal no disponible"],
                estado=ConnectorStatus.NO_DISPONIBLE,
            )
