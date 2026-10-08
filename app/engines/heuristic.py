"""Motor heurístico de URLs.

Analiza la estructura léxica de la URL (sin red ni ML) y produce un sub-score 0-100
basado en señales ponderadas, más overrides que fuerzan bandas altas ante combinaciones
críticas (brand impersonation + keyword de credenciales).
"""
from __future__ import annotations

import ipaddress
from typing import Dict, List, Set

from rapidfuzz import fuzz

from app.engines.base import AnalysisContext, EngineResult

# Lista curada de TLD abusivos.
SUSPICIOUS_TLDS: Set[str] = {
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "shop", "ink",
    "vip", "click", "buzz", "cc", "icu", "club", "work", "live", "loan",
}

# Acortadores de URL conocidos: ocultan el destino real del enlace.
URL_SHORTENERS: Set[str] = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "t.ly",
    "lnkd.in", "s.id", "bl.ink", "v.gd", "adf.ly", "bit.do", "trib.al",
    "soo.gd", "shorte.st", "qr.ae", "tr.ee", "link.tl", "x.co",
}

# Lista curada de marcas para typosquatting / impersonación.
BRANDS: List[str] = [
    "google", "paypal", "microsoft", "apple", "amazon", "facebook",
    "netflix", "bankofamerica", "wellsfargo", "hsbc", "github", "dropbox",
    "instagram", "whatsapp", "telegram", "outlook",
]

# Keywords de credenciales en path/query.
CREDENTIAL_WORDS: Set[str] = {
    "login", "verify", "secure", "account", "password", "banking",
    "webscr", "update", "signin", "bill", "invoice", "confirm",
    "token", "auth", "wallet", "benefit",
}

# Leet sustituciones para normalizar typosquat.
_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "4": "a", "@": "a"})


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


class HeuristicEngine:
    """Reglas heurísticas sobre la cadena de la URL."""

    name = "heuristica"

    def analyze(self, ctx: AnalysisContext) -> EngineResult:
        signals: Dict[str, float] = {}
        reasons: List[str] = []

        self._detect_ip(ctx, signals, reasons)
        self._detect_at(ctx, signals, reasons)
        self._detect_https(ctx, signals, reasons)
        self._detect_tld(ctx, signals, reasons)
        self._detect_subdomains(ctx, signals, reasons)
        self._detect_dashes(ctx, signals, reasons)
        self._detect_credential_keywords(ctx, signals, reasons)
        self._detect_typosquat(ctx, signals, reasons)
        self._detect_shortener(ctx, signals, reasons)

        sub_score = sum(signals.values())
        normalized = max(0.0, min(100.0, sub_score))

        # Floor escalation: ciertas señales individuales elevan por sí solas el score.
        floors = 0.0
        if signals.get("ip_host"):
            floors = max(floors, 60.0)  # host IP cruda es señal MAY fuerte
        if signals.get("at"):
            floors = max(floors, 45.0)  # ocultamiento de host con '@'
        if signals.get("suspicious_tld"):
            floors = max(floors, 35.0)  # TLD abusivo conocido
        if signals.get("typosquat"):
            floors = max(floors, 40.0)  # dominio que imita marca
        if signals.get("shortener"):
            floors = max(floors, 35.0)  # destino oculto: como mínimo, sospechoso
        normalized = max(normalized, floors)

        # Override: impersonación de marca + pedido de credenciales.
        if signals.get("brand_impersonation") and signals.get("credential"):
            normalized = max(normalized, 60.0)
            reasons.append("Dominio que imita una marca legítima y pide credenciales")

        if not reasons:
            reasons.append("URL sin señales heurísticas destacables")

        return EngineResult(sub_score=normalized, motivos=reasons)

    def _detect_ip(self, ctx, signals, reasons):
        if _is_ip(ctx.host):
            signals["ip_host"] = 40
            reasons.append("El host es una dirección IP, no un dominio")

    def _detect_at(self, ctx, signals, reasons):
        if ctx.username:
            signals["at"] = 30
            reasons.append(f"La URL oculta el host real tras '{ctx.username}@'")

    def _detect_https(self, ctx, signals, reasons):
        if ctx.scheme != "https":
            signals["no_https"] = 7
            reasons.append("La URL no usa HTTPS")

    def _detect_tld(self, ctx, signals, reasons):
        tld = (ctx.suffix or "").lower()
        if tld in SUSPICIOUS_TLDS:
            signals["suspicious_tld"] = 10
            reasons.append(f"El TLD '{tld}' se asocia a abuso")

    def _detect_subdomains(self, ctx, signals, reasons):
        sub = ctx.subdomain
        domain = (ctx.registered_domain or "").lower()
        if sub:
            # impersonación: una marca aparece como SUBDOMINIO de un dominio ajeno
            # (p.ej. secure.paypal.com.evil.com), no en el dominio oficial.
            sub_parts = [p for p in sub.lower().split(".") if p]
            for part in sub_parts:
                if part in BRANDS and part not in domain:
                    signals["brand_impersonation"] = 22
                    reasons.append(f"El host intenta parecerse a '{part}'")
                    break
            # exceso de subdominios, como señal adicional.
            levels = len(sub_parts)
            if levels >= 3 and "brand_impersonation" not in signals:
                signals["subdomains"] = 12
                reasons.append("Cantidad de subdominios inusualmente alta")

    def _detect_dashes(self, ctx, signals, reasons):
        domain = ctx.registered_domain
        if domain:
            n = domain.count("-")
            if n >= 2:
                signals["dashes"] = 8
                reasons.append("Guiones abundantes en el dominio")

    def _detect_shortener(self, ctx, signals, reasons):
        domain = (ctx.registered_domain or ctx.host or "").lower()
        if domain in URL_SHORTENERS:
            signals["shortener"] = 30
            reasons.append(f"Usa un acortador de URL ({domain}): el destino real queda oculto")

    def _detect_credential_keywords(self, ctx, signals, reasons):
        text_flat = (ctx.path.lower() + ctx.query.lower())
        hits = [w for w in CREDENTIAL_WORDS if w in text_flat]
        if hits:
            signals["credential"] = 10
            reasons.append(f"Pide credenciales o acciones sensibles (palabras: {', '.join(hits)})")

    def _detect_typosquat(self, ctx, signals, reasons):
        domain = (ctx.registered_domain or "").lower().split(".")[0]
        if not domain:
            return
        # Normaliza leet y quita separadores para comparar de forma robusta.
        cleaned = domain.replace("-", "").replace(".", "").translate(_LEET)
        for brand in BRANDS:
            if cleaned == brand:
                return  # es el dominio oficial
            ratio = fuzz.ratio(cleaned, brand)
            partial = fuzz.partial_ratio(cleaned, brand)
            if brand in cleaned or ratio >= 80 or partial >= 85:
                signals["typosquat"] = 30
                reasons.append(f"Dominio que se asemeja a la marca '{brand}'")
                return
