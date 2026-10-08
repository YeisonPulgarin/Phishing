"""Análisis de correos electrónicos y mensajes de texto (RF1).

Dado el contenido de un correo (texto `.eml` completo o campos sueltos) o de un SMS, extrae
el dominio del remitente y las URLs, y los evalúa con el mismo pipeline que una URL
ingresada directamente (heurística + red + ML). Suma señales propias del mensaje:
palabras sospechosas en asunto y cuerpo, nombre de remitente que suplanta una marca,
Reply-To distinto del remitente, enlaces cuyo texto no coincide con su destino y fallos de
autenticación SPF/DKIM/DMARC. El análisis del cuerpo se limita a palabras clave, sin
procesamiento de lenguaje natural. No se procesan archivos adjuntos.
"""
from __future__ import annotations

import re
import unicodedata
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from email import message_from_string, policy
from email.utils import parseaddr
from typing import List, Optional

from bs4 import BeautifulSoup

from app.core.config import Settings
from app.core.pipeline import AnalysisPipeline
from app.engines.base import AnalysisContext
from app.engines.heuristic import BRANDS

MAX_URLS = 5            # enlaces analizados por mensaje (los demás se informan)
MAX_BONUS = 50.0        # tope de lo que suman las señales del mensaje

# Palabras y frases típicas de phishing/smishing (sin tildes, en minúsculas).
KEYWORDS = [
    "verifique su cuenta", "verifica tu cuenta", "cuenta suspendida", "cuenta bloqueada",
    "cuenta sera cerrada", "urgente", "accion inmediata", "ultimo aviso", "contrasena",
    "haga clic", "haz clic", "inicie sesion", "actualice sus datos", "actualiza tus datos",
    "confirme su identidad", "premio", "ganador", "paquete retenido", "pago pendiente",
    "factura adjunta", "reembolso", "clave de acceso", "tarjeta bloqueada",
    "verify your account", "account suspended", "password", "click here",
    "confirm your identity", "unusual activity", "security alert", "gift card",
    "invoice attached", "refund", "limited time",
]

_URL_RE = re.compile(r"""https?://[^\s<>"'\)\]]+""", re.IGNORECASE)
_DOMAIN_IN_TEXT_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.IGNORECASE)
_AUTH_FAIL_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*(fail|softfail|permerror|temperror)", re.IGNORECASE)


def _strip_accents(text: str) -> str:
    return "".join(c for c in unicodedata.normalize("NFKD", text) if not unicodedata.combining(c))


def _registered_domain(host_or_url: str) -> str:
    try:
        url = host_or_url if "://" in host_or_url else f"https://{host_or_url}"
        return AnalysisContext.from_url(url).registered_domain or ""
    except Exception:
        return ""


@dataclass
class ParsedMessage:
    """Contenido ya extraído de un correo o mensaje."""

    kind: str = "correo"                       # "correo" | "mensaje"
    subject: str = ""
    sender_name: str = ""
    sender_address: str = ""
    sender_domain: str = ""
    reply_to_domain: str = ""
    body: str = ""
    urls: List[str] = field(default_factory=list)
    link_mismatches: List[tuple[str, str]] = field(default_factory=list)  # (texto visible, destino)
    auth_failures: List[str] = field(default_factory=list)


def extract_urls(text: str) -> List[str]:
    """URLs http/https del texto, sin duplicados y sin puntuación final."""
    seen, out = set(), []
    for match in _URL_RE.findall(text or ""):
        url = match.rstrip(".,;:!?")
        if url not in seen:
            seen.add(url)
            out.append(url)
    return out


def parse_email(raw: str) -> ParsedMessage:
    """Interpreta un correo en formato RFC 822 (.eml). Tolera entradas mal formadas."""
    msg = message_from_string(raw or "", policy=policy.default)
    name, address = parseaddr(str(msg.get("From", "")))
    parsed = ParsedMessage(
        subject=str(msg.get("Subject", "")).strip(),
        sender_name=name.strip(),
        sender_address=address.strip().lower(),
    )
    parsed.sender_domain = address.rsplit("@", 1)[-1].strip().lower() if "@" in address else ""
    _, reply_to = parseaddr(str(msg.get("Reply-To", "")))
    parsed.reply_to_domain = reply_to.rsplit("@", 1)[-1].strip().lower() if "@" in reply_to else ""

    auth = " ".join(str(h) for h in msg.get_all("Authentication-Results", []))
    parsed.auth_failures = sorted({m.group(1).upper() for m in _AUTH_FAIL_RE.finditer(auth)})

    texts: List[str] = []
    urls: List[str] = []
    for part in msg.walk():
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue  # los adjuntos quedan fuera del alcance
        ctype = part.get_content_type()
        if ctype not in ("text/plain", "text/html"):
            continue
        try:
            content = part.get_content()
        except Exception:
            continue
        if ctype == "text/html":
            soup = BeautifulSoup(content, "lxml")
            for a in soup.find_all("a", href=True):
                href = a["href"].strip()
                if not href.lower().startswith(("http://", "https://")):
                    continue
                urls.append(href)
                shown = _DOMAIN_IN_TEXT_RE.search(a.get_text(" ", strip=True))
                if shown and _registered_domain(shown.group(0)) != _registered_domain(href):
                    parsed.link_mismatches.append((shown.group(0).lower(), href))
            texts.append(soup.get_text(" ", strip=True))
        else:
            texts.append(content)
            urls.extend(extract_urls(content))

    parsed.body = "\n".join(texts).strip()
    parsed.urls = list(dict.fromkeys(urls))
    return parsed


def parse_fields(subject: str = "", sender: str = "", body: str = "") -> ParsedMessage:
    """Arma el mensaje a partir de campos pegados a mano (asunto, remitente, cuerpo)."""
    name, address = parseaddr(sender or "")
    parsed = ParsedMessage(subject=(subject or "").strip(), sender_name=name.strip(),
                           sender_address=address.strip().lower(), body=(body or "").strip())
    if "@" in address:
        parsed.sender_domain = address.rsplit("@", 1)[-1].strip().lower()
    parsed.urls = extract_urls(f"{subject}\n{body}")
    return parsed


def parse_text_message(text: str) -> ParsedMessage:
    """Mensaje de texto (SMS, chat): solo cuerpo y enlaces."""
    parsed = ParsedMessage(kind="mensaje", body=(text or "").strip())
    parsed.urls = extract_urls(parsed.body)
    return parsed


def find_keywords(*texts: str) -> List[str]:
    haystack = _strip_accents(" ".join(t for t in texts if t)).lower()
    return [k for k in KEYWORDS if k in haystack]


class EmailAnalyzer:
    """Evalúa un `ParsedMessage` reutilizando el pipeline de URLs."""

    def __init__(self, pipeline: AnalysisPipeline, settings: Settings) -> None:
        self._pipeline = pipeline
        self._settings = settings

    def analyze(self, msg: ParsedMessage) -> dict:
        urls = msg.urls[:MAX_URLS]
        targets = {f"url:{u}": u for u in urls}
        if msg.sender_domain:
            targets["remitente"] = f"https://{msg.sender_domain}"
        reports = self._run_parallel(targets)

        url_results = []
        for u in urls:
            r = reports.get(f"url:{u}")
            url_results.append(self._summary(u, r))
        sender_report = reports.get("remitente")

        signals, bonus = self._message_signals(msg)
        url_scores = [r.score for u in urls if (r := reports.get(f"url:{u}")) is not None]
        sender_score = sender_report.score if sender_report is not None else 0.0
        base = max(url_scores + [sender_score * 0.8], default=0.0)
        score = round(min(100.0, base + min(bonus, MAX_BONUS)), 1)

        analyzed = len(url_scores) + (1 if sender_report is not None else 0)
        confianza = round(min(1.0, 0.3 + 0.15 * analyzed + (0.1 if signals else 0.0)), 2)

        reasons = list(signals)
        for item in url_results:
            if item["score"] is not None and item["score"] >= self._settings.bands["sospechoso"]:
                reasons.append(f"Enlace {item['url']}: " + "; ".join(item["motivos"][:3]))
        if sender_report is not None and sender_report.score >= self._settings.bands["sospechoso"]:
            reasons.append(f"Dominio del remitente {msg.sender_domain}: "
                           + "; ".join(sender_report.motivos[:3]))
        if len(msg.urls) > MAX_URLS:
            reasons.append(f"El mensaje trae {len(msg.urls)} enlaces; se analizaron los primeros {MAX_URLS}")
        if not reasons:
            reasons.append("No se encontraron señales de phishing en el mensaje")

        return {
            "tipo": msg.kind,
            "asunto": msg.subject,
            "extracto": msg.body[:120],
            "remitente": {"nombre": msg.sender_name, "direccion": msg.sender_address,
                          "dominio": msg.sender_domain},
            "veredicto": self._settings.band_name(int(round(score))),
            "score": score,
            "confianza": confianza,
            "motivos": reasons,
            "enlaces": url_results,
            "dominio_remitente": self._summary(msg.sender_domain, sender_report) if msg.sender_domain else None,
            "desglose": {"enlaces": round(max(url_scores, default=0.0), 1),
                         "remitente": round(sender_score, 1),
                         "senales_mensaje": round(min(bonus, MAX_BONUS), 1)},
        }

    # -- helpers -----------------------------------------------------------------------

    def _run_parallel(self, targets: dict):
        """Analiza todos los destinos a la vez, con el mismo tope de tiempo que una URL."""
        if not targets:
            return {}
        pool = ThreadPoolExecutor(max_workers=len(targets))
        futures = {key: pool.submit(self._pipeline.analyze, url) for key, url in targets.items()}
        wait(list(futures.values()), timeout=self._settings.analysis_timeout + 0.5)
        pool.shutdown(wait=False, cancel_futures=True)
        out = {}
        for key, fut in futures.items():
            if fut.done() and fut.exception() is None:
                out[key] = fut.result()
        return out

    @staticmethod
    def _summary(target: str, report) -> dict:
        if report is None:
            return {"url": target, "veredicto": None, "score": None,
                    "motivos": ["No se pudo analizar a tiempo"]}
        return {"url": target, "veredicto": report.veredicto, "score": report.score,
                "motivos": report.motivos}

    @staticmethod
    def _message_signals(msg: ParsedMessage) -> tuple[List[str], float]:
        signals: List[str] = []
        bonus = 0.0

        words = find_keywords(msg.subject, msg.body)
        if words:
            bonus += min(20.0, 5.0 * len(words))
            shown = ", ".join(f"«{w}»" for w in words[:5])
            signals.append(f"Usa lenguaje típico de phishing: {shown}")

        name = _strip_accents(msg.sender_name).lower().replace(" ", "")
        for brand in BRANDS:
            if brand in name and brand not in msg.sender_domain.replace("-", ""):
                bonus += 25.0
                signals.append(f"El nombre del remitente dice ser {brand.capitalize()}, "
                               f"pero el correo viene de {msg.sender_domain or 'un dominio desconocido'}")
                break

        sender_reg = _registered_domain(msg.sender_domain) if msg.sender_domain else ""
        reply_reg = _registered_domain(msg.reply_to_domain) if msg.reply_to_domain else ""
        if reply_reg and sender_reg and reply_reg != sender_reg:
            bonus += 15.0
            signals.append(f"Las respuestas irían a otro dominio ({msg.reply_to_domain}), "
                           f"distinto del remitente ({msg.sender_domain})")

        if msg.link_mismatches:
            bonus += 25.0
            shown, target = msg.link_mismatches[0]
            signals.append(f"Un enlace muestra «{shown}» pero lleva a otro sitio ({target})")

        if msg.auth_failures:
            bonus += 20.0
            signals.append("El servidor de correo reportó fallos de autenticación: "
                           + ", ".join(msg.auth_failures))
        return signals, bonus
