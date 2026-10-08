"""Tests del análisis de correos y mensajes (app.core.email_analysis)."""
import time

import pytest

from app.core.config import Settings
from app.core.email_analysis import (
    EmailAnalyzer, extract_urls, find_keywords, parse_email, parse_fields, parse_text_message,
)
from app.core.pipeline import AnalysisReport

PHISHING_EML = """\
From: "PayPal Seguridad" <soporte@paypa1-alertas.tk>
Reply-To: cobros@otro-dominio.ru
To: victima@example.com
Subject: URGENTE: verifique su cuenta
Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=paypa1-alertas.tk; dkim=none
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="XX"

--XX
Content-Type: multipart/alternative; boundary="YY"

--YY
Content-Type: text/plain; charset=utf-8

Su cuenta sera suspendida. Haga clic aqui: http://paypa1-alertas.tk/login.
--YY
Content-Type: text/html; charset=utf-8

<html><body><p>Ingrese a <a href="http://paypa1-alertas.tk/login">www.paypal.com</a> ahora.</p>
<a href="https://bit.ly/3abcde">Ver detalle</a></body></html>
--YY--
--XX
Content-Type: application/pdf
Content-Disposition: attachment; filename="factura.pdf"

http://no-debe-analizarse.example/adjunto
--XX--
"""

BENIGN_EML = """\
From: Ana Perez <ana@universidad.edu.co>
To: yo@example.com
Subject: Reunión del lunes
Content-Type: text/plain; charset=utf-8

Hola, te confirmo la reunión del lunes a las 10. Saludos.
"""


class FakePipeline:
    """Pipeline falso: puntaje según el dominio, sin red."""

    def __init__(self, scores=None, delay=0.0):
        self.scores = scores or {}
        self.delay = delay
        self.calls = []

    def analyze(self, url):
        self.calls.append(url)
        time.sleep(self.delay)
        score = next((v for k, v in self.scores.items() if k in url), 5.0)
        band = "phishing" if score >= 60 else "sospechoso" if score >= 35 else "seguro"
        return AnalysisReport(url=url, veredicto=band, score=score, confianza=0.8,
                              motivos=[f"motivo de {url}"], desglose={})


def analyzer(pipeline=None, **settings):
    return EmailAnalyzer(pipeline or FakePipeline(), Settings(**settings))


# -- parser ---------------------------------------------------------------------------

def test_parse_email_extracts_sender_reply_to_and_auth():
    m = parse_email(PHISHING_EML)
    assert m.sender_name == "PayPal Seguridad"
    assert m.sender_domain == "paypa1-alertas.tk"
    assert m.reply_to_domain == "otro-dominio.ru"
    assert m.subject == "URGENTE: verifique su cuenta"
    assert m.auth_failures == ["SPF"]


def test_parse_email_collects_urls_from_text_and_html_without_attachments():
    m = parse_email(PHISHING_EML)
    assert "http://paypa1-alertas.tk/login" in m.urls          # sin el punto final
    assert "https://bit.ly/3abcde" in m.urls                   # solo estaba en el HTML
    assert not any("no-debe-analizarse" in u for u in m.urls)  # adjuntos fuera de alcance
    assert len(m.urls) == len(set(m.urls))


def test_parse_email_detects_link_text_mismatch():
    m = parse_email(PHISHING_EML)
    assert m.link_mismatches == [("www.paypal.com", "http://paypa1-alertas.tk/login")]


def test_parse_email_tolerates_garbage():
    m = parse_email("esto no es un correo \x00\x01 ???")
    assert m.urls == [] and m.sender_domain == ""
    assert parse_email("").sender_domain == ""


def test_extract_urls_strips_punctuation_and_dedupes():
    text = "Entre a https://a.com/x), o https://a.com/x. y también http://b.org/y!"
    assert extract_urls(text) == ["https://a.com/x", "http://b.org/y"]


def test_find_keywords_ignores_accents_and_case():
    assert "verifique su cuenta" in find_keywords("Por favor VERIFIQUE su cuenta")
    assert "contrasena" in find_keywords("Su contraseña expiró")
    assert find_keywords("Hola, nos vemos en la reunión") == []


def test_parse_fields_and_text_message():
    m = parse_fields("Aviso", "Banco <aviso@banco-falso.com>", "Entre a http://banco-falso.com/x")
    assert m.sender_domain == "banco-falso.com" and m.urls == ["http://banco-falso.com/x"]
    sms = parse_text_message("Tu paquete esta retenido: https://bit.ly/abc123")
    assert sms.kind == "mensaje" and sms.urls == ["https://bit.ly/abc123"]


# -- analizador -----------------------------------------------------------------------

def test_phishing_email_is_classified_as_phishing_with_reasons():
    res = analyzer(FakePipeline({"paypa1": 70})).analyze(parse_email(PHISHING_EML))
    assert res["veredicto"] == "phishing" and res["score"] >= 60
    text = " ".join(res["motivos"])
    assert "dice ser Paypal" in text             # nombre de remitente suplantado
    assert "otro dominio" in text                # Reply-To distinto
    assert "muestra «www.paypal.com»" in text    # texto del enlace vs destino
    assert "SPF" in text                         # fallo de autenticación
    assert "phishing" in text.lower()


def test_benign_email_is_safe():
    res = analyzer().analyze(parse_email(BENIGN_EML))
    assert res["veredicto"] == "seguro"
    assert res["motivos"] == ["No se encontraron señales de phishing en el mensaje"]
    assert res["enlaces"] == [] and res["dominio_remitente"]["url"] == "universidad.edu.co"


def test_sender_domain_goes_through_the_same_pipeline():
    pipe = FakePipeline()
    analyzer(pipe).analyze(parse_email(PHISHING_EML))
    assert "https://paypa1-alertas.tk" in pipe.calls          # dominio del remitente
    assert "http://paypa1-alertas.tk/login" in pipe.calls     # enlaces del cuerpo


def test_only_first_links_are_analyzed():
    body = " ".join(f"http://sitio{i}.com/x" for i in range(9))
    pipe = FakePipeline()
    res = analyzer(pipe).analyze(parse_fields("", "", body))
    assert len(res["enlaces"]) == 5 and len(pipe.calls) == 5
    assert any("9 enlaces" in m for m in res["motivos"])


def test_slow_pipeline_is_skipped_within_time_limit():
    msg = parse_fields("", "", "http://lento.com/x")
    t0 = time.monotonic()
    res = analyzer(FakePipeline(delay=1.5), analysis_timeout=0.2).analyze(msg)
    assert time.monotonic() - t0 < 1.0
    assert res["enlaces"][0]["score"] is None
    assert res["enlaces"][0]["motivos"] == ["No se pudo analizar a tiempo"]


def test_sms_with_shortener_and_keywords_is_suspicious():
    res = analyzer(FakePipeline({"bit.ly": 40})).analyze(
        parse_text_message("URGENTE: su paquete esta retenido, haga clic https://bit.ly/abc123"))
    assert res["tipo"] == "mensaje" and res["veredicto"] in {"sospechoso", "phishing"}
    assert res["dominio_remitente"] is None


def test_signals_are_capped():
    res = analyzer(FakePipeline({"paypa1": 99})).analyze(parse_email(PHISHING_EML))
    assert res["score"] <= 100 and res["desglose"]["senales_mensaje"] <= 50


def test_real_brand_sender_is_not_flagged_as_impersonation():
    msg = parse_fields("Recibo", "PayPal <service@paypal.com>", "Gracias por su compra.")
    res = analyzer().analyze(msg)
    assert not any("dice ser" in m for m in res["motivos"])
    assert res["veredicto"] == "seguro"
