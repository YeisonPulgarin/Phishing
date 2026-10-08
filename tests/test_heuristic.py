"""Tests del motor heurístico de URLs (app.engines.heuristic)."""
import pytest

from app.engines.base import AnalysisContext
from app.engines.heuristic import HeuristicEngine


@pytest.fixture()
def engine():
    return HeuristicEngine()


def _score(engine, url) -> float:
    return engine.analyze(AnalysisContext.from_url(url)).normalized_score


def test_plain_https_url_low_score(engine):
    s = _score(engine, "https://www.google.com")
    assert s < 35


def test_official_brand_domain_not_impersonation(engine):
    # El dominio oficial de una marca no debe marcar impersonación.
    result = engine.analyze(AnalysisContext.from_url("https://www.paypal.com/login"))
    assert not any("imita" in m or "parecerse" in m for m in result.motivos)
    assert result.normalized_score < 35


def test_subdomain_squatting_is_impersonation(engine):
    # 'paypal' como subdominio de un dominio ajeno SÍ es impersonación.
    result = engine.analyze(
        AnalysisContext.from_url("https://secure.paypal.com.evil.tk/login")
    )
    assert any("parecerse a 'paypal'" in m for m in result.motivos)


def test_ip_as_host_high_score(engine):
    s = _score(engine, "http://192.168.1.1/login")
    assert s >= 60


def test_at_symbol_raises_score(engine):
    # El userinfo @ oculta el host real
    s = _score(engine, "https://www.paypal.com@evil.tk/login")
    assert s >= 50


def test_no_https_adds_score(engine):
    http = _score(engine, "http://example.com")
    https = _score(engine, "https://example.com")
    assert http >= https


def test_credential_keywords_raise_score(engine):
    with_login = _score(engine, "https://example.com/verify/account/login")
    normal = _score(engine, "https://example.com/home")
    assert with_login > normal


def test_suspicious_tld(engine):
    s = _score(engine, "https://freegift.tk/claim")
    assert s >= 35


def test_typosquat_brand(engine):
    # "paypal" con sustitucion + dominio que parece paypal
    s = _score(engine, "https://paypa1-secure.com/login")
    assert s >= 40


def test_excessive_subdomains(engine):
    s = _score(engine, "https://a.b.c.d.example.com/login")
    assert s > 0


def test_subdomain_squatting(engine):
    # dominio legitimo de marca usado como subdominio + TLD raro
    s = _score(engine, "https://secure-pays.paypal.verify.tk/login")
    assert s >= 60


def test_dashes_in_domain(engine):
    s = _score(engine, "https://paypal-secure-verify-account.com")
    assert s > 0


def test_url_shortener_is_flagged():
    from app.engines.base import AnalysisContext
    from app.engines.heuristic import HeuristicEngine

    result = HeuristicEngine().analyze(AnalysisContext.from_url("https://bit.ly/3xYz9"))
    assert result.normalized_score >= 35
    assert any("acortador" in m for m in result.motivos)


def test_shortener_name_in_path_is_not_flagged():
    from app.engines.base import AnalysisContext
    from app.engines.heuristic import HeuristicEngine

    result = HeuristicEngine().analyze(AnalysisContext.from_url("https://www.example.com/bit.ly"))
    assert not any("acortador" in m for m in result.motivos)
