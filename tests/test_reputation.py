"""Tests de la lista de dominios de reputación (app.engines.reputation)."""
from pathlib import Path

import numpy as np
import pytest

from app.engines.base import AnalysisContext
from app.engines.ml import REPUTABLE_ML_CAP, MlEngine, load_model
from app.engines.reputation import (
    PLATFORM_DOMAINS, USER_CONTENT_HOSTS, ReputationList, parse_tranco,
)

SEED = Path("data/known_domains.txt")


def ctx(url):
    return AnalysisContext.from_url(url)


def test_registered_domain_and_its_subdomains_are_reputable():
    rep = ReputationList(["google.com", "bancolombia.com"])
    for url in ["https://google.com", "https://www.google.com", "https://accounts.google.com/signin",
                "https://mail.GOOGLE.com", "https://www.bancolombia.com/personas"]:
        assert rep.is_reputable(ctx(url)), url


def test_lookalikes_and_foreign_domains_are_not_reputable():
    rep = ReputationList(["google.com", "paypal.com"])
    for url in ["https://google.com.evil.tk", "https://evil-google.com", "https://paypa1.com",
                "https://login.paypal.com.verify-account.ru", "https://gooogle.com", "http://1.2.3.4/google.com"]:
        assert not rep.is_reputable(ctx(url)), url


def test_user_content_hosts_inside_reputable_domains_do_not_benefit():
    rep = ReputationList(["google.com", "live.com", "office.com"])
    for host in USER_CONTENT_HOSTS:
        assert not rep.is_reputable(ctx(f"https://{host}/x")), host
    assert not rep.is_reputable(ctx("https://algo.sites.google.com"))     # subdominio del host de usuario
    assert rep.is_reputable(ctx("https://accounts.google.com"))


def test_platforms_and_shorteners_are_never_reputable_even_if_listed():
    rep = ReputationList(["github.io", "web.app", "blogspot.com", "bit.ly", "tinyurl.com", "google.com"])
    for url in ["https://usuario.github.io", "https://mi-sitio.web.app", "https://x.blogspot.com", "https://bit.ly/abc"]:
        assert not rep.is_reputable(ctx(url)), url
    assert len(rep) == 1


def test_from_files_ignores_comments_blank_lines_and_missing_files(tmp_path):
    f = tmp_path / "dominios.txt"
    f.write_text("# comentario\n\nGoogle.com   # inline\n  microsoft.com \n", encoding="utf-8")
    rep = ReputationList.from_files(f, tmp_path / "no-existe.txt")
    assert "google.com" in rep and "microsoft.com" in rep and len(rep) == 2
    assert len(ReputationList.from_files(tmp_path / "nada.txt")) == 0


def test_parse_tranco_filters_platforms_and_shorteners_and_respects_top_n():
    lines = ["1,google.com", "2,github.io", "3,bit.ly", "4,facebook.com", "5,blogspot.com",
             "6,amazon.com", "basura", "7,wikipedia.org"]
    assert parse_tranco(lines, 3) == ["google.com", "facebook.com", "amazon.com"]
    assert parse_tranco(lines, 100) == ["google.com", "facebook.com", "amazon.com", "wikipedia.org"]


def test_seed_list_is_clean():
    rep = ReputationList.from_files(SEED)
    names = [l.split("#")[0].strip() for l in SEED.read_text(encoding="utf-8").splitlines()]
    names = [n for n in names if n]
    assert len(rep) == len(names) >= 100, "ningún dominio de la lista semilla fue descartado"
    assert "google.com" in rep and "bancolombia.com" in rep
    assert not (set(names) & PLATFORM_DOMAINS)
    assert all(n == n.lower() and " " not in n and "." in n for n in names)


# -- integración con el motor ML ----------------------------------------------------------

class FixedModel:
    def __init__(self, p):
        self.p = p

    def predict_proba(self, X):
        return np.array([[1 - self.p, self.p]] * len(X))


def test_ml_engine_caps_score_for_reputable_domains_and_says_so():
    rep = ReputationList(["google.com"])
    engine = MlEngine(FixedModel(0.97), rep)
    res = engine.analyze(ctx("https://accounts.google.com"))
    assert res.sub_score == REPUTABLE_ML_CAP
    assert "alta reputación" in res.motivos[0] and "97%" in res.motivos[0]


def test_ml_engine_keeps_score_for_unknown_domains():
    engine = MlEngine(FixedModel(0.97), ReputationList(["google.com"]))
    assert engine.analyze(ctx("https://accounts.google.com.evil.tk")).sub_score == pytest.approx(97)


def test_ml_engine_without_reputation_is_unchanged():
    assert MlEngine(FixedModel(0.97)).analyze(ctx("https://accounts.google.com")).sub_score == pytest.approx(97)


def test_real_model_with_seed_list_fixes_legit_subdomains_but_not_phishing():
    """El caso que motivó la lista: subdominios legítimos puntuaban como phishing."""
    model = load_model("data/model.joblib")
    plain = MlEngine(model)
    guarded = MlEngine(model, ReputationList.from_files(SEED))
    for url in ["https://accounts.google.com", "https://mail.google.com",
                "https://login.microsoftonline.com", "https://docs.github.com"]:
        assert plain.analyze(ctx(url)).sub_score > 60, f"{url}: el problema original ya no se reproduce"
        assert guarded.analyze(ctx(url)).sub_score <= REPUTABLE_ML_CAP, url
    for url in ["https://paypa1-alertas.tk", "https://login.secure-bank.evil.tk/verify"]:
        assert guarded.analyze(ctx(url)).sub_score > 60, url
