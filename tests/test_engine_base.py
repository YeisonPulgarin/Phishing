"""Tests del contrato base de motores (app.engines.base)."""
import pytest

from app.engines.base import AnalysisContext, Engine, EngineResult


def test_engine_result_defaults():
    r = EngineResult(sub_score=50, motivos=["a"])
    assert r.estado == "ok"
    assert r.normalized_score == 50


def test_engine_result_clamped_to_0_100():
    assert EngineResult(sub_score=-5).normalized_score == 0
    assert EngineResult(sub_score=150).normalized_score == 100


def test_engine_result_error_state():
    r = EngineResult(sub_score=0, motivos=[], estado="error")
    assert r.estado == "error"


def test_analysis_context_url_parts():
    ctx = AnalysisContext.from_url("https://user@secure.paypal.com.evil.com/login")
    assert ctx.host == "secure.paypal.com.evil.com"
    assert ctx.scheme == "https"
    assert ctx.path == "/login"


def test_engine_protocol_runtime_checkable():
    """Engine es un protocolo estructural: una clase con analyze y name lo cumple."""
    class Concrete:
        name = "x"

        def analyze(self, ctx):
            return EngineResult(sub_score=0)

    assert isinstance(Concrete(), Engine)
