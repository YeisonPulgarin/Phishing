"""Tests del pipeline de análisis (app.core.pipeline)."""
from app.core.config import Settings
from app.core.pipeline import AnalysisPipeline, AnalysisReport
from app.engines.base import AnalysisContext, EngineResult, EngineStatus
from app.engines.ml import MlEngine


class StubEngine:
    """Motor que devuelve un sub-score fijo."""

    def __init__(self, name, score, estado=EngineStatus.OK):
        self.name = name
        self._score = score
        self._estado = estado

    def analyze(self, ctx):
        return EngineResult(sub_score=self._score, motivos=[f"motor {self.name} analizado"], estado=self._estado)


class StubConnector:
    def __init__(self, name, score, enabled=True):
        self.name = name
        self._score = score
        self.enabled = enabled

    def check(self, url):
        from app.connectors.base import ConnectorResult
        return ConnectorResult(sub_score=self._score, motivos=[f"conector {self.name}"])


def _pipeline(**sub_scores):
    engines = []
    conns = []
    # Sub-scores por nombre de motor/conector
    for k, v in sub_scores.items():
        if k in ("heuristica", "red", "ml"):
            engines.append(StubEngine(k, v))
        else:
            conns.append(StubConnector(k, v))
    settings = Settings()
    return AnalysisPipeline(settings, engines=engines, connectors=conns)


def test_report_structure_complete():
    pipe = _pipeline(heuristica=30, red=20, ml=40)
    rep: AnalysisReport = pipe.analyze("https://www.example.com/")
    assert rep.url
    assert rep.veredicto in {"seguro", "sospechoso", "phishing"}
    assert 0 <= rep.score <= 100
    assert 0 <= rep.confianza <= 1
    assert rep.desglose is not None
    assert "heuristica" in rep.desglose


def test_pipeline_tolerates_disabled_connectors():
    # Un conector deshabilitado o sin key no rompe el pipeline.
    pipe = AnalysisPipeline(
        Settings(),
        engines=[StubEngine("heuristica", 90, EngineStatus.OK)],
        connectors=[StubConnector("google_safe_browsing", 5, enabled=False)],
    )
    rep = pipe.analyze("https://evil-ish.example.com")
    assert rep.veredicto in {"sospechoso", "phishing"}


def test_pipeline_error_engine_does_not_break():
    # Un motor en estado error se omite; el análisis continúa con los demás.
    pipe = AnalysisPipeline(
        Settings(),
        engines=[
            StubEngine("heuristica", 90, EngineStatus.OK),
            StubEngine("red", 0, EngineStatus.ERROR),
        ],
        connectors=[],
    )
    rep = pipe.analyze("https://x.com")
    assert rep.score > 0


def test_pipeline_ml_is_optional():
    # Sin motores disponibles no explota; devuelve un reporte por defecto.
    pipe = AnalysisPipeline(Settings(), engines=[], connectors=[])
    rep = pipe.analyze("https://x.com")
    assert rep.veredicto in {"seguro", "sospechoso", "phishing"}


def test_pipeline_skips_slow_engine_within_timeout():
    """Un motor lento se omite al vencer el tiempo máximo (RNF2) y se informa."""
    import time

    class SlowEngine:
        name = "red"

        def analyze(self, ctx):
            time.sleep(1.2)
            return EngineResult(sub_score=90, motivos=["nunca llega"])

    pipe = AnalysisPipeline(
        Settings(analysis_timeout=0.3),
        engines=[StubEngine("heuristica", 40), SlowEngine()],
        connectors=[],
    )
    t0 = time.monotonic()
    rep = pipe.analyze("https://www.example.com")
    elapsed = time.monotonic() - t0

    assert elapsed < 1.0
    assert "red" not in rep.desglose and "heuristica" in rep.desglose
    assert any("no respondió a tiempo" in m for m in rep.motivos)


def test_pipeline_reports_engine_unavailable_reason():
    pipe = AnalysisPipeline(
        Settings(),
        engines=[StubEngine("heuristica", 20), StubEngine("red", 0, EngineStatus.NO_DISPONIBLE)],
        connectors=[],
    )
    rep = pipe.analyze("https://x.com")
    assert "red" not in rep.desglose
    assert any("motor red analizado" in m for m in rep.motivos)
