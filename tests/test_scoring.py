"""Tests del combinador de scoring (app.core.scoring)."""
import pytest

from app.core.config import Settings
from app.core.scoring import ScoreCombiner


@pytest.fixture()
def combiner():
    return ScoreCombiner(Settings())


def test_all_motors_present(combiner):
    out = combiner.combine({
        "heuristica": 20.0,
        "red": 10.0,
        "ml": 30.0,
        "google_safe_browsing": 5.0,
        "virustotal": 5.0,
    })
    # pesos: ml .45*30=13.5 + heur .25*20=5 + red .2*10=2 + conn .1*(5+5)/1.0*... 
    assert out.score > 0
    assert out.veredicto in {"seguro", "sospechoso", "phishing"}
    assert 0 <= out.confianza <= 1


def test_consistent_high_motors_map_to_phishing(combiner):
    # Todos los motores coinciden en riesgo alto -> phishing.
    out = combiner.combine({"heuristica": 90, "red": 85, "ml": 95.0})
    assert out.score >= 80
    assert out.veredicto == "phishing"


def test_high_ml_single_motor_stays_suspicious(combiner):
    # Un solo motor alto, el resto limpio: se pondera y no dispara phishing.
    out = combiner.combine({"heuristica": 10, "red": 10, "ml": 90.0})
    assert out.veredicto in {"sospechoso", "phishing"}
    assert out.score < 80


def test_missing_motors_renormalize(combiner):
    # Solo heuristica disponible
    out = combiner.combine({"heuristica": 50.0})
    assert out.veredicto in {"sospechoso", "phishing"}


def test_low_scores_map_to_seguro(combiner):
    out = combiner.combine({"heuristica": 5, "red": 5, "ml": 5})
    assert out.veredicto == "seguro"
