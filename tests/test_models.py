"""Tests del modelo de datos Analysis (app.db.models)."""
import pytest
from sqlmodel import SQLModel, Session, create_engine

from app.db.models import Analysis


@pytest.fixture()
def session():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


def test_analysis_fields_persist(session):
    """Un Analysis se guarda con todos sus campos y se puede leer de vuelta."""
    a = Analysis(
        url="https://example.com/login",
        veredicto="sospechoso",
        score=50,
        confianza=0.8,
        motivos=["dominio nuevo", "keyword de login"],
        desglose={"heuristica": 70, "ml": 30},
        source="api",
    )
    session.add(a)
    session.commit()
    session.refresh(a)

    assert a.id is not None
    got = session.get(Analysis, a.id)
    assert got.url == "https://example.com/login"
    assert got.veredicto == "sospechoso"
    assert got.score == 50
    assert got.confianza == 0.8
    assert got.motivos == ["dominio nuevo", "keyword de login"]
    assert got.desglose == {"heuristica": 70, "ml": 30}
    assert got.source == "api"
    assert got.created_at is not None


def test_analysis_same_url_allowed_multiple_times(session):
    """La misma URL puede analizarse varias veces: cada análisis es una fila de historial."""
    session.add(Analysis(url="https://dup.com", veredicto="seguro", score=10))
    session.commit()
    session.add(Analysis(url="https://dup.com", veredicto="phishing", score=90))
    session.commit()  # no debe lanzar
    from sqlmodel import select
    rows = session.exec(select(Analysis).where(Analysis.url == "https://dup.com")).all()
    assert len(rows) == 2
