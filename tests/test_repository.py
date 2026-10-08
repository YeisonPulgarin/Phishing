"""Tests del repositorio de análisis (app.db.repository)."""
import pytest
from sqlmodel import SQLModel, Session, create_engine

from app.core.config import Settings
from app.db.models import Analysis
from app.db.repository import AnalysisRepository
from app.db.session import DB, build_engine


@pytest.fixture()
def repo():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield AnalysisRepository(s)


def _analysis(url, veredicto, score):
    return Analysis(url=url, veredicto=veredicto, score=score)


def test_create_and_get(repo):
    a = repo.create(_analysis("https://a.com", "seguro", 10))
    got = repo.get(a.id)
    assert got is not None
    assert got.url == "https://a.com"


def test_find_by_url(repo):
    repo.create(_analysis("https://b.com", "phishing", 90))
    hit = repo.find_by_url("https://b.com")
    assert hit is not None
    assert hit.veredicto == "phishing"
    assert repo.find_by_url("https://missing.com") is None


def test_list_most_recent_first(repo):
    a1 = repo.create(_analysis("https://one.com", "seguro", 10))
    a2 = repo.create(_analysis("https://two.com", "sospechoso", 50))
    items = repo.list_all()
    # El más reciente primero
    assert items[0].id == a2.id
    assert items[1].id == a1.id


def test_db_session_creates_and_commits(tmp_path):
    """El contenedor DB crea la BD, y una sesión persiste un Analysis."""
    db_path = tmp_path / "test.db"
    settings = Settings(db_path=str(db_path))
    db = DB(settings)

    with db.session() as session:
        repo = AnalysisRepository(session)
        created = repo.create(Analysis(url="https://x.com", veredicto="seguro", score=5))

    # Nueva sesión lee lo persistido
    with db.session() as session:
        got = session.get(Analysis, created.id)
        assert got is not None
        assert got.url == "https://x.com"


def test_find_by_url_returns_most_recent(repo):
    repo.create(_analysis("https://dup.com", "seguro", 10))
    last = repo.create(_analysis("https://dup.com", "phishing", 90))
    hit = repo.find_by_url("https://dup.com")
    assert hit.id == last.id
    assert hit.veredicto == "phishing"


def test_init_db_removes_legacy_unique_index(tmp_path):
    """Una base vieja con índice UNIQUE sobre url se migra sin borrar el archivo."""
    import sqlite3

    from app.db.session import init_db

    db_file = tmp_path / "legacy.db"
    con = sqlite3.connect(db_file)
    con.executescript(
        """
        CREATE TABLE analysis (
            id INTEGER PRIMARY KEY, url VARCHAR NOT NULL, veredicto VARCHAR NOT NULL,
            score INTEGER NOT NULL, confianza FLOAT NOT NULL, motivos JSON, desglose JSON,
            source VARCHAR NOT NULL, created_at DATETIME NOT NULL
        );
        CREATE UNIQUE INDEX ix_analysis_url ON analysis (url);
        """
    )
    con.commit()
    con.close()

    engine = build_engine(str(db_file))
    init_db(engine)
    with Session(engine) as s:
        repo = AnalysisRepository(s)
        repo.create(_analysis("https://dup.com", "seguro", 10))
        repo.create(_analysis("https://dup.com", "phishing", 90))  # antes: IntegrityError
        assert repo.find_by_url("https://dup.com").veredicto == "phishing"
