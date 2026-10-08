"""Configuración de la sesión de base de datos SQLite."""
from __future__ import annotations

from contextlib import contextmanager
from typing import Generator

from sqlmodel import Session, SQLModel, create_engine

from app.core.config import Settings


def build_engine(db_path: str, *, echo: bool = False):
    """Crea un engine SQLite a partir de la ruta del archivo."""
    return create_engine(f"sqlite:///{db_path}", echo=echo)


def init_db(engine) -> None:
    """Crea las tablas si no existen."""
    # Importar los modelos aquí garantiza que las tablas estén registradas en
    # SQLModel.metadata antes de create_all, sin depender del orden de imports del app.
    from app.db import models  # noqa: F401

    SQLModel.metadata.create_all(engine)
    _relax_url_unique_index(engine)


def _relax_url_unique_index(engine) -> None:
    """Quita el índice UNIQUE sobre `analysis.url` en bases creadas con el esquema viejo.

    `create_all` no altera tablas existentes: una base vieja conserva el índice único y
    re-analizar la misma URL fallaría con 500. Se reemplaza por un índice normal.
    """
    from sqlalchemy import inspect, text

    insp = inspect(engine)
    if "analysis" not in insp.get_table_names():
        return
    for ix in insp.get_indexes("analysis"):
        if ix.get("name") == "ix_analysis_url" and ix.get("unique"):
            with engine.begin() as conn:
                conn.execute(text("DROP INDEX ix_analysis_url"))
                conn.execute(text("CREATE INDEX ix_analysis_url ON analysis (url)"))


class DB:
    """Contenedor de engine + fábrica de sesiones, construido desde Settings."""

    def __init__(self, settings: Settings) -> None:
        self.engine = build_engine(settings.db_path)
        init_db(self.engine)

    @contextmanager
    def session(self) -> Generator[Session, None, None]:
        with Session(self.engine) as session:
            yield session
