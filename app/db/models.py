"""Modelos de persistencia con SQLModel.

Storage local en SQLite. El modelo Analysis es a la vez tabla y schema de respuesta.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List, Optional

from sqlalchemy import Column
from sqlalchemy.dialects.sqlite import JSON
from sqlmodel import Field, SQLModel


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Analysis(SQLModel, table=True):
    """Registro de un análisis de URL."""

    id: Optional[int] = Field(default=None, primary_key=True)
    url: str = Field(index=True, nullable=False)
    veredicto: str = Field(nullable=False)
    score: int = Field(nullable=False)
    confianza: float = Field(default=0.0, nullable=False)
    motivos: List[str] = Field(default_factory=list, sa_column=Column(JSON))
    desglose: Dict[str, float] = Field(default_factory=dict, sa_column=Column(JSON))
    source: str = Field(default="api", nullable=False)
    created_at: datetime = Field(default_factory=_now, nullable=False)
