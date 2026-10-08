"""Repositorio de acceso a los análisis guardados."""
from __future__ import annotations

from typing import List, Optional

from sqlmodel import Session, select

from app.db.models import Analysis


class AnalysisRepository:
    """Encapsula el acceso a la tabla Analysis."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def create(self, analysis: Analysis) -> Analysis:
        self._session.add(analysis)
        self._session.commit()
        self._session.refresh(analysis)
        return analysis

    def get(self, analysis_id: int) -> Optional[Analysis]:
        return self._session.get(Analysis, analysis_id)

    def find_by_url(self, url: str) -> Optional[Analysis]:
        """Devuelve el análisis más reciente de la URL (puede haber varios)."""
        stmt = (
            select(Analysis)
            .where(Analysis.url == url)
            .order_by(Analysis.created_at.desc(), Analysis.id.desc())
        )
        return self._session.exec(stmt).first()

    def list_all(self, limit: int = 100) -> List[Analysis]:
        stmt = select(Analysis).order_by(Analysis.created_at.desc()).limit(limit)
        return list(self._session.exec(stmt).all())
