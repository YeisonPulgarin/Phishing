"""Dependencias de FastAPI.

Puntos de inyección para el pipeline de análisis y la sesión de base de datos. Se
overridean en los tests y permiten configurar la app por defecto desde Settings.
"""
from __future__ import annotations

from typing import Generator

from fastapi import Depends, HTTPException, status
from sqlmodel import Session

from app.core.config import Settings
from app.core.email_analysis import EmailAnalyzer
from app.core.pipeline import AnalysisPipeline
from app.db.session import DB
from app.engines.explain import ModelExplainer

_settings = Settings.from_env()
_db_container = DB(_settings)
_pipeline = AnalysisPipeline(_settings)


def get_db() -> Generator[Session, None, None]:
    with _db_container.session() as session:
        yield session


def get_pipeline() -> AnalysisPipeline:
    return _pipeline


def get_email_analyzer(pipeline: AnalysisPipeline = Depends(get_pipeline)) -> EmailAnalyzer:
    return EmailAnalyzer(pipeline, _settings)


_explainers: dict[int, ModelExplainer] = {}


def get_explainer(pipeline: AnalysisPipeline = Depends(get_pipeline)) -> ModelExplainer:
    model = pipeline.ml_model
    if model is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Modelo de ML no disponible")
    # Se reutiliza el explicador por modelo: crear el TreeExplainer es lo costoso.
    if id(model) not in _explainers:
        _explainers[id(model)] = ModelExplainer(model)
    return _explainers[id(model)]


def get_settings() -> Settings:
    return _settings
