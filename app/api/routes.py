"""Endpoints REST de la API.

- POST /api/analyze   -> analiza una URL y persiste el resultado.
- GET  /api/analyses  -> lista el historial.
- GET  /api/analyses/{id} -> devuelve un análisis.
- POST /api/auth      -> valida la API key (login de la UI).
- POST /api/explain   -> explicación SHAP de la predicción del modelo ML para una URL.
- GET  /api/evaluation -> reportes de evaluación y de entrenamiento del modelo (para la UI).
- POST /api/analyze-email   -> analiza un correo (.eml completo o asunto/remitente/cuerpo).
- POST /api/analyze-message -> analiza un mensaje de texto (SMS, chat).
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
import json
from pathlib import Path

from pydantic import BaseModel, Field, field_validator, model_validator
from sqlmodel import Session

import app.core.security as security

from app.api.deps import get_db, get_email_analyzer, get_explainer, get_pipeline, get_settings
from app.core.email_analysis import (
    EmailAnalyzer, parse_email, parse_fields, parse_text_message,
)
from app.core.pipeline import AnalysisPipeline
from app.core.config import Settings
from app.engines.explain import ModelExplainer
from app.engines.ml import FEATURE_LABELS
from app.core.security import require_api_key
from app.db.models import Analysis
from app.db.repository import AnalysisRepository

router = APIRouter(prefix="/api")


class AnalyzeRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def url_not_blank(cls, v: str) -> str:
        v = v.strip()
        if not v or v.lower() in {"http://", "https://"}:
            raise ValueError("La URL no puede estar vacía")
        if not v.startswith(("http://", "https://")):
            # Se normaliza agregando https, así que debe parsearse después.
            pass
        return v


class AuthRequest(BaseModel):
    api_key: str


class EmailRequest(BaseModel):
    """Correo completo en formato .eml (`raw`) o campos sueltos (`subject`, `sender`, `body`)."""

    raw: Optional[str] = Field(default=None, max_length=300_000)
    subject: Optional[str] = Field(default=None, max_length=1_000)
    sender: Optional[str] = Field(default=None, max_length=500)
    body: Optional[str] = Field(default=None, max_length=200_000)

    @model_validator(mode="after")
    def has_content(self) -> "EmailRequest":
        if not (self.raw or "").strip() and not (self.body or "").strip():
            raise ValueError("Ingresá el correo completo (.eml) o al menos el cuerpo")
        return self


class MessageRequest(BaseModel):
    text: str = Field(max_length=5_000)

    @field_validator("text")
    @classmethod
    def text_not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("El mensaje no puede estar vacío")
        return v


def _persist_message(session: Session, result: dict) -> int:
    """Guarda un análisis de correo/mensaje en el historial (misma tabla que las URLs)."""
    first_url = result["enlaces"][0]["url"] if result["enlaces"] else ""
    label = result["asunto"] or first_url or result["extracto"] or "(sin texto)"
    record = Analysis(
        url=f"{result['tipo']}: {label}"[:200],
        veredicto=result["veredicto"],
        score=int(round(result["score"])),
        confianza=result["confianza"],
        motivos=result["motivos"],
        desglose=result["desglose"],
        source=result["tipo"],
    )
    return AnalysisRepository(session).create(record).id


@router.post("/analyze", status_code=200, dependencies=[Depends(require_api_key)])
def analyze(
    body: AnalyzeRequest,
    pipeline: AnalysisPipeline = Depends(get_pipeline),
    session: Session = Depends(get_db),
) -> dict:
    report = pipeline.analyze(body.url)
    record = Analysis(
        url=report.url,
        veredicto=report.veredicto,
        score=int(round(report.score)),
        confianza=report.confianza,
        motivos=report.motivos,
        desglose=report.desglose,
        source="api",
    )
    saved = AnalysisRepository(session).create(record)
    return {
        "id": saved.id,
        "url": report.url,
        "veredicto": report.veredicto,
        "score": report.score,
        "confianza": report.confianza,
        "motivos": report.motivos,
        "desglose": report.desglose,
    }


@router.post("/explain", status_code=200, dependencies=[Depends(require_api_key)])
def explain(body: AnalyzeRequest, explainer: ModelExplainer = Depends(get_explainer)) -> dict:
    try:
        return explainer.explain(body.url)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "URL inválida") from exc


def _load_report(directory: Path, name: str):
    path = directory / name
    try:
        return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None
    except (OSError, ValueError):
        return None


@router.get("/evaluation", status_code=200, dependencies=[Depends(require_api_key)])
def evaluation(settings: Settings = Depends(get_settings)) -> dict:
    """Reportes generados por `scripts/evaluate.py` y `scripts/train_model.py` (null si no existen)."""
    directory = Path(settings.model_path).parent
    return {
        "evaluacion": _load_report(directory, "evaluation_report.json"),
        "modelo": _load_report(directory, "model_report.json"),
        "etiquetas": FEATURE_LABELS,
    }


@router.post("/analyze-email", status_code=200, dependencies=[Depends(require_api_key)])
def analyze_email(
    body: EmailRequest,
    analyzer: EmailAnalyzer = Depends(get_email_analyzer),
    session: Session = Depends(get_db),
) -> dict:
    parsed = (parse_email(body.raw) if (body.raw or "").strip()
              else parse_fields(body.subject or "", body.sender or "", body.body or ""))
    result = analyzer.analyze(parsed)
    result["id"] = _persist_message(session, result)
    return result


@router.post("/analyze-message", status_code=200, dependencies=[Depends(require_api_key)])
def analyze_message(
    body: MessageRequest,
    analyzer: EmailAnalyzer = Depends(get_email_analyzer),
    session: Session = Depends(get_db),
) -> dict:
    result = analyzer.analyze(parse_text_message(body.text))
    result["id"] = _persist_message(session, result)
    return result


@router.get("/analyses", status_code=200, dependencies=[Depends(require_api_key)])
def list_analyses(session: Session = Depends(get_db)) -> list:
    items = AnalysisRepository(session).list_all()
    return [
        {
            "id": a.id,
            "url": a.url,
            "veredicto": a.veredicto,
            "score": a.score,
            "confianza": a.confianza,
            "created_at": a.created_at.isoformat(),
        }
        for a in items
    ]


@router.get("/analyses/{analysis_id}", status_code=200, dependencies=[Depends(require_api_key)])
def get_analysis(analysis_id: int, session: Session = Depends(get_db)) -> dict:
    a = AnalysisRepository(session).get(analysis_id)
    if a is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Análisis no encontrado")
    return {
        "id": a.id,
        "url": a.url,
        "veredicto": a.veredicto,
        "score": a.score,
        "confianza": a.confianza,
        "motivos": a.motivos,
        "desglose": a.desglose,
        "created_at": a.created_at.isoformat(),
    }


@router.post("/auth", status_code=200)
def login(body: AuthRequest) -> dict:
    validator = security._get_validator()
    if not validator.is_valid(body.api_key):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="API key inválida")
    return {"ok": True}
