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
from email import message_from_string
from email.utils import parsedate_to_datetime
from pathlib import Path

from pydantic import BaseModel, Field, field_validator, model_validator
from sqlmodel import Session

import app.core.security as security

from app.api.deps import (
    get_db, get_email_analyzer, get_explainer, get_mailbox, get_pipeline, get_settings,
)
from app.core.mailbox import Mailbox, MailboxError
from app.core.email_analysis import (
    EmailAnalyzer, parse_email, parse_fields, parse_text_message,
)
from app.core.pipeline import AnalysisPipeline
from app.core.config import Settings
from app.engines.base import AnalysisContext
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
        "motivos_por_motor": report.motivos_por_motor,
        "partes": url_parts(report.url),
        "tiempo_ms": report.tiempo_ms,
    }


def url_parts(url: str) -> dict:
    """Partes de la URL para mostrarla segmentada en la interfaz.

    El dominio registrado es el que realmente decide a qué sitio lleva el enlace;
    todo lo que va a su izquierda (subdominio, usuario) lo elige quien registró el dominio.
    """
    ctx = AnalysisContext.from_url(url)
    rest = url.split("://", 1)[-1]
    rest = rest[rest.find("/"):] if "/" in rest else ""
    return {
        "esquema": ctx.scheme,
        "usuario": ctx.username,
        "subdominio": ctx.subdomain,
        "dominio": ctx.registered_domain or ctx.host,
        "puerto": ctx.port,
        "ruta": rest,
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


# ---------------------------------------------------------------- bandeja del servidor propio
# El análisis de un correo es costoso (consulta la red por cada enlace), y la bandeja se
# refresca sola cada pocos segundos: se cachea por UID para no repetir trabajo.
_inbox_cache: dict[str, dict] = {}


def _message_date(raw: str) -> Optional[str]:
    """Fecha del encabezado Date en ISO, o None si el correo no la trae o viene mal formada."""
    try:
        parsed = parsedate_to_datetime(message_from_string(raw).get("Date", ""))
        return parsed.isoformat() if parsed else None
    except (TypeError, ValueError):
        return None


@router.get("/inbox", status_code=200, dependencies=[Depends(require_api_key)])
def inbox(
    limit: int = 20,
    mailbox: Mailbox = Depends(get_mailbox),
    analyzer: EmailAnalyzer = Depends(get_email_analyzer),
    settings: Settings = Depends(get_settings),
) -> dict:
    """Correos del buzón IMAP propio, cada uno ya clasificado como phishing o normal."""
    info = {"configurada": mailbox.enabled, "buzon": settings.imap_mailbox,
            "cuarentena": settings.imap_quarantine, "correos": []}
    if not mailbox.enabled:
        return info
    try:
        messages = mailbox.fetch_recent(max(1, min(limit, 50)))
    except MailboxError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc)) from exc

    if len(_inbox_cache) > 500:
        _inbox_cache.clear()
    for message in messages:
        result = _inbox_cache.get(message.uid)
        if result is None:
            result = analyzer.analyze(parse_email(message.raw))
            result["fecha"] = _message_date(message.raw)
            _inbox_cache[message.uid] = result
        info["correos"].append({
            "uid": message.uid,
            "fecha": result.get("fecha"),
            "asunto": result.get("asunto") or "(sin asunto)",
            "remitente": result.get("remitente") or {},
            "veredicto": result["veredicto"],
            "score": result["score"],
            "confianza": result.get("confianza"),
            "motivos": (result.get("motivos") or [])[:3],
            "enlaces": len(result.get("enlaces") or []),
        })
    return info


@router.get("/inbox/{uid}", status_code=200, dependencies=[Depends(require_api_key)])
def inbox_message(uid: str) -> dict:
    """Análisis completo de un correo de la bandeja (el mismo que devuelve /analyze-email)."""
    result = _inbox_cache.get(uid)
    if result is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Ese correo ya no está en la bandeja. Actualízala.")
    return result


@router.post("/inbox/{uid}/cuarentena", status_code=200, dependencies=[Depends(require_api_key)])
def quarantine(
    uid: str,
    mailbox: Mailbox = Depends(get_mailbox),
    settings: Settings = Depends(get_settings),
) -> dict:
    """Mueve el correo a la carpeta de cuarentena del buzón (como hace el spam de Gmail)."""
    try:
        mailbox.move(uid, settings.imap_quarantine)
    except MailboxError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc)) from exc
    _inbox_cache.pop(uid, None)
    return {"movido": True, "carpeta": settings.imap_quarantine}


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
