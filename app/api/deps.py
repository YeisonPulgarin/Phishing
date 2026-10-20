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
from app.core.mailbox import Mailbox
from app.core.pipeline import AnalysisPipeline
from app.db.session import DB
from app.engines.explain import ModelExplainer

_settings = Settings.from_env()
_db_container = DB(_settings)
_pipeline = AnalysisPipeline(_settings)
def _build_mailbox(user: str, password: str) -> Mailbox:
    """Un buzón para una cuenta concreta. Todas comparten servidor (host/puerto/TLS);
    solo cambian usuario y contraseña."""
    return Mailbox(
        host=_settings.imap_host,
        port=_settings.imap_port,
        user=user,
        password=password,
        use_ssl=_settings.imap_ssl,
        mailbox=_settings.imap_mailbox,
        starttls=_settings.imap_starttls,
    )


# Un buzón listo por cada cuenta configurada (la conexión real se abre solo al usarlo).
_mailboxes: dict = {acc["id"]: _build_mailbox(acc["user"], acc["password"]) for acc in _settings.imap_accounts}
# Buzón vacío de reserva: su propiedad .enabled es False, así la bandeja se muestra "no configurada".
_mailbox = next(iter(_mailboxes.values()), _build_mailbox("", ""))


def default_account_id() -> str:
    """Id de la primera cuenta configurada (la que se usa si no se pide ninguna)."""
    return _settings.imap_accounts[0]["id"] if _settings.imap_accounts else ""


def list_accounts() -> list:
    """Cuentas disponibles para el selector de la bandeja (sin exponer contraseñas)."""
    return [{"id": a["id"], "nombre": a["nombre"]} for a in _settings.imap_accounts]


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


def get_mailbox(cuenta: str | None = None) -> Mailbox:
    """Buzón de la cuenta pedida (?cuenta=<id>); si no se indica o no existe, la primera."""
    if cuenta and cuenta in _mailboxes:
        return _mailboxes[cuenta]
    return _mailbox
