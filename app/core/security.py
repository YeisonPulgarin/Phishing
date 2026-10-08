"""Autenticación por API key (header X-API-Key).

Valida la key enviada por el cliente contra el conjunto de claves válidas de la
configuración. Una petición sin key o con key inválida recibe 401.
"""
from __future__ import annotations

from fastapi import Header, HTTPException, status

from app.core.config import Settings

_settings = Settings.from_env()


class APIKeyValidator:
    """Valida una API key contra el conjunto de claves de configuración."""

    def __init__(self, settings: Settings) -> None:
        self._keys = set(settings.api_keys)

    def is_valid(self, key: str) -> bool:
        return key in self._keys


def _get_validator() -> APIKeyValidator:
    # Punto de inyección: en tests se overridea esta función.
    return APIKeyValidator(_settings)


def require_api_key(x_api_key: str = Header(default="")) -> None:
    """Dependencia FastAPI que exige una API key válida."""
    validator = _get_validator()
    if not x_api_key or not validator.is_valid(x_api_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key inválida o ausente",
            headers={"WWW-Authenticate": "ApiKey"},
        )
