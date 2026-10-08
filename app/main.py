"""Entrypoint de la aplicación FastAPI.

Levanta la API REST y sirve la UI estática. La configuración se carga desde entorno.
"""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.api.routes import router as api_router
from app.core.config import Settings

settings = Settings.from_env()

app = FastAPI(title=settings.app_name)

app.include_router(api_router)

# La UI no usa scripts ni estilos en línea ni recursos externos: la política puede ser estricta.
# No se aplica a /docs (Swagger carga recursos de una CDN).
_UI_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; "
    "form-action 'self'; frame-ancestors 'none'"
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("X-Frame-Options", "DENY")
    path = request.url.path
    if path == "/" or path.startswith("/static/"):
        response.headers.setdefault("Content-Security-Policy", _UI_CSP)
    if path.startswith("/api/"):
        response.headers.setdefault("Cache-Control", "no-store")  # los análisis son datos del usuario
    return response

_UI_DIR = Path(__file__).resolve().parent / "ui"


@app.get("/health")
def health() -> JSONResponse:
    return JSONResponse({"status": "ok", "app": settings.app_name})


def _mount_ui() -> None:
    if _UI_DIR.exists():
        app.mount("/static", StaticFiles(directory=_UI_DIR), name="static")

        @app.get("/", include_in_schema=False)
        def index() -> FileResponse:
            return FileResponse(_UI_DIR / "index.html")


_mount_ui()
