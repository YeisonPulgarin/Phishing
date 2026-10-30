"""Punto de entrada para Vercel: expone la app FastAPI de app/main.py.

En local se sigue usando `python -m uvicorn app.main:app --reload`.
"""
from app.main import app  # noqa: F401
