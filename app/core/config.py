"""Configuración de la aplicación.

Concentra todos los valores configurables del sistema (claves API, pesos del scoring,
umbrales de bandas, rutas). Se instancia desde variables de entorno con prefijo `PD_`.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, Tuple

from dotenv import load_dotenv

# Carga las variables de un archivo `.env` del directorio de trabajo (si existe) al
# importar el módulo. `override=False` respeta las variables de entorno ya definidas:
# una env var real tiene prioridad sobre el `.env`. Correr acá garantiza que cualquier
# `Settings.from_env()` posterior vea los valores del `.env`.
load_dotenv()


@dataclass
class Settings:
    """Valores de configuración de phishing-detector."""

    app_name: str = "phishing-detector"
    db_path: str = "phishing.db"

    # Autenticación por API key: conjunto de claves válidas.
    api_keys: set = field(default_factory=lambda: {"dev-key"})

    # Pesos del scoring combinado (suman 1.0).
    heuristic_weight: float = 0.25
    ml_weight: float = 0.45
    network_weight: float = 0.20
    connector_weight: float = 0.10

    # Bandas de veredicto: nombre -> umbral mínimo de score.
    bands: Dict[str, int] = field(
        default_factory=lambda: {
            "seguro": 0,
            "sospechoso": 35,
            "phishing": 60,
        }
    )

    # Tiempo máximo total de un análisis, en segundos (RNF2: menos de 5 s por URL).
    analysis_timeout: float = 4.5

    # Conectores externos opcionales (None = no disponible / sin key).
    gsb_api_key: str | None = None
    vt_api_key: str | None = None

    # Rutas de datos versionados.
    model_path: str = "data/model.joblib"
    dataset_path: str = "data/dataset"
    # Lista de dominios de reputación (opcional); se suma `known_domains_tranco.txt` si existe.
    known_domains_path: str = "data/known_domains.txt"

    @classmethod
    def from_env(cls) -> "Settings":
        s = cls()
        if v := os.getenv("PD_DB_PATH"):
            s.db_path = v
        if v := os.getenv("PD_API_KEYS"):
            s.api_keys = {k.strip() for k in v.split(",") if k.strip()}
        if v := os.getenv("PD_GSB_API_KEY"):
            s.gsb_api_key = v
        if v := os.getenv("PD_VT_API_KEY"):
            s.vt_api_key = v
        if v := os.getenv("PD_MODEL_PATH"):
            s.model_path = v
        if v := os.getenv("PD_DATASET_PATH"):
            s.dataset_path = v
        if v := os.getenv("PD_KNOWN_DOMAINS_PATH"):
            s.known_domains_path = v
        if v := os.getenv("PD_ANALYSIS_TIMEOUT"):
            s.analysis_timeout = float(v)
        if v := os.getenv("PD_HEURISTIC_WEIGHT"):
            s.heuristic_weight = float(v)
        if v := os.getenv("PD_ML_WEIGHT"):
            s.ml_weight = float(v)
        if v := os.getenv("PD_NETWORK_WEIGHT"):
            s.network_weight = float(v)
        if v := os.getenv("PD_CONNECTOR_WEIGHT"):
            s.connector_weight = float(v)
        return s

    def band_name(self, score: int) -> str:
        """Mapea un score 0-100 al nombre de la banda correspondiente."""
        # Las bandas se evalúan de mayor a menor umbral.
        ordered: list[tuple[str, int]] = sorted(
            self.bands.items(), key=lambda kv: kv[1], reverse=True
        )
        for name, threshold in ordered:
            if score >= threshold:
                return name
        return "seguro"

    def band_thresholds(self) -> Tuple[str, ...]:
        return tuple(sorted(self.bands, key=self.bands.get, reverse=True))
