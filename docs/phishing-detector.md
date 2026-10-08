# Detector de phishing

Sistema que recibe una URL y determina si es phishing o no. Expone una API REST y una UI
web mínima. Un usuario autenticado envía una URL y recibe un veredicto con score,
confianza y desglose de motivos.

## Cómo funciona

Aplicación monolítica FastAPI en Python que sirve la API y la UI estática desde el mismo
proceso (`app/main.py`). El flujo de análisis está orquestado por `app/core/pipeline.py`
(`AnalysisPipeline`):

1. **Normalización** — si la URL no trae esquema, se agrega `https://`.
2. **Motores de análisis** (cada uno produce un sub-score 0–100):
   - `app/engines/heuristic.py` — `HeuristicEngine`: señales léxicas de la URL (host IP,
     símbolo `@`, TLD abusivo, typosquat de marcas, exceso de subdominios, guiones,
     keywords de credenciales, ausencia de HTTPS). Usa señal-peso aditivo con floors y
     overrides para combinaciones críticas.
   - `app/engines/red.py` — `NetworkEngine`: chequeos de red (DNS, certificado SSL,
     redirecciones, edad del dominio vía RDAP, contenido HTML). El acceso a red está
     detrás de un cliente inyectable (`NetworkClient`) para testear sin tocar la red real.
   - `app/engines/ml.py` — `MlEngine`: extrae 13 features léxicas y usa un Random Forest
     (persistido con joblib en `data/model.joblib`) para estimar la probabilidad de
     phishing.
3. **Conectores externos** (`app/connectors/`): Google Safe Browsing y VirusTotal.
   Opcionales: sin API key configurada (en `Settings`) devuelven "no disponible" y no
   bloquean el análisis.
4. **Scoring** (`app/core/scoring.py`, `ScoreCombiner`): pondera los sub-scores de los
   motores disponibles (ML 45%, heurística 25%, red 20%, conectores 10%, re-normalizados
   sobre los presentes), mapea el score a una banda de veredicto y calcula la confianza
   según cuántos motores aportaron.
5. **Persistencia** — el resultado se guarda en SQLite (`app/db/models.py`, modelo
   `Analysis`) a través del repositorio `AnalysisRepository`.

Resultado (`AnalysisReport`): `url`, `veredicto`, `score`, `confianza`, `motivos` y
`desglose` (sub-score por motor).

### Bandas de veredicto (configurables en `Settings`)

- `seguro`: 0–34
- `sospechoso`: 35–59
- `phishing`: 60–100

Los motores aplican floors/overrides antes de llegar al scoring, por lo que una señal
crítica sola (host IP, `@`, TLD abusivo, typosquat) puede elevar la banda incluso si el
score ponderado es bajo.

## Endpoints

| Método | Ruta | Auth | Descripción |
|--------|------|------|-------------|
| POST | `/api/analyze` | `X-API-Key` | Analiza una URL y devuelve el reporte |
| GET | `/api/analyses` | `X-API-Key` | Lista el historial de análisis |
| GET | `/api/analyses/{id}` | `X-API-Key` | Devuelve un análisis por id |
| POST | `/api/auth` | — | Valida la API key (login de la UI) |
| GET | `/health` | — | Health check |

La autenticación se valida en `app/core/security.py` contra el conjunto `Settings.api_keys`
(por defecto `dev-key`).

## Configuración

Toda la configuración vive en `app/core/config.py` (`Settings`, leída con `from_env()` con
prefijo `PD_`). Los valores se leen de variables de entorno y, si existe, de un archivo
`.env` en el directorio de trabajo (una variable de entorno ya definida tiene prioridad).
Variables relevantes:

- `PD_DB_PATH` — ruta del archivo SQLite.
- `PD_API_KEYS` — claves válidas separadas por coma.
- `PD_GSB_API_KEY` / `PD_VT_API_KEY` — claves de los conectores opcionales (si se omiten,
  los conectores degradan).
- `PD_MODEL_PATH` / `PD_DATASET_PATH` — rutas del modelo y dataset.

## Entrenamiento del modelo

`scripts/embed_dataset.py` genera el dataset de entrenamiento y
`scripts/train_model.py` entrena el Random Forest y persiste `data/model.joblib`.
Ambos se ejecutan offline. El dataset incluido es sintético; para usar datos reales
(p. ej. UCI Phishing Websites), reemplazar `data/dataset/phishing.csv` manteniendo el mismo
formato de columnas y re-correr `train_model.py`.

## UI web

La UI (`app/ui/`) pide la API key (validada con `/api/auth`), permite enviar una URL por
formulario y muestra el veredicto, score, confianza y motivos. Se sirve en `/`.

## Decisiones

- **SQLite + SQLModel** para persistencia: suficiente para el volumen inicial; el salto a
  Postgres queda acotado y fuera de alcance.
- **Random Forest sobre XGBoost/NLP**: interpretable (feature importance) y suficiente en
  latencia para el hot path. NLP pesado está excluido.
- **Conectores externos degradables**: nunca bloquean el análisis local si no hay key o la
  llamada falla.
- **Floors/overrides en los motores**: una señal crítica eleva la banda sin depender de la
  ponderación lineal.
- **Red detrás de cliente inyectable**: toda la suite corre sin tocar red real (mocks).

## Limitaciones conocidas

- **No se renderiza JavaScript** ni se navega con browser headless: el análisis de
  contenido se limita a HTML estático y a los checks HTTP de bajo riesgo. Contenido
  dinámico queda fuera de alcance.
- **Dataset ML sintético**: el modelo incluido se entrenó con datos generados por reglas,
  no con un dataset real; es reentrenable (ver "Entrenamiento del modelo").
- **Sin registro de usuarios**: las API keys se definen por configuración, no desde la UI.
- **Sin rate limiting elaborado** ni reentrenamiento automático por feedback.
