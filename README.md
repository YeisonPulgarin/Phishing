# Pishing Detector

Sistema que analiza una URL y determina si es phishing. Expone una API REST y una UI web
mínima: un usuario autenticado envía una URL y recibe un veredicto con score, confianza y
desglose de motivos.

## Stack

- Python 3.11
- FastAPI + Uvicorn
- SQLModel (SQLite)
- scikit-learn (Random Forest) + joblib

## Instalación

```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Levantar en desarrollo

```bash
uvicorn app.main:app --reload
```

La API queda en `http://localhost:8000` (docs interactivas en `/docs`) y la UI en `/`.

## Tests

```bash
pytest
```

## Uso de la API

La autenticación usa una API key en el header `X-API-Key` (por defecto `dev-key`, ver
[Configuración](#configuración)).

```bash
curl -X POST http://localhost:8000/api/analyze \
  -H "Content-Type: application/json" \
  -H "X-API-Key: dev-key" \
  -d '{"url": "https://login.secure-bank.evil.tk/verify"}'
```

### Endpoints

| Método | Ruta | Auth | Descripción |
|--------|------|------|-------------|
| POST | `/api/analyze` | `X-API-Key` | Analiza una URL y devuelve el reporte |
| GET | `/api/analyses` | `X-API-Key` | Lista el historial de análisis |
| GET | `/api/analyses/{id}` | `X-API-Key` | Devuelve un análisis por id |
| GET | `/api/evaluation` | `X-API-Key` | Reportes de evaluación y entrenamiento (los usa la pestaña Evaluación) |
| POST | `/api/explain` | `X-API-Key` | Explicación SHAP de la predicción del ML para una URL |
| POST | `/api/analyze-email` | `X-API-Key` | Analiza un correo (`raw` = .eml completo, o `subject`/`sender`/`body`) |
| POST | `/api/analyze-message` | `X-API-Key` | Analiza un mensaje de texto (SMS, chat): `{"text": "..."}` |
| POST | `/api/auth` | — | Valida la API key (login de la UI) |
| GET | `/api/inbox` | `X-API-Key` | Correos del buzón IMAP propio, ya clasificados |
| GET | `/api/inbox/{uid}` | `X-API-Key` | Análisis completo de un correo de la bandeja |
| POST | `/api/inbox/{uid}/cuarentena` | `X-API-Key` | Mueve ese correo a la carpeta de cuarentena |
| GET | `/health` | — | Health check |

La especificación completa está en `docs/api/openapi.yaml`, con colección ejecutable en
Bruno en `docs/collections/`.

### Interfaz web

Al encender el servidor (`uvicorn app.main:app`) la interfaz queda en http://localhost:8000 (misma
dirección que la API, sin segundo proceso). Se ingresa con la clave API del `.env`
(`PD_API_KEYS`) y tiene cuatro secciones:

- **Analizar:** enlace, correo (campos o archivo `.eml`) o SMS, con ejemplos para probar. Muestra
  la categoría, un indicador de riesgo de 0 a 100 (velocímetro y escala con marcador), qué hacer,
  y para los enlaces una **disección "Así se lee este enlace"** que separa la URL en sus partes
  (protocolo, subdominio, dominio real, ruta) y pone cada señal debajo de la parte que la provoca.
  Los motivos se agrupan por la fuente que los encontró (reglas, modelo de IA, red, servicios),
  junto con cómo se compone el puntaje y la explicación SHAP del modelo. Cada resultado se puede
  copiar como resumen y relanzar con "Analizar otro".
- **Bandeja:** se conecta por IMAP al servidor de correo propio (Postfix + Dovecot) y muestra
  los correos que van llegando, cada uno ya clasificado como seguro, sospechoso o phishing. Se
  relee sola cada pocos segundos, permite abrir el detalle de cada correo y mover los de phishing
  a una carpeta de cuarentena, igual que hace el spam de Gmail. Se activa llenando las variables
  `PD_IMAP_*` del `.env`; si se dejan vacías, la pestaña avisa cómo configurarla.
- **Historial:** análisis guardados con filtros, detalle de cada uno y descarga en CSV.
- **Evaluación:** reglas vs modelo de IA vs combinado (tabla, métricas, curvas ROC, matriz de
  confusión), comparación de modelos y limitaciones.
- **Cómo funciona:** el recorrido del enlace al veredicto.

Es HTML, CSS y JavaScript sin dependencias ni internet (`app/ui/`), con tema oscuro y claro y
diseño para celular: desde el teléfono, abre `http://IP-del-computador:8000` en la misma red
(levanta el servidor con `--host 0.0.0.0`). Todo el contenido dinámico entra como texto (nunca
`innerHTML`) y el servidor envía una política CSP estricta, cabeceras de endurecimiento y
`Cache-Control: no-store` en la API.

### Correos y mensajes

El análisis de un correo extrae el dominio del remitente y las URLs del cuerpo (texto y HTML,
sin adjuntos) y los evalúa con el mismo pipeline que una URL. Suma señales propias: lenguaje
típico de phishing, nombre de remitente que suplanta una marca, `Reply-To` distinto del
remitente, enlaces cuyo texto no coincide con su destino y fallos SPF/DKIM/DMARC.

```bash
curl -X POST http://localhost:8000/api/analyze-email \
  -H "Content-Type: application/json" -H "X-API-Key: dev-key" \
  -d '{"subject": "URGENTE: verifique su cuenta", "sender": "PayPal <soporte@paypa1-alertas.tk>", "body": "Haga clic: http://paypa1-alertas.tk/login"}'
```

### Evaluación

`python scripts/evaluate.py` compara reglas heurísticas, ML y puntaje combinado (precisión,
recall, F1, accuracy y AUC-ROC) sobre dominios que el modelo no vio y escribe
`docs/evaluacion.md` y `data/evaluation_report.json`.

## Configuración

Las variables de entorno usan el prefijo `PD_` (ver `app/core/config.py`):

- `PD_DB_PATH` — ruta del archivo SQLite.
- `PD_API_KEYS` — claves válidas separadas por coma (default `dev-key`).
- `PD_GSB_API_KEY` / `PD_VT_API_KEY` — claves de Google Safe Browsing / VirusTotal. Si se
  omiten, esos conectores degradan a "no disponible" y no bloquean el análisis.
- `PD_MODEL_PATH` / `PD_DATASET_PATH` — rutas del modelo y dataset de ML.
- `PD_KNOWN_DOMAINS_PATH` — lista de dominios de reputación (default `data/known_domains.txt`).
- `PD_ANALYSIS_TIMEOUT` — tiempo máximo total de un análisis en segundos (default `4.5`).

## Entrenamiento del modelo

El modelo se entrena con el dataset real PhiUSIIL (UCI, 235 795 URLs). El CSV no se
versiona: descargalo de https://archive.ics.uci.edu/dataset/967 y dejalo en
`data/dataset/PhiUSIIL_Phishing_URL_Dataset.csv`.

```bash
python scripts/train_model.py                    # o pasando la ruta del CSV como argumento
```

El script compara Regresión Logística y Random Forest con validación cruzada agrupada por
dominio, elige por F1, evalúa ambos en un test de dominios nunca vistos y guarda
`data/model.joblib` y `data/model_report.json` (todas las métricas). El modelo versionado
ya viene entrenado: solo hace falta re-entrenar si cambia el dataset o las features.

El ML ve únicamente la estructura del dominio (`canonical_ml_url`): el dataset tiene atajos
(100% de las legítimas son `https://www.<dominio>` sin ruta) que inflarían las métricas.

## Documentación

- `docs/phishing-detector.md` — cómo funciona el sistema, decisiones y limitaciones.
- `docs/api/openapi.yaml` — spec OpenAPI 3.1.
- `docs/collections/` — colección Bruno para probar la API.

## Limitaciones conocidas

- No se renderiza JavaScript: el análisis de contenido se limita a HTML estático y checks
  HTTP de bajo riesgo.
- El ML solo evalúa la estructura del dominio y, como el 97% de las legítimas de PhiUSIIL no
  tiene subdominio, puntúa alto los subdominios legítimos (p. ej. `mail.google.com`). Se
  mitiga con una lista de dominios de reputación (`data/known_domains.txt`; se amplía con
  `python scripts/update_known_domains.py`), que limita el peso del ML para esas marcas.
  Esa lista es un punto de evasión: un atacante puede alojar phishing en un servicio legítimo.
  Ver `data/model_report.json`.
- Las API keys se definen por configuración; no hay registro de usuarios desde la UI.
