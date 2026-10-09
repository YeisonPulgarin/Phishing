# Mezcla de interfaces + mejoras de UX

Este proyecto (`pishing`) ya tenía una interfaz modular propia. Se le **integró la interfaz de
PhishShield** (`pishing-detector`) tomando sus elementos distintivos y rehaciéndolos con el
sistema de diseño, los helpers (`h`/`s`/`vars`) y la política de seguridad (CSP estricta, sin
recursos externos, todo el contenido dinámico como texto) del proyecto base. No se cambió el
comportamiento de detección.

## Lo que se trajo de PhishShield

- **Disección del enlace — "Así se lee este enlace".** Separa la URL en sus partes (protocolo,
  usuario, subdominio, **dominio real**, puerto, ruta) y coloca cada señal debajo de la parte que
  la provoca. Es la pieza educativa principal de PhishShield.
- **Escala de riesgo con marcador.** Barra 0–100 con las tres zonas (Seguro / Sospechoso /
  Phishing) y un marcador que se desliza hasta el puntaje, como complemento al velocímetro.
- **"¿Por qué?" agrupado por fuente.** Los motivos de una URL se agrupan por el motor que los
  encontró (reglas heurísticas, modelo de IA, red, servicios), cada uno con su puntaje.

## Mejoras de experiencia de uso añadidas

- **Barra de acciones del resultado:** "Analizar otro" (vuelve arriba y enfoca el campo) y
  "Copiar resumen" (copia veredicto, puntaje, qué hacer y señales al portapapeles).
- **Tiempo de análisis** visible en la línea de resumen ("analizado en 0,43 s").
- La disección usa scroll horizontal propio en pantallas chicas y respeta el modo de
  movimiento reducido y el tema claro/oscuro, igual que el resto de la interfaz.

## Archivos tocados

Backend (solo aditivo, para alimentar la UI; no cambia la detección):
- `app/core/pipeline.py` — `AnalysisReport` ahora incluye `motivos_por_motor` y `tiempo_ms`.
- `app/api/routes.py` — `/api/analyze` devuelve además `partes`, `motivos_por_motor` y `tiempo_ms`
  (helper `url_parts`).

Frontend:
- `app/ui/js/data.js` — `ENGINE_ORDER`, `PART_LABELS`, `partFor` (mapea cada motivo a su parte).
- `app/ui/js/charts.js` — `riskScale(score)`.
- `app/ui/js/views.js` — disección, motivos agrupados, barra de acciones y tiempo en el resultado.
- `app/ui/styles.css` — estilos de la escala, la disección, los grupos de motivos y las acciones.

Documentación: `docs/api/openapi.yaml` y `README.md` actualizados con los campos nuevos.

## Verificación hecha

- `node --check` en todos los módulos JS y `python -m compileall app` sin errores.
- Se replicaron los chequeos de `tests/test_ui.py` que leen archivos (CSP sin inline, sin
  recursos externos, sin `innerHTML`/`eval`/`setAttribute("style")`, todos los assets e imports
  resuelven): conformes.
- Render de extremo a extremo en Chromium (tema claro y oscuro) contra un backend simulado:
  la disección, la escala, los motivos agrupados y las acciones funcionan sin errores de consola.

> No se pudo correr `pytest` en este entorno porque la instalación de dependencias (PyPI) está
> bloqueada por política de red. Para la batería completa, en tu equipo:
> `pip install -r requirements.txt` y luego `pytest`.
