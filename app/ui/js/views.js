/* Vistas de la interfaz: resultado de un análisis, historial, evaluación y "cómo funciona". */
import { h, clear, icon, alertBox, $ } from "./dom.js";
import * as charts from "./charts.js";
import {
  ATTACH_RISK, BANDS, COMPONENT_NAMES, ENGINE_ORDER, METRICS, MODEL_NAMES, PART_LABELS, SYSTEMS, THRESHOLDS, VERDICTS,
  fmtBytes, fmtDate, num3, partFor, pct, revealName, splitReasons, verdictInfo, verdictKey,
} from "./data.js";

const pill = (v) => (v ? h("span", { class: `pill v-${verdictKey(v)}` }, verdictInfo(v).titulo) : h("span", { class: "pill none" }, "Sin dato"));
const desgloseItems = (d) => Object.entries(d || {}).map(([k, v]) => ({ label: COMPONENT_NAMES[k] || k, value: Number(v) }));

/* ---------------------------------------------------------------- resultado de un análisis */

const explainCache = new Map();

function explainPanel(api, targets) {
  const panel = h("section", { class: "panel" },
    h("h3", {}, "Qué miró el modelo de IA"),
    h("p", { class: "sub" }, "Cuánto empujó cada rasgo del dominio hacia phishing."));
  if (!targets.length) {
    panel.append(h("p", { class: "note" }, "Este mensaje no tiene un dominio que explicar."));
    return panel;
  }
  const body = h("div");
  const load = async (url) => {
    clear(body).append(h("p", { class: "note" }, "Calculando la explicación…"));
    try {
      if (!explainCache.has(url)) explainCache.set(url, await api.explain(url));
      draw(explainCache.get(url));
    } catch (err) {
      clear(body).append(alertBox(err.message));
    }
  };
  const draw = (exp) => {
    const items = exp.contribuciones.map((c) => ({ label: c.descripcion, hint: c.valor_texto, contribution: Number(c.contribucion) }));
    const prob = pct(exp.probabilidad_phishing);
    const caption = exp.unidad === "puntos porcentuales"
      ? `Dominio analizado: ${exp.dominio} · El modelo parte de ${Number(exp.valor_base).toFixed(0)}% y estima ${prob} de probabilidad de phishing.`
      : `Dominio analizado: ${exp.dominio} · Probabilidad estimada por el modelo: ${prob}.`;
    clear(body).append(
      h("p", { class: "note mono-line" }, caption),
      charts.contributionBars(items),
      h("div", { class: "legend" }, h("span", {}, h("i", { class: "up" }), "sube el riesgo"), h("span", {}, h("i", { class: "down" }), "baja el riesgo")),
      h("p", { class: "note" }, "Explica el modelo de IA por sí solo. El resultado final también considera las reglas, la verificación de red y la reputación del dominio."));
  };
  if (targets.length > 1) {
    const select = h("select", { "aria-label": "Dominio a explicar" }, targets.map((t) => h("option", { value: t }, t)));
    select.addEventListener("change", () => load(select.value));
    panel.append(h("div", { class: "select-row" }, select));
  }
  panel.append(body);
  load(targets[0]);
  return panel;
}

function explainTargets(res) {
  const d = res.data;
  if (res.tipo === "url") return [d.url];
  const targets = [];
  if (d.remitente?.dominio) targets.push(`https://${d.remitente.dominio}`);
  for (const e of d.enlaces || []) targets.push(e.url);
  return [...new Set(targets)];
}

function linksTable(enlaces) {
  const rows = enlaces.map((e) => h("tr", {},
    h("td", { class: "wrap mono" }, e.url), h("td", {}, pill(e.veredicto)),
    h("td", { class: "num" }, e.score == null ? "—" : Math.round(e.score)),
    h("td", { class: "wrap" }, (e.motivos || []).slice(0, 2).join("; "))));
  return h("div", { class: "table-wrap" }, h("table", {},
    h("thead", {}, h("tr", {}, h("th", {}, "Enlace"), h("th", {}, "Veredicto"), h("th", { class: "num" }, "Puntaje"), h("th", {}, "Principales señales"))),
    h("tbody", {}, rows)));
}

/* "Qué hacer": si lo que delata al correo son sus adjuntos, el consejo empieza por ellos. */
function adviceFor(info, d) {
  const risky = (d?.adjuntos || []).some((a) => a.riesgo !== "bajo");
  if (!risky) return info.recomendacion;
  if (d.enlaces?.length) return `No abras los archivos adjuntos. ${info.recomendacion}`;
  return "No abras ni descargues los archivos adjuntos, y no respondas. Si ya abriste alguno, "
    + "desconecta el equipo de la red y avisa al encargado de sistemas.";
}

/* Adjuntos revisados: nombre (con trucos invisibles a la vista), riesgo, tamaño y por qué. */
function attachmentsTable(adjuntos) {
  const rows = adjuntos.map((a) => {
    const r = ATTACH_RISK[a.riesgo] || ATTACH_RISK.bajo;
    return h("tr", {},
      h("td", { class: "wrap mono" }, revealName(a.nombre)),
      h("td", {}, h("span", { class: `pill v-${r.v}` }, r.label)),
      h("td", { class: "num" }, fmtBytes(a.tamano)),
      h("td", { class: "wrap" }, (a.motivos || []).slice(0, 2).join("; ") || "Sin señales de riesgo"));
  });
  return h("div", { class: "table-wrap" }, h("table", {},
    h("thead", {}, h("tr", {}, h("th", {}, "Archivo"), h("th", {}, "Riesgo"), h("th", { class: "num" }, "Tamaño"), h("th", {}, "Por qué"))),
    h("tbody", {}, rows)));
}

/* Líneas que son avisos técnicos, no señales de riesgo: se muestran atenuadas. */
const QUIET = /no disponible|no respondió|sin señales/i;

/* "¿Por qué?" agrupado por la fuente que encontró cada señal (reglas, modelo, red, servicios). */
function reasonsByEngine(porMotor, desglose) {
  const extra = Object.keys(porMotor).filter((k) => !ENGINE_ORDER.includes(k));
  const keys = ENGINE_ORDER.filter((k) => porMotor[k]).concat(extra);
  const groups = keys.map((k) => {
    const has = Object.prototype.hasOwnProperty.call(desglose || {}, k);
    return h("div", { class: "reasons-group" },
      h("div", { class: "rg-head" },
        h("b", {}, COMPONENT_NAMES[k] || k),
        h("span", { class: "rg-score" }, has ? `${Math.round(desglose[k])}/100` : "sin puntaje")),
      h("ul", { class: "reasons" }, porMotor[k].map((m) => h("li", { class: QUIET.test(m) ? "quiet" : null }, m))));
  });
  return h("section", { class: "panel" },
    h("h3", {}, "Por qué"),
    groups);
}

/* Disección del enlace: muestra la URL por partes y pone cada señal debajo de la parte que la provoca. */
function urlDissection(partes, porMotor) {
  const notes = { esquema: [], usuario: [], subdominio: [], dominio: [], puerto: [], ruta: [] };
  for (const engine of ["heuristica", "red"]) {
    for (const m of porMotor[engine] || []) {
      const role = partFor(m);
      if (role && notes[role] && !notes[role].includes(m)) notes[role].push(m);
    }
  }
  const pieces = [
    ["esquema", partes.esquema ? `${partes.esquema}://` : ""],
    ["usuario", partes.usuario ? `${partes.usuario}@` : ""],
    ["subdominio", partes.subdominio ? `${partes.subdominio}.` : ""],
    ["dominio", partes.dominio || ""],
    ["puerto", partes.puerto ? `:${partes.puerto}` : ""],
    ["ruta", partes.ruta || ""],
  ].filter(([, text]) => text);

  const row = h("div", { class: "url-parts" }, pieces.map(([role, text]) => {
    const flagged = notes[role].length > 0;
    return h("div", { class: "part", "data-role": role, "data-flag": String(flagged) },
      h("span", { class: "part-text" }, text),
      h("span", { class: "part-label" }, PART_LABELS[role] || role),
      flagged ? h("ul", { class: "part-notes" }, notes[role].map((n) => h("li", {}, n))) : null);
  }));

  return h("section", { class: "panel dissect" },
    h("h3", {}, "Así se lee este enlace"),
    h("p", { class: "sub" }, "Cada señal aparece debajo de la parte de la dirección que la provoca."),
    h("div", { class: "url-parts-scroll" }, row),
    h("p", { class: "note real-domain" },
      "El sitio al que realmente lleva es ", h("code", {}, partes.dominio || "—"),
      ". Todo lo que está a su izquierda lo elige quien registró ese dominio, aunque mencione el nombre de un banco o una marca."));
}

/* Texto plano del resultado, para el botón "Copiar resumen". */
function summaryText(res) {
  const d = res.data, info = verdictInfo(d.veredicto);
  const target = res.tipo === "url" ? d.url : res.tipo === "correo" ? `Correo: ${d.asunto || "(sin asunto)"}` : "Mensaje analizado";
  const lines = [`PhishShield — ${info.titulo} (${Math.round(d.score)}/100)`, target, "", `Qué hacer: ${adviceFor(info, d)}`];
  const { reasons } = splitReasons(d.motivos || []);
  if (reasons.length) lines.push("", "Señales:", ...reasons.slice(0, 6).map((r) => `• ${r}`));
  return lines.join("\n");
}

/* Acciones sobre el resultado: volver a analizar y copiar el resumen al portapapeles. */
function resultActions(res) {
  const focusInput = () => {
    window.scrollTo({ top: 0, behavior: "smooth" });
    const id = res.tipo === "url" ? "#url-input" : res.tipo === "mensaje" ? "#sms-text" : "#email-subject";
    const el = $(id);
    if (el) el.focus();
  };
  const label = h("span", {}, "Copiar resumen");
  const copyBtn = h("button", { type: "button", class: "btn ghost" }, icon("download"), label);
  copyBtn.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(summaryText(res));
      label.textContent = "¡Copiado!";
    } catch {
      label.textContent = "No se pudo copiar";
    }
    setTimeout(() => { label.textContent = "Copiar resumen"; }, 1800);
  });
  return h("div", { class: "result-actions" },
    h("button", { type: "button", class: "btn ghost", onclick: focusInput }, icon("scan"), "Analizar otro"),
    copyBtn);
}

function senderPanel(d) {
  const r = d.remitente || {};
  return h("section", { class: "panel" },
    h("h3", {}, "Datos del correo"),
    h("div", { class: "sender" },
      h("div", {}, h("span", { class: "muted" }, "Remitente: "), h("span", { class: "mono" }, r.direccion ? `${r.nombre || ""} <${r.direccion}>`.trim() : "no identificado")),
      h("div", {}, h("span", { class: "muted" }, "Asunto: "), d.asunto || "(sin asunto)")));
}

function flatReasons(reasons, services) {
  return h("section", { class: "panel" },
    h("h3", {}, "Por qué"),
    h("ul", { class: "reasons" }, reasons.map((r) => h("li", {}, r))),
    services.length ? h("p", { class: "note" }, `Servicios opcionales sin configurar: ${services.join(", ")}.`) : null);
}

export function renderResult(root, res, api) {
  const d = res.data, v = verdictKey(d.veredicto), info = VERDICTS[v];
  const { reasons, services } = splitReasons(d.motivos || []);
  const porMotor = d.motivos_por_motor || {};
  const grouped = res.tipo === "url" && Object.keys(porMotor).length > 0;

  // En lenguaje simple y sin avisos técnicos: lo que el usuario necesita ver de un vistazo.
  const topSignals = reasons.filter((r) => !QUIET.test(r)).slice(0, 3);
  const metaBits = [];
  if (d.confianza != null) metaBits.push(`Confianza ${pct(d.confianza)}`);
  if (d.tiempo_ms) metaBits.push(`${(d.tiempo_ms / 1000).toFixed(2).replace(".", ",")} s`);

  // 1) La respuesta: veredicto, qué hacer y las señales principales. Nada que haya que descifrar.
  const hero = h("div", { class: "hero" },
    charts.gauge(d.score),
    h("div", { class: "verdict" },
      h("h2", { class: "verdict-headline" }, info.titular),
      h("p", { class: "verdict-sum" }, info.resumen),
      metaBits.length ? h("p", { class: "verdict-meta" }, metaBits.join(" · ")) : null,
      h("div", { class: "todo" }, h("b", {}, "Qué hacer"), adviceFor(info, d)),
      topSignals.length
        ? h("div", { class: "signals" },
            h("h3", {}, "Señales principales"),
            h("ul", {}, topSignals.map((r) => h("li", {}, r))))
        : null));

  // 2) El detalle técnico, plegado: está para quien quiera mirarlo, no estorba a quien no.
  const body = h("div", { class: "more-body" });
  if (res.tipo === "url" && d.partes) body.append(urlDissection(d.partes, porMotor));
  if (res.tipo === "correo") body.append(senderPanel(d));
  body.append(grouped ? reasonsByEngine(porMotor, d.desglose) : flatReasons(reasons, services));
  const bars = desgloseItems(d.desglose);
  if (bars.length) body.append(h("section", { class: "panel" }, h("h3", {}, "De dónde sale el puntaje"), charts.scoreBars(bars)));
  if (res.tipo !== "url") {
    body.append(h("section", { class: "panel" }, h("h3", {}, "Enlaces encontrados"),
      d.enlaces?.length ? linksTable(d.enlaces) : h("p", { class: "note" }, "El mensaje no contiene enlaces.")));
  }
  if (res.tipo === "correo" && d.adjuntos?.length) {
    body.append(h("section", { class: "panel" }, h("h3", {}, "Archivos adjuntos"),
      h("p", { class: "sub" }, "Se revisan sin abrirlos ni ejecutarlos: nombre, tipo y firma del contenido."),
      attachmentsTable(d.adjuntos)));
  }
  body.append(explainPanel(api, explainTargets(res)));

  const detail = h("details", { class: "more" }, h("summary", {}, "Ver el análisis completo"), body);

  clear(root).append(h("div", { class: `result v-${v}` }, hero, resultActions(res), detail));
}

/* ---------------------------------------------------------------- bandeja del servidor propio */

/* Lista los correos que llegan al buzón IMAP, ya clasificados. `onOpen(uid)` abre el detalle. */
export function createInbox(root, api, onOpen) {
  let data = { configurada: true, correos: [], buzon: "INBOX", cuarentena: "Phishing", cuentas: [], cuenta: "" };
  let autoQuarantine = false, busy = false, account = "";
  const moved = new Set();                       // evita reintentar el mismo correo en cada refresco

  const setup = () => clear(root).append(h("div", { class: "alert info" }, icon("info"),
    h("span", {}, "La bandeja no está conectada a un servidor de correo. Funciona cuando PhishShield corre en la misma red que el servidor del laboratorio: agrega sus datos en el archivo ",
      h("code", {}, ".env"), " (", h("code", {}, "PD_IMAP_HOST"), " y ", h("code", {}, "PD_IMAP_ACCOUNTS"),
      ") y reinicia el detector. En la versión publicada en internet no está disponible, porque el servidor de correo vive en una red privada; el resto de funciones sí.")));

  const draw = () => {
    if (!data.configurada) return setup();
    const rows = data.correos;
    const counts = { seguro: 0, sospechoso: 0, phishing: 0 };
    rows.forEach((r) => { counts[verdictKey(r.veredicto)] += 1; });

    const kpi = (label, n, v) => h("div", { class: `kpi${v ? ` v-${v}` : ""}` },
      h("div", { class: "k" }, label), h("div", { class: "v" }, String(n)));

    const body = rows.map((r) => {
      const v = verdictKey(r.veredicto);
      const rem = r.remitente || {};
      const from = rem.nombre
        ? `${rem.nombre} <${rem.direccion || ""}>`.replace(" <>", "")
        : (rem.direccion || "remitente desconocido");
      const open = () => onOpen(r.uid, account);
      const action = v === "phishing"
        ? h("button", {
            type: "button", class: "btn ghost tiny",
            onclick: (e) => { e.stopPropagation(); move(r.uid); },
          }, "A cuarentena")
        : null;
      return h("tr", { class: "click", tabindex: "0", onclick: open,
        onkeydown: (e) => { if (e.key === "Enter") open(); } },
        h("td", {}, pill(r.veredicto)),
        h("td", { class: "wrap" }, h("div", { class: "subj" }, r.asunto,
          r.adjuntos
            ? h("span", {
                class: `clip${r.adjuntos_riesgo ? " danger" : ""}`,
                title: r.adjuntos_riesgo ? `${r.adjuntos_riesgo} adjunto(s) riesgoso(s)` : `${r.adjuntos} adjunto(s)`,
              }, icon("clip"), String(r.adjuntos))
            : null),
          h("div", { class: "muted mono from" }, from)),
        h("td", { class: "num" }, String(Math.round(r.score))),
        h("td", {}, r.fecha ? fmtDate(r.fecha) : "—"),
        h("td", { class: "row-action" }, action));
    });

    const cuentas = data.cuentas || [];
    let picker = null;
    if (cuentas.length) {
      const select = h("select", { "aria-label": "Buzón a leer" },
        cuentas.map((c) => h("option", { value: c.id, selected: c.id === account || null }, c.nombre)));
      select.addEventListener("change", () => { account = select.value; refresh(); });
      picker = h("div", { class: "mailbox-picker" },
        h("label", { class: "mp-label" }, icon("mail"), "Buzón:"), select);
    }

    clear(root).append(
      picker,
      h("div", { class: "kpis" },
        kpi("Correos en el buzón", rows.length),
        kpi("Phishing", counts.phishing, "phishing"),
        kpi("Sospechosos", counts.sospechoso, "sospechoso"),
        kpi("Seguros", counts.seguro, "seguro")),
      h("label", { class: "check" },
        h("input", { type: "checkbox", checked: autoQuarantine || null,
          onchange: (e) => { autoQuarantine = e.target.checked; if (autoQuarantine) sweep(); } }),
        `Mover automáticamente lo que sea phishing a la carpeta "${data.cuarentena}"`),
      rows.length
        ? h("div", { class: "table-wrap" }, h("table", { class: "inbox" },
            h("thead", {}, h("tr", {}, h("th", {}, "Veredicto"), h("th", {}, "Correo"),
              h("th", { class: "num" }, "Puntaje"), h("th", {}, "Fecha"), h("th", {}))),
            h("tbody", {}, body)))
        : h("div", { class: "alert info" }, icon("info"),
            h("span", {}, "El buzón está vacío. Envía un correo desde otra cuenta y aparecerá aquí.")));
  };

  const move = async (uid) => {
    moved.add(uid);
    try {
      await api.quarantine(uid, account || undefined);
      data.correos = data.correos.filter((c) => c.uid !== uid);
      draw();
    } catch (err) {
      clear(root).append(alertBox(err.message));
    }
  };

  /* Con el automático encendido, saca de la bandeja todo lo que dio phishing. */
  const sweep = async () => {
    for (const c of data.correos.filter((x) => verdictKey(x.veredicto) === "phishing" && !moved.has(x.uid))) {
      await move(c.uid);
    }
  };

  const refresh = async (quiet = false) => {
    if (busy) return;
    busy = true;
    if (!quiet && !root.firstChild) root.append(h("p", { class: "note" }, "Leyendo el buzón… La primera vez puede tardar un poco mientras analiza cada correo; luego es instantáneo."));
    try {
      data = await api.inbox(20, account || undefined);
      if (!account && data.cuenta) account = data.cuenta;
      draw();
      if (autoQuarantine) await sweep();
    } catch (err) {
      if (!quiet || !root.firstChild) clear(root).append(alertBox(err.message));
    } finally {
      busy = false;
    }
  };

  return { refresh };
}

/* Ruta que siguió el correo (cabeceras Received), del origen al destino. */
function routePanel(ruta) {
  if (!ruta || !ruta.saltos || !ruta.saltos.length) return null;
  const hops = ruta.saltos.map((hop, i) => h("li", {}, h("span", { class: "hop-n" }, String(i + 1)), h("span", { class: "mono" }, hop)));
  const nota = ruta.paso_por_internet
    ? "El correo pasó por servidores de internet, como un correo normal."
    : "El correo no pasó por ningún servidor de internet: se entregó solo dentro de la red local.";
  return [h("h4", { class: "gap" }, "Ruta del correo"),
    h("ol", { class: "route" }, hops),
    h("p", { class: "note" }, nota)];
}

/* Detalle de un correo de la bandeja, dentro del diálogo. */
export async function openInboxMessage(api, uid, cuenta) {
  const dialog = $("#detail"), body = clear($("#detail-body"));
  body.append(h("p", { class: "note" }, "Cargando…"));
  if (!dialog.open) dialog.showModal();
  try {
    const d = await api.inboxMessage(uid, cuenta);
    const v = verdictKey(d.veredicto), info = VERDICTS[v];
    const r = d.remitente || {};
    const { reasons } = splitReasons(d.motivos || []);
    const bars = desgloseItems(d.desglose);
    clear(body).append(h("div", { class: `v-${v}` },
      h("div", { class: "meta" },
        h("div", {}, pill(d.veredicto), `  ${Math.round(d.score)}/100`),
        h("div", { class: "mono" }, r.direccion ? `${r.nombre || ""} <${r.direccion}>`.trim() : "remitente no identificado"),
        h("div", {}, d.asunto || "(sin asunto)")),
      h("div", { class: "todo" }, h("b", {}, "Qué hacer"), adviceFor(info, d)),
      h("h4", { class: "gap" }, "Por qué"),
      h("ul", { class: "reasons" }, reasons.map((x) => h("li", {}, x))),
      // El desglose deja ver de dónde sale cada punto, incluso cuando ninguna señal
      // llegó al umbral para aparecer en la lista de arriba.
      bars.length ? [h("h4", { class: "gap" }, "De dónde sale el puntaje"), charts.scoreBars(bars)] : null,
      d.enlaces?.length ? [h("h4", { class: "gap" }, "Enlaces encontrados"), linksTable(d.enlaces)] : null,
      d.adjuntos?.length ? [h("h4", { class: "gap" }, "Archivos adjuntos"), attachmentsTable(d.adjuntos)] : null,
      routePanel(d.ruta)));
  } catch (err) {
    clear(body).append(alertBox(err.message));
  }
}

/* ---------------------------------------------------------------- historial */

const csvCell = (value) => {
  let text = String(value ?? "");
  if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;           // evita inyección de fórmulas en Excel
  return `"${text.replaceAll('"', '""')}"`;
};

/* Panel: resumen visual calculado en el navegador a partir del historial (/api/analyses).
   No necesita endpoints nuevos: agrega lo que ya se guardó en cada análisis. */
const VERDICT_COLOR = { seguro: "var(--ok)", sospechoso: "var(--warn)", phishing: "var(--bad)" };
const TYPE_OF = (u) => (u || "").startsWith("correo:") ? "correo" : (u || "").startsWith("mensaje:") ? "mensaje" : "enlace";

export async function renderDashboard(root, api) {
  clear(root).append(h("p", { class: "note" }, "Cargando panel…"));
  let rows;
  try {
    rows = await api.history();
  } catch (err) {
    clear(root).append(alertBox(err.message));
    return;
  }

  const total = rows.length;
  if (!total) {
    clear(root).append(h("div", { class: "alert info" }, icon("info"),
      h("span", {}, "Aún no hay análisis. Analiza un enlace o un correo y el panel se irá llenando con estadísticas.")));
    return;
  }

  const counts = { seguro: 0, sospechoso: 0, phishing: 0 };
  const types = { enlace: 0, correo: 0, mensaje: 0 };
  let scoreSum = 0;
  const dayCount = {};
  const dkey = (d) => `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`;
  rows.forEach((r) => {
    counts[verdictKey(r.veredicto)] += 1;
    types[TYPE_OF(r.url)] += 1;
    scoreSum += Number(r.score) || 0;
    const d = new Date(r.created_at);
    if (!isNaN(d)) { d.setHours(0, 0, 0, 0); dayCount[dkey(d)] = (dayCount[dkey(d)] || 0) + 1; }
  });
  const avg = scoreSum / total;

  const today = new Date(); today.setHours(0, 0, 0, 0);
  const days = [];
  for (let i = 9; i >= 0; i -= 1) { const d = new Date(today); d.setDate(d.getDate() - i); days.push(d); }
  const colItems = days.map((d) => ({ label: `${d.getDate()}/${d.getMonth() + 1}`, value: dayCount[dkey(d)] || 0 }));

  const kpi = (label, n, v, sub) => h("div", { class: `kpi${v ? ` v-${v}` : ""}` },
    h("div", { class: "k" }, label), h("div", { class: "v" }, String(n)), sub ? h("div", { class: "s" }, sub) : null);

  const legend = h("div", { class: "donut-legend" }, ["phishing", "sospechoso", "seguro"].map((k) =>
    h("div", { class: "lg-item" },
      h("i", { vars: { background: VERDICT_COLOR[k] } }),
      h("span", { class: "lg-l" }, verdictInfo(k).titulo),
      h("span", { class: "lg-n" }, String(counts[k])))));

  const donutSegs = [
    { value: counts.phishing, color: VERDICT_COLOR.phishing },
    { value: counts.sospechoso, color: VERDICT_COLOR.sospechoso },
    { value: counts.seguro, color: VERDICT_COLOR.seguro },
  ];

  const typeItems = [
    { label: "Enlaces", value: types.enlace, color: "var(--accent)" },
    { label: "Correos", value: types.correo, color: "var(--accent2)" },
    { label: "Mensajes", value: types.mensaje, color: "#5eb8a0" },
  ];

  const avgBand = avg >= BANDS.phishing ? "phishing" : avg >= BANDS.sospechoso ? "sospechoso" : "seguro";

  clear(root).append(
    h("div", { class: "kpis" },
      kpi("Análisis en total", total, "", `${pct(counts.phishing / total)} fueron phishing`),
      kpi("Phishing", counts.phishing, "phishing"),
      kpi("Sospechosos", counts.sospechoso, "sospechoso"),
      kpi("Seguros", counts.seguro, "seguro")),
    h("div", { class: "grid-2" },
      h("div", { class: "panel" },
        h("h3", {}, "Actividad por día"),
        h("p", { class: "sub" }, "Análisis realizados en los últimos 10 días."),
        charts.columns(colItems)),
      h("div", { class: "panel" },
        h("h3", {}, "Distribución de veredictos"),
        h("p", { class: "sub" }, "Cómo se repartieron todos los análisis."),
        h("div", { class: "donut-panel" }, charts.donut(donutSegs), legend))),
    h("div", { class: "grid-2" },
      h("div", { class: "panel" },
        h("h3", {}, "Por tipo de análisis"),
        h("p", { class: "sub" }, "Qué se revisó: enlaces, correos o mensajes de texto."),
        charts.countBars(typeItems)),
      h("div", { class: `panel v-${avgBand}` },
        h("h3", {}, "Riesgo promedio"),
        h("p", { class: "sub" }, "Puntaje medio de todos los análisis guardados."),
        charts.gauge(avg))));
}

/* Prueba real: matriz de confusión con los correos reales que pasaron por el detector.
   El usuario marca la "verdad" (legítimo / phishing) de cada correo; se guarda en este
   navegador (localStorage) y la matriz + métricas se recalculan en vivo. Sin cambios en el backend. */
const TRUTH_KEY = (id) => `pd_truth_${id}`;
function getTruth(id) { try { return localStorage.getItem(TRUTH_KEY(id)) || ""; } catch { return ""; } }
function setTruth(id, val) {
  try { if (val) localStorage.setItem(TRUTH_KEY(id), val); else localStorage.removeItem(TRUTH_KEY(id)); } catch { /* sin almacenamiento */ }
}

export async function renderRealEval(root, api) {
  clear(root).append(h("p", { class: "note" }, "Cargando correos analizados…"));
  let rows;
  try {
    rows = (await api.history()).sort((a, b) => b.id - a.id);
  } catch (err) {
    clear(root).append(alertBox(err.message));
    return;
  }

  let scope = "correo"; // "correo" = solo correos del servidor; "todos" = cualquier análisis

  const draw = () => {
    const items = scope === "correo" ? rows.filter((r) => TYPE_OF(r.url) === "correo") : rows;

    let tp = 0, fp = 0, fn = 0, tn = 0, labeled = 0;
    items.forEach((r) => {
      const t = getTruth(r.id);
      if (!t) return;
      labeled += 1;
      const flagged = verdictKey(r.veredicto) !== "seguro"; // el detector lo marcó (sospechoso o phishing)
      const realPhish = t === "phishing";
      if (flagged && realPhish) tp += 1;
      else if (flagged && !realPhish) fp += 1;
      else if (!flagged && realPhish) fn += 1;
      else tn += 1;
    });

    const safeDiv = (a, b) => (b ? a / b : null);
    const acc = safeDiv(tp + tn, labeled);
    const prec = safeDiv(tp, tp + fp);
    const rec = safeDiv(tp, tp + fn);
    const f1 = (prec != null && rec != null && prec + rec > 0) ? (2 * prec * rec) / (prec + rec) : null;
    const show = (x) => (x == null ? "—" : pct(x, 1));

    const metric = (label, value, sub) => h("div", { class: "kpi" },
      h("div", { class: "k" }, label), h("div", { class: "v" }, value), sub ? h("div", { class: "s" }, sub) : null);

    const cell = (value, total, good) => h("div", { class: `cell ${good ? "good" : "bad"}`, vars: { "--ci": `${15 + 55 * (value / (total || 1))}%` } },
      h("b", {}, String(value)), total ? `${(100 * value / total).toFixed(0)}%` : "0%");
    const legitRow = tn + fp, phishRow = fn + tp;
    const matrix = h("div", { class: "cm" },
      h("span"), h("span", { class: "h" }, "Predicho: legítimo"), h("span", { class: "h" }, "Predicho: phishing"),
      h("span", { class: "h" }, "Real: legítimo"), cell(tn, legitRow, true), cell(fp, legitRow, false),
      h("span", { class: "h" }, "Real: phishing"), cell(fn, phishRow, false), cell(tp, phishRow, true));

    // Control de alcance (correos / todos)
    const scopeChip = (key, label) => h("button", { type: "button", class: `chip${scope === key ? " active" : ""}`,
      onclick: () => { scope = key; draw(); } }, label);

    // Fila de etiquetado
    const truthBtn = (r, val, label, cls) => {
      const on = getTruth(r.id) === val;
      return h("button", { type: "button", class: `truth-btn ${cls}${on ? " on" : ""}`,
        "aria-pressed": String(on),
        onclick: () => { setTruth(r.id, on ? "" : val); draw(); } }, label);
    };
    const body = items.map((r) => {
      const subject = (r.url || "").replace(/^correo:\s*/, "").replace(/^mensaje:\s*/, "");
      return h("tr", {},
        h("td", { class: "subj-cell" }, subject || "(sin asunto)"),
        h("td", {}, pill(r.veredicto)),
        h("td", { class: "truth-cell" },
          h("div", { class: "truth-btns" }, truthBtn(r, "legit", "Legítimo", "legit"), truthBtn(r, "phishing", "Phishing", "phish"))));
    });

    const anyLabeled = labeled > 0;
    const resetBtn = h("button", { type: "button", class: "btn ghost tiny",
      onclick: () => { items.forEach((r) => setTruth(r.id, "")); draw(); } }, "Reiniciar etiquetas");

    clear(root).append(
      h("div", { class: "chips scope-chips" }, scopeChip("correo", "Solo correos"), scopeChip("todos", "Todos los análisis")),
      h("div", { class: "kpis" },
        metric("Exactitud", show(acc), "aciertos / total etiquetado"),
        metric("Precisión", show(prec), "de lo marcado, cuánto era phishing"),
        metric("Sensibilidad", show(rec), "del phishing real, cuánto detectó"),
        metric("Puntaje F1", show(f1), "equilibrio precisión/sensibilidad")),
      h("div", { class: "grid-2" },
        h("div", { class: "panel" },
          h("h3", {}, "Marca la verdad de cada correo"),
          h("p", { class: "sub" }, "Tú sabes cuáles enviaste como phishing y cuáles como correo normal. Márcalo aquí; se guarda en este navegador."),
          items.length
            ? h("div", { class: "table-wrap" }, h("table", { class: "truth-table" },
                h("thead", {}, h("tr", {}, h("th", {}, "Asunto"), h("th", {}, "Detector"), h("th", {}, "Verdad real"))),
                h("tbody", {}, body)))
            : h("div", { class: "alert info" }, icon("info"), h("span", {}, "Aún no hay correos analizados. Ve a la Bandeja, analiza los correos de prueba y vuelve aquí.")),
          items.length ? h("div", { class: "note-row" }, resetBtn) : null),
        h("div", { class: "panel" },
          h("h3", {}, "Matriz de confusión"),
          h("p", { class: "sub" }, "Se considera que el detector “marcó” un correo cuando su veredicto fue Sospechoso o Phishing."),
          anyLabeled ? matrix : h("div", { class: "alert info" }, icon("info"), h("span", {}, "Marca al menos un correo para empezar a construir la matriz.")),
          h("p", { class: "note" }, `${labeled} de ${items.length} correos etiquetados.`))));
  };

  draw();
}

export function createHistory(root, api, onOpen) {
  let rows = [], filter = "todos";

  const draw = () => {
    const counts = { seguro: 0, sospechoso: 0, phishing: 0 };
    rows.forEach((r) => { counts[verdictKey(r.veredicto)] += 1; });
    const visible = filter === "todos" ? rows : rows.filter((r) => verdictKey(r.veredicto) === filter);

    const kpi = (label, n, v) => h("div", { class: `kpi${v ? ` v-${v}` : ""}` }, h("div", { class: "k" }, label), h("div", { class: "v" }, String(n)));
    const chip = (key, label, n) => h("button", {
      type: "button", class: `chip${filter === key ? " active" : ""}`, onclick: () => { filter = key; draw(); },
    }, label, h("span", { class: "n" }, String(n)));

    const body = visible.map((r) => h("tr", { class: "click", tabindex: "0", onclick: () => onOpen(r.id),
      onkeydown: (e) => { if (e.key === "Enter") onOpen(r.id); } },
      h("td", { class: "num" }, String(r.id)), h("td", { class: "wrap mono" }, r.url), h("td", {}, pill(r.veredicto)),
      h("td", { class: "num" }, String(Math.round(r.score))), h("td", { class: "num" }, pct(r.confianza)), h("td", {}, fmtDate(r.created_at))));

    clear(root).append(
      h("div", { class: "kpis" }, kpi("Análisis guardados", rows.length), kpi("Seguros", counts.seguro, "seguro"),
        kpi("Sospechosos", counts.sospechoso, "sospechoso"), kpi("Phishing", counts.phishing, "phishing")),
      h("div", { class: "chips" }, chip("todos", "Todos", rows.length), chip("seguro", "Seguros", counts.seguro),
        chip("sospechoso", "Sospechosos", counts.sospechoso), chip("phishing", "Phishing", counts.phishing)),
      rows.length
        ? h("div", { class: "table-wrap" }, h("table", {},
          h("thead", {}, h("tr", {}, h("th", { class: "num" }, "N°"), h("th", {}, "Qué se analizó"), h("th", {}, "Veredicto"),
            h("th", { class: "num" }, "Puntaje"), h("th", { class: "num" }, "Confianza"), h("th", {}, "Fecha"))),
          h("tbody", {}, body)))
        : h("div", { class: "alert info" }, icon("info"), h("span", {}, "Todavía no hay análisis guardados. Analiza un enlace, un correo o un mensaje y aparecerá aquí.")));
  };

  return {
    async refresh() {
      clear(root).append(h("p", { class: "note" }, "Cargando historial…"));
      try {
        rows = (await api.history()).sort((a, b) => b.id - a.id);
        draw();
      } catch (err) {
        clear(root).append(alertBox(err.message));
      }
    },
    csv() {
      const lines = [["id", "qué se analizó", "veredicto", "puntaje", "confianza", "fecha"].map(csvCell).join(",")];
      rows.forEach((r) => lines.push([r.id, r.url, r.veredicto, r.score, r.confianza, r.created_at].map(csvCell).join(",")));
      return lines.join("\n");
    },
  };
}

export async function openDetail(api, id) {
  const dialog = $("#detail"), body = clear($("#detail-body"));
  body.append(h("p", { class: "note" }, "Cargando…"));
  if (!dialog.open) dialog.showModal();
  try {
    const d = await api.historyItem(id);
    const v = verdictKey(d.veredicto), { reasons, services } = splitReasons(d.motivos || []);
    const bars = desgloseItems(d.desglose);
    clear(body).append(h("div", { class: `v-${v}` },
      h("div", { class: "meta" },
        h("div", { class: "mono" }, d.url), h("div", { class: "muted" }, `Análisis N° ${d.id} · ${fmtDate(d.created_at)}`),
        h("div", {}, pill(d.veredicto), `  Puntaje ${Math.round(d.score)}/100 · Confianza ${pct(d.confianza)}`)),
      h("h4", {}, "Motivos"), h("ul", { class: "reasons" }, reasons.map((r) => h("li", {}, r))),
      services.length ? h("p", { class: "note" }, `Servicios opcionales sin configurar: ${services.join(", ")}.`) : null,
      bars.length ? [h("h4", { class: "gap" }, "Composición del puntaje"), charts.scoreBars(bars)] : null));
  } catch (err) {
    clear(body).append(alertBox(err.message));
  }
}

/* ---------------------------------------------------------------- evaluación */

const best = (values) => Math.max(...values);

export async function renderEvaluation(root, api) {
  clear(root).append(h("p", { class: "note" }, "Cargando evaluación…"));
  let data;
  try {
    data = await api.evaluation();
  } catch (err) {
    clear(root).append(alertBox(err.message));
    return;
  }
  const ev = data.evaluacion, model = data.modelo, labels = data.etiquetas || {};
  if (!ev) {
    clear(root).append(h("div", { class: "alert info" }, icon("info"),
      h("span", {}, "Todavía no se generó el reporte de evaluación. Corre en la terminal: ", h("code", {}, "python scripts/evaluate.py"))));
    return;
  }

  let threshold = THRESHOLDS[0].key, cmSystem = SYSTEMS[3].key;
  const tableHost = h("div"), barsHost = h("div"), cmHost = h("div"), tabs = h("div", { class: "seg small", role: "tablist" });

  const drawThreshold = () => {
    const rows = SYSTEMS.map((sys) => ({ sys, r: ev.sistemas[sys.key] }));
    const cols = [...METRICS.map((m) => ({ ...m, get: (x) => x.r[threshold][m.key] })), { key: "auc", name: "AUC-ROC", get: (x) => x.r.auc }];
    const top = cols.map((c) => best(rows.map(c.get)));
    clear(tableHost).append(h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, h("th", {}, "Sistema"), cols.map((c) => h("th", { class: "num" }, c.name)))),
      h("tbody", {}, rows.map((x) => h("tr", {}, h("td", {}, x.sys.name),
        cols.map((c, i) => h("td", { class: `num${c.get(x) === top[i] ? " best" : ""}` }, num3(c.get(x))))))))));
    const values = {};
    cols.forEach((c) => { values[c.key] = rows.map(c.get); });
    clear(barsHost).append(charts.groupedBars(cols, values),
      h("div", { class: "sys-legend" }, SYSTEMS.map((sys, i) => h("span", { class: `sys-btn s${i}${sys.dash ? " dash" : ""}` }, h("i"), sys.name))));
    markTabs();
  };
  const markTabs = () => tabs.querySelectorAll(".seg-item").forEach((b) => b.classList.toggle("active", b.dataset.key === threshold));
  THRESHOLDS.forEach((t) => tabs.append(h("button", { type: "button", class: "seg-item", "data-key": t.key,
    onclick: () => { threshold = t.key; drawThreshold(); drawMatrix(); } }, `${t.label} (${t.desc})`)));

  const drawMatrix = () => {
    const m = ev.sistemas[cmSystem][threshold].matriz;
    const cell = (value, total, good) => h("div", { class: `cell ${good ? "good" : "bad"}`, vars: { "--ci": `${15 + 55 * (value / (total || 1))}%` } },
      h("b", {}, value.toLocaleString("es-CO")), `${(100 * value / (total || 1)).toFixed(1)}%`);
    const legit = m.tn + m.fp, phish = m.fn + m.tp;
    clear(cmHost).append(h("div", { class: "cm" },
      h("span"), h("span", { class: "h" }, "Predicho: legítima"), h("span", { class: "h" }, "Predicho: phishing"),
      h("span", { class: "h" }, "Real: legítima"), cell(m.tn, legit, true), cell(m.fp, legit, false),
      h("span", { class: "h" }, "Real: phishing"), cell(m.fn, phish, false), cell(m.tp, phish, true)));
  };
  const cmSelect = h("select", { "aria-label": "Sistema" }, SYSTEMS.map((sys) => h("option", { value: sys.key, selected: sys.key === cmSystem }, sys.name)));
  cmSelect.addEventListener("change", () => { cmSystem = cmSelect.value; drawMatrix(); });

  const roc = charts.rocChart(SYSTEMS.map((sys) => ev.sistemas[sys.key].roc));
  const chosen = model?.modelo_elegido;
  const kpi = (label, value, sub) => h("div", { class: "kpi" }, h("div", { class: "k" }, label), h("div", { class: "v" }, value), h("div", { class: "s" }, sub));
  const kpis = h("div", { class: "kpis" },
    chosen ? kpi("Accuracy del modelo ML", pct(model.test[chosen].accuracy, 1), "en dominios que no vio") : null,
    chosen ? kpi("F1 del modelo ML", num3(model.test[chosen].f1), MODEL_NAMES[chosen] || chosen) : null,
    kpi("AUC-ROC combinado", num3(ev.sistemas.combinado_url_completa.auc), "reglas + modelo de IA"),
    kpi("URLs evaluadas", ev.filas_test.toLocaleString("es-CO"), `${ev.phishing_test.toLocaleString("es-CO")} phishing · ${ev.legitimas_test.toLocaleString("es-CO")} legítimas`));

  clear(root).append(
    kpis,
    h("section", { class: "panel" },
      h("h3", {}, "Reglas vs modelo de IA vs combinado"),
      h("p", { class: "sub" }, "Sobre dominios que el modelo no vio durante el entrenamiento. No incluye la verificación de red ni servicios externos, que dependen de consultas en vivo. En verde, el mejor valor de cada columna."),
      tabs, tableHost),
    h("div", { class: "grid-eq" },
      h("section", { class: "panel" }, h("h3", {}, "Métricas por sistema"), barsHost),
      h("section", { class: "panel" }, h("h3", {}, "Curvas ROC"), h("p", { class: "sub" }, "Toca un sistema en la leyenda para ocultarlo."), roc.element, roc.legend)),
    h("section", { class: "panel" }, h("h3", {}, "Matriz de confusión"),
      h("div", { class: "select-row" }, cmSelect), cmHost));

  if (model) {
    const rows = Object.keys(MODEL_NAMES).filter((k) => model.test[k]);
    const importance = Object.entries(model.importancia_features || {}).sort((a, b) => b[1] - a[1]).slice(0, 10)
      .map(([k, v]) => ({ label: labels[k] || k, value: v }));
    root.append(...[
      h("section", { class: "panel" }, h("h3", {}, "Regresión Logística vs Random Forest"),
        h("p", { class: "sub" }, "El modelo se elige por F1 en validación cruzada agrupada por dominio."),
        h("div", { class: "table-wrap" }, h("table", {},
          h("thead", {}, h("tr", {}, ["Modelo", "F1 validación cruzada", "Accuracy test", "Precisión test", "Recall test", "F1 test", "AUC test"].map((t, i) => h("th", { class: i ? "num" : "" }, t)))),
          h("tbody", {}, rows.map((k) => h("tr", {}, h("td", {}, MODEL_NAMES[k] + (k === chosen ? " ✔ elegido" : "")),
            [model.cv[k].f1, model.test[k].accuracy, model.test[k].precision, model.test[k].recall, model.test[k].f1, model.test[k].auc]
              .map((x) => h("td", { class: "num" }, num3(x))))))))),
      importance.length ? h("section", { class: "panel" }, h("h3", {}, "Características más importantes del modelo"),
        charts.scoreBars(importance, Math.max(...importance.map((i) => i.value)), (v) => v.toFixed(3))) : null,
    ].filter(Boolean));
  }

  root.append(h("section", { class: "panel" }, h("h3", {}, "Limitaciones que conviene conocer"),
    h("ul", { class: "list" },
      h("li", {}, h("b", {}, "El dataset tiene atajos. "), "En PhiUSIIL todas las URLs legítimas son https://www.dominio sin ruta. Un modelo que mira la URL completa llega a ~99% de accuracy, pero solo aprendió ese patrón. Por eso el modelo mira únicamente la estructura del dominio."),
      h("li", {}, h("b", {}, "Los subdominios legítimos parecen sospechosos "), "(el dataset casi no tiene) y se mitiga con una lista de dominios de reputación."),
      h("li", {}, h("b", {}, "El test es optimista "), "frente a tráfico real: las legítimas del dataset son sitios sin subdominio."),
      h("li", {}, "Un atacante puede alojar phishing en servicios legítimos o registrar dominios con buena apariencia."))));
  drawThreshold();
  drawMatrix();
}

/* ---------------------------------------------------------------- cómo funciona */

export function renderHow(root) {
  const node = (title, text, cls = "") => h("div", { class: `node ${cls}`.trim() }, h("b", {}, title), h("span", {}, text));
  const band = (key, range) => h("div", { class: `band v-${key}` }, h("h4", {}, VERDICTS[key].titulo), h("div", { class: "rng" }, range),
    h("p", {}, VERDICTS[key].resumen), h("p", { class: "muted" }, VERDICTS[key].recomendacion));
  clear(root).append(
    h("section", { class: "panel" }, h("h3", {}, "Del enlace al veredicto"),
      h("p", { class: "sub" }, "Cada fuente aporta un puntaje de riesgo y un combinador ponderado los une en un número de 0 a 100."),
      h("div", { class: "flow" },
        h("div", { class: "flow-col" }, node("Enlace", "Una URL directa"), node("Correo", "Remitente, enlaces, adjuntos y señales del mensaje"), node("Mensaje (SMS)", "Texto y enlaces que contiene")),
        h("div", { class: "arrow" }, "→"),
        h("div", { class: "flow-col" },
          node("Reglas heurísticas", "IP en vez de dominio, @ en la dirección, terminaciones abusadas, acortadores, palabras que piden credenciales, imitación de marcas"),
          node("Verificación de red", "Si el dominio existe, certificado válido, antigüedad (RDAP), redirecciones y formularios de contraseña"),
          node("Modelo de IA", "Clasificador entrenado con ~235 000 URLs reales (PhiUSIIL), explicado con SHAP"),
          node("Reputación", "Para sitios muy conocidos se reduce el peso del modelo")),
        h("div", { class: "arrow" }, "→"),
        h("div", { class: "flow-col" }, node("Puntaje 0–100", "Combinación ponderada de las fuentes disponibles", "core"), node("Veredicto", "Seguro, sospechoso o phishing, con motivos y qué hacer", "core")))),
    h("section", { class: "panel" }, h("h3", {}, "Qué significa cada categoría"),
      h("div", { class: "bands" }, band("seguro", `0 – ${BANDS.sospechoso - 1}`), band("sospechoso", `${BANDS.sospechoso} – ${BANDS.phishing - 1}`), band("phishing", `${BANDS.phishing} – 100`))),
    h("section", { class: "panel" }, h("h3", {}, "Privacidad y seguridad"),
      h("ul", { class: "list" },
        h("li", {}, "Los archivos adjuntos nunca se abren ni se ejecutan: solo se revisan su nombre, su tipo y la firma de su contenido."),
        h("li", {}, "No se conecta a direcciones privadas ni locales aunque se las pidan (protección SSRF)."),
        h("li", {}, "Los análisis se guardan en el historial del servidor; no se envían a terceros salvo los servicios opcionales que tú configures."),
        h("li", {}, "Ninguna herramienta es infalible: ante la duda, confirma con la entidad por otro canal."))));
}
