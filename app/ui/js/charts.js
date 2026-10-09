/* Gráficos hechos a mano (SVG y CSS), sin librerías ni internet. */
import { h, s, animateVar } from "./dom.js";
import { BANDS, SYSTEMS } from "./data.js";

const CX = 120, CY = 120, R = 92;
const polar = (score, r = R) => {
  const a = Math.PI * (1 - score / 100);
  return [CX + r * Math.cos(a), CY - r * Math.sin(a)];
};
const arc = (a, b) => {
  const [x1, y1] = polar(a), [x2, y2] = polar(b);
  return `M ${x1.toFixed(2)} ${y1.toFixed(2)} A ${R} ${R} 0 ${b - a > 50 ? 1 : 0} 1 ${x2.toFixed(2)} ${y2.toFixed(2)}`;
};

function countUp(node, target, ms = 1000) {
  const start = performance.now();
  const frame = (now) => {
    const t = Math.min(1, (now - start) / ms);
    node.textContent = String(Math.round(target * (1 - Math.pow(1 - t, 3))));
    if (t < 1) requestAnimationFrame(frame);
  };
  requestAnimationFrame(frame);
}

/* Velocímetro semicircular 0–100 con las tres zonas de riesgo y aguja animada. */
export function gauge(score) {
  const value = Math.max(0, Math.min(100, Number(score) || 0));
  const needle = s("g", { class: "needle" },
    s("line", { x1: CX, y1: CY, x2: CX, y2: CY - 74 }), s("circle", { cx: CX, cy: CY, r: 8 }));
  const ticks = [0, BANDS.sospechoso, BANDS.phishing, 100].map((v) => {
    const [x, y] = v === 0 ? [CX - R, CY + 20] : v === 100 ? [CX + R, CY + 20] : polar(v, R + 18);
    return s("text", { class: "tick", x: x.toFixed(1), y: y.toFixed(1), "text-anchor": "middle" }, String(v));
  });
  const svg = s("svg", { viewBox: "0 0 240 146", role: "img", "aria-label": `Puntaje de riesgo ${Math.round(value)} de 100` },
    s("path", { class: "arc a-ok", d: arc(0, BANDS.sospechoso - 0.7) }),
    s("path", { class: "arc a-warn", d: arc(BANDS.sospechoso + 0.7, BANDS.phishing - 0.7) }),
    s("path", { class: "arc a-bad", d: arc(BANDS.phishing + 0.7, 100) }),
    ...ticks, needle);
  const number = h("b", {}, "0");
  requestAnimationFrame(() => requestAnimationFrame(() => { needle.style.transform = `rotate(${-90 + value * 1.8}deg)`; }));
  countUp(number, value);
  return h("div", { class: "gauge" }, svg, h("div", { class: "gauge-score" }, number, h("small", {}, " /100")));
}

/* Escala lineal 0–100 con las tres zonas y un marcador que se desliza hasta el puntaje.
   Complementa al velocímetro: ubica el puntaje dentro de las bandas Seguro/Sospechoso/Phishing. */
export function riskScale(score) {
  const value = Math.max(0, Math.min(100, Number(score) || 0));
  const track = h("div", { class: "scale-track" },
    h("i", { class: "b-ok", vars: { "--w": `${BANDS.sospechoso}%` } }),
    h("i", { class: "b-warn", vars: { "--w": `${BANDS.phishing - BANDS.sospechoso}%` } }),
    h("i", { class: "b-bad", vars: { "--w": `${100 - BANDS.phishing}%` } }));
  const marker = h("div", { class: "scale-marker", vars: { "--x": "0%" } });
  animateVar(marker, "--x", `${value}%`);
  return h("div", { class: "scale", role: "img", "aria-label": `Puntaje ${Math.round(value)} de 100 en la escala de riesgo` },
    h("div", { class: "scale-rail" }, track, marker),
    h("div", { class: "scale-labels" },
      h("span", {}, "Seguro 0–", String(BANDS.sospechoso - 1)),
      h("span", {}, "Sospechoso ", String(BANDS.sospechoso), "–", String(BANDS.phishing - 1)),
      h("span", {}, "Phishing ", String(BANDS.phishing), "–100")));
}

/* Fila de barra horizontal. `left` y `width` van de 0 a 100 (% del carril). */
function barRow({ label, hint, valueText, left = 0, width, zero = null, kind = "" }) {
  const fill = h("div", { class: `fill ${kind}`.trim(), vars: { "--l": `${left}%`, "--w": "0%" } });
  animateVar(fill, "--w", `${width}%`);
  return h("div", { class: "hbar" },
    h("span", { class: "lbl" }, label, hint ? h("small", { class: "muted" }, ` · ${hint}`) : null),
    h("div", { class: "track" }, fill, zero == null ? null : h("div", { class: "zero", vars: { "--z": `${zero}%` } })),
    h("span", { class: "val" }, valueText));
}

/* Barras de puntaje 0–100 (cómo se compone el puntaje, importancia de características). */
export function scoreBars(items, max = 100, format = (v) => v.toFixed(0)) {
  return h("div", { class: "bars" }, items.map((it) =>
    barRow({ label: it.label, valueText: format(it.value), width: Math.max(1, (it.value / max) * 100) })));
}

/* Barras divergentes (SHAP): hacia la derecha suben el riesgo, hacia la izquierda lo bajan. */
export function contributionBars(items) {
  const values = items.map((i) => i.contribution);
  const lo = Math.min(0, ...values), hi = Math.max(0, ...values), span = hi - lo || 1;
  const zero = (-lo / span) * 100;
  return h("div", { class: "bars" }, items.map((it) => {
    const width = Math.max(1, (Math.abs(it.contribution) / span) * 100);
    const left = it.contribution >= 0 ? zero : zero - width;
    return barRow({
      label: it.label, hint: it.hint, left, width, zero, kind: it.contribution >= 0 ? "up" : "down",
      valueText: `${it.contribution > 0 ? "+" : ""}${it.contribution.toFixed(1)}`,
    });
  }));
}

/* Barras verticales agrupadas: una columna por métrica, una barra por sistema. */
export function groupedBars(metrics, values) {
  const groups = metrics.map((m) => {
    const bars = SYSTEMS.map((sys, i) => {
      const v = values[m.key][i];
      const bar = h("div", { class: `vbar s${i}`, title: `${sys.name} · ${m.name}: ${v.toFixed(3)}`, vars: { "--h": "0%" } });
      animateVar(bar, "--h", `${Math.max(1, v * 100)}%`);
      return bar;
    });
    return h("div", { class: "vgroup" }, h("div", { class: "bars-in" }, bars));
  });
  return h("div", {}, h("div", { class: "vbars" }, groups),
    h("div", { class: "vlabels" }, metrics.map((m) => h("span", {}, m.name))));
}

/* Curvas ROC con leyenda que permite ocultar sistemas. Devuelve { element, legend }. */
export function rocChart(curves) {
  const L = 58, T = 12, W = 350, H = 320;
  const px = (v) => (L + v * W).toFixed(1), py = (v) => (T + (1 - v) * H).toFixed(1);
  const grid = [0, 0.25, 0.5, 0.75, 1].flatMap((t) => [
    s("line", { class: "grid", x1: px(0), x2: px(1), y1: py(t), y2: py(t) }),
    s("line", { class: "grid", x1: px(t), x2: px(t), y1: py(0), y2: py(1) }),
    s("text", { class: "axis-t", x: L - 8, y: Number(py(t)) + 4, "text-anchor": "end" }, t.toFixed(2)),
    s("text", { class: "axis-t", x: px(t), y: T + H + 18, "text-anchor": "middle" }, t.toFixed(2)),
  ]);
  const lines = curves.map((c, i) => s("polyline", {
    class: `line s${i}${SYSTEMS[i].dash ? " dash" : ""}`,
    points: c.fpr.map((f, k) => `${px(f)},${py(c.tpr[k])}`).join(" "),
  }));
  const svg = s("svg", { class: "roc", viewBox: `0 0 ${L + W + 12} ${T + H + 44}`, role: "img", "aria-label": "Curvas ROC de los cinco sistemas" },
    ...grid, s("line", { class: "diag", x1: px(0), y1: py(0), x2: px(1), y2: py(1) }), ...lines,
    s("text", { class: "axis-t", x: L + W / 2, y: T + H + 38, "text-anchor": "middle" }, "Tasa de falsos positivos"),
    s("text", { class: "axis-t", x: 12, y: T + H / 2, "text-anchor": "middle", transform: `rotate(-90 12 ${T + H / 2})` }, "Tasa de verdaderos positivos"));
  const legend = h("div", { class: "sys-legend" }, SYSTEMS.map((sys, i) => {
    const btn = h("button", { type: "button", class: `sys-btn s${i}${sys.dash ? " dash" : ""}`, "aria-pressed": "true", title: "Mostrar u ocultar" },
      h("i"), sys.name);
    btn.addEventListener("click", () => {
      const off = btn.classList.toggle("off");
      lines[i].classList.toggle("off", off);
      btn.setAttribute("aria-pressed", String(!off));
    });
    return btn;
  }));
  return { element: svg, legend };
}
