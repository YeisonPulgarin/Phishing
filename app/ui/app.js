/* PhishShield: punto de entrada de la interfaz (acceso, navegación y formularios). */
import { Api, keyStore } from "./js/api.js";
import { $, $$, h, clear, icon, alertBox } from "./js/dom.js";
import { EXAMPLES } from "./js/data.js";
import { createHistory, openDetail, renderEvaluation, renderHow, renderResult } from "./js/views.js";

const api = new Api();
const history = createHistory($("#history-root"), api, (id) => openDetail(api, id));

/* ---------------------------------------------------------------- tema */
const root = document.documentElement;
function setTheme(theme) {
  root.dataset.theme = theme;
  localStorage.setItem("pd_theme", theme);
  const use = $("#theme-btn use");
  use.setAttribute("href", theme === "dark" ? "#i-sun" : "#i-moon");
}
setTheme(localStorage.getItem("pd_theme") === "light" ? "light" : "dark");
$("#theme-btn").addEventListener("click", () => setTheme(root.dataset.theme === "dark" ? "light" : "dark"));

/* ---------------------------------------------------------------- acceso */
const loginError = (message) => {
  const box = $("#login-error");
  box.textContent = message;
  box.classList.toggle("hidden", !message);
};

let healthTimer = null;
function enter() {
  $("#login-view").classList.add("hidden");
  $("#shell").classList.remove("hidden");
  showView("analizar");
  checkHealth();
  if (!healthTimer) healthTimer = setInterval(checkHealth, 20000);
  $("#url-input").focus();
}

function logout(message = "") {
  keyStore.clear();
  clear($("#result"));
  $("#shell").classList.add("hidden");
  $("#login-view").classList.remove("hidden");
  $("#api-key-input").value = "";
  loginError(message);
}

$("#login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const key = $("#api-key-input").value.trim();
  if (!key) return loginError("Escribe tu clave API.");
  try {
    await api.checkKey(key);
    keyStore.save(key, $("#remember").checked);
    loginError("");
    enter();
  } catch (err) {
    loginError(err.message);
  }
});
$("#logout-btn").addEventListener("click", () => logout());

async function checkHealth() {
  const status = $("#status");
  try {
    await api.health();
    status.className = "status ok";
    $("#status-text").textContent = "Conectado";
  } catch {
    status.className = "status down";
    $("#status-text").textContent = "Sin conexión";
  }
}

/* ---------------------------------------------------------------- navegación */
let evaluationLoaded = false;
function showView(name) {
  $$("[data-view].view").forEach((v) => v.classList.toggle("hidden", v.dataset.view !== name));
  $$(".nav-item").forEach((b) => b.classList.toggle("active", b.dataset.view === name));
  if (name === "historial") history.refresh();
  if (name === "evaluacion" && !evaluationLoaded) { evaluationLoaded = true; renderEvaluation($("#eval-root"), api); }
  window.scrollTo({ top: 0 });
}
$$(".nav-item").forEach((b) => b.addEventListener("click", () => showView(b.dataset.view)));
renderHow($("#como-root"));

$("#history-refresh").addEventListener("click", () => history.refresh());
$("#history-csv").addEventListener("click", () => {
  const blob = new Blob(["\ufeff" + history.csv()], { type: "text/csv;charset=utf-8" });
  const link = h("a", { download: "historial-phishshield.csv" });
  link.href = URL.createObjectURL(blob);
  link.click();
  URL.revokeObjectURL(link.href);
});
$("#detail-close").addEventListener("click", () => $("#detail").close());
$("#detail").addEventListener("click", (e) => { if (e.target === $("#detail")) $("#detail").close(); });

/* ---------------------------------------------------------------- formularios */
function switchKind(kind) {
  $$("#kind-tabs .seg-item").forEach((b) => b.classList.toggle("active", b.dataset.kind === kind));
  $$("form.form").forEach((f) => f.classList.toggle("hidden", f.dataset.kind !== kind));
  clear($("#result"));
}
$$("#kind-tabs .seg-item").forEach((b) => b.addEventListener("click", () => switchKind(b.dataset.kind)));

let emailMode = "campos";
function switchEmailMode(mode) {
  emailMode = mode;
  $$("#email-mode .seg-item").forEach((b) => b.classList.toggle("active", b.dataset.mode === mode));
  $("#email-fields").classList.toggle("hidden", mode !== "campos");
  $("#email-eml").classList.toggle("hidden", mode !== "eml");
}
$$("#email-mode .seg-item").forEach((b) => b.addEventListener("click", () => switchEmailMode(b.dataset.mode)));
$("#email-file").addEventListener("change", async (e) => {
  const file = e.target.files[0];
  if (file) $("#email-raw").value = await file.text();
});

const fillers = {
  url: (v) => { $("#url-input").value = v; $("#url-input").focus(); },
  correo: (v) => {
    switchEmailMode("campos");
    $("#email-subject").value = v.subject; $("#email-sender").value = v.sender; $("#email-body").value = v.body;
  },
  mensaje: (v) => { $("#sms-text").value = v; $("#sms-text").focus(); },
};
$$(".chips[data-examples]").forEach((box) => {
  const kind = box.dataset.examples;
  box.append(h("span", { class: "chips-label" }, "Probar con un ejemplo:"),
    ...EXAMPLES[kind].map((ex) => h("button", { type: "button", class: "chip", onclick: () => fillers[kind](ex.value) }, ex.label)));
});

const SCAN_STEPS = ["Revisando las reglas de seguridad…", "Verificando el dominio en la red…", "Consultando el modelo de inteligencia artificial…", "Calculando el puntaje de riesgo…"];
function startScan(host) {
  const line = h("span", {}, SCAN_STEPS[0]);
  clear(host).append(h("div", { class: "scan", role: "status" }, h("strong", {}, "Analizando…"), line));
  let i = 0;
  const timer = setInterval(() => { i = (i + 1) % SCAN_STEPS.length; line.textContent = SCAN_STEPS[i]; }, 1100);
  return () => clearInterval(timer);
}

async function run(kind, form, validate, call) {
  const host = $("#result"), button = $("button[type=submit]", form);
  const problem = validate();
  if (problem) { clear(host).append(alertBox(problem)); return; }
  button.disabled = true;
  const stop = startScan(host);
  try {
    const data = await call();
    stop();
    renderResult(host, { tipo: kind, data }, api);
    host.scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (err) {
    stop();
    if (err.status === 401) return logout("Tu clave ya no es válida. Vuelve a ingresarla.");
    clear(host).append(alertBox(err.message));
  } finally {
    button.disabled = false;
  }
}

const value = (id) => $(id).value.trim();
$("#form-url").addEventListener("submit", (e) => {
  e.preventDefault();
  run("url", e.currentTarget, () => (value("#url-input") ? "" : "Escribe o pega un enlace para revisar."), () => api.analyzeUrl(value("#url-input")));
});
$("#form-correo").addEventListener("submit", (e) => {
  e.preventDefault();
  const fromFile = emailMode === "eml";
  run("correo", e.currentTarget,
    () => ((fromFile ? value("#email-raw") : value("#email-body")) ? "" : fromFile ? "Sube un archivo .eml o pega el correo completo." : "Escribe el cuerpo del mensaje."),
    () => api.analyzeEmail(fromFile
      ? { raw: $("#email-raw").value }
      : { subject: value("#email-subject"), sender: value("#email-sender"), body: $("#email-body").value }));
});
$("#form-mensaje").addEventListener("submit", (e) => {
  e.preventDefault();
  run("mensaje", e.currentTarget, () => (value("#sms-text") ? "" : "Pega el texto del mensaje que recibiste."), () => api.analyzeMessage(value("#sms-text")));
});

/* ---------------------------------------------------------------- arranque */
(async function start() {
  const stored = keyStore.get();
  if (!stored) return;
  try {
    await api.checkKey(stored);
    enter();
  } catch (err) {
    logout(err.status === 401 ? "La clave guardada ya no es válida." : "");
  }
})();
