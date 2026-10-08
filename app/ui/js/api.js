/* Cliente de la API del detector. Traduce errores a mensajes en español comprensibles. */
const KEY = "pd_api_key";

export class ApiError extends Error {
  constructor(message, status = 0) {
    super(message);
    this.status = status;
  }
}

export const keyStore = {
  get() { return sessionStorage.getItem(KEY) || localStorage.getItem(KEY) || ""; },
  save(key, remember) { this.clear(); (remember ? localStorage : sessionStorage).setItem(KEY, key); },
  clear() { sessionStorage.removeItem(KEY); localStorage.removeItem(KEY); },
};

async function detail(resp) {
  try {
    const body = await resp.json();
    const first = Array.isArray(body.detail) ? body.detail[0]?.msg : body.detail;
    return String(first || "revisa los datos ingresados.").replace(/^Value error, /, "");
  } catch {
    return "revisa los datos ingresados.";
  }
}

export class Api {
  async request(method, path, body, { auth = true } = {}) {
    const headers = {};
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (auth) headers["X-API-Key"] = keyStore.get();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 25000);
    let resp;
    try {
      resp = await fetch(path, { method, headers, signal: controller.signal, body: body === undefined ? undefined : JSON.stringify(body) });
    } catch (err) {
      throw new ApiError(err.name === "AbortError"
        ? "El detector tardó demasiado en responder. Inténtalo de nuevo."
        : "No se pudo conectar con el detector. ¿Está encendido el servidor?");
    } finally {
      clearTimeout(timer);
    }
    if (resp.status === 401) throw new ApiError("La clave API no es válida.", 401);
    if (resp.status === 422) throw new ApiError(`Entrada no válida: ${await detail(resp)}`, 422);
    if (resp.status === 503) throw new ApiError("El modelo de aprendizaje automático no está disponible en el servidor.", 503);
    if (!resp.ok) throw new ApiError(`El detector respondió con un error (${resp.status}).`, resp.status);
    try {
      return await resp.json();
    } catch {
      throw new ApiError("El detector devolvió una respuesta que no se pudo leer.");
    }
  }

  health() { return this.request("GET", "/health", undefined, { auth: false }); }
  checkKey(key) { return this.request("POST", "/api/auth", { api_key: key }, { auth: false }); }
  analyzeUrl(url) { return this.request("POST", "/api/analyze", { url }); }
  analyzeEmail(payload) { return this.request("POST", "/api/analyze-email", payload); }
  analyzeMessage(text) { return this.request("POST", "/api/analyze-message", { text }); }
  explain(url) { return this.request("POST", "/api/explain", { url }); }
  history() { return this.request("GET", "/api/analyses"); }
  historyItem(id) { return this.request("GET", `/api/analyses/${encodeURIComponent(id)}`); }
  evaluation() { return this.request("GET", "/api/evaluation"); }
}
