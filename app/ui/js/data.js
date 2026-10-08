/* Textos, constantes y ejemplos de la interfaz. */
export const BANDS = { sospechoso: 35, phishing: 60 };

export const VERDICTS = {
  seguro: {
    titulo: "Seguro",
    resumen: "No encontramos señales claras de phishing.",
    recomendacion: "Puedes continuar, pero nunca compartas contraseñas ni códigos en enlaces que no hayas pedido tú.",
  },
  sospechoso: {
    titulo: "Sospechoso",
    resumen: "Hay señales de alerta. Conviene verificar antes de actuar.",
    recomendacion: "No ingreses contraseñas ni datos personales. Confirma con la entidad por otro canal, por ejemplo una llamada o escribiendo tú mismo su sitio oficial.",
  },
  phishing: {
    titulo: "Phishing",
    resumen: "Es muy probable que sea un intento de phishing.",
    recomendacion: "No abras el enlace ni respondas. Si ya ingresaste datos, cambia tus contraseñas y avisa a tu banco o proveedor.",
  },
};

export const verdictKey = (v) => (VERDICTS[v] ? v : "sospechoso");
export const verdictInfo = (v) => VERDICTS[verdictKey(v)];

export const COMPONENT_NAMES = {
  heuristica: "Reglas heurísticas", red: "Verificación de red", ml: "Modelo de IA",
  google_safe_browsing: "Google Safe Browsing", virustotal: "VirusTotal",
  enlaces: "Enlaces del mensaje", remitente: "Dominio del remitente", senales_mensaje: "Señales del mensaje",
};

export const SYSTEMS = [
  { key: "heuristica_url_completa", name: "Reglas (URL completa)", dash: false },
  { key: "heuristica_solo_dominio", name: "Reglas (solo dominio)", dash: true },
  { key: "ml", name: "Modelo ML", dash: false },
  { key: "combinado_url_completa", name: "Combinado (URL completa)", dash: false },
  { key: "combinado_solo_dominio", name: "Combinado (solo dominio)", dash: true },
];
export const THRESHOLDS = [
  { key: "umbral_35", label: "Alerta desde 35", desc: "sospechoso o phishing" },
  { key: "umbral_60", label: "Alerta desde 60", desc: "solo phishing" },
];
export const METRICS = [
  { key: "accuracy", name: "Accuracy" }, { key: "precision", name: "Precisión" },
  { key: "recall", name: "Recall" }, { key: "f1", name: "F1" },
];
export const MODEL_NAMES = { regresion_logistica: "Regresión Logística", random_forest: "Random Forest" };

export const EXAMPLES = {
  url: [
    { label: "Phishing: banco falso", value: "https://login.secure-bank.evil.tk/verify" },
    { label: "Sospechoso: enlace acortado", value: "https://bit.ly/3xYz9" },
    { label: "Legítimo: Wikipedia", value: "https://www.wikipedia.org" },
    { label: "Legítimo con subdominio: Google", value: "https://accounts.google.com" },
  ],
  correo: [
    { label: "Phishing: falso aviso de PayPal", value: {
      subject: "URGENTE: verifique su cuenta", sender: "PayPal Seguridad <soporte@paypa1-alertas.tk>",
      body: "Su cuenta será suspendida. Haga clic aquí para verificarla: http://paypa1-alertas.tk/login" } },
    { label: "Legítimo: aviso de Google", value: {
      subject: "Resumen semanal", sender: "Google <no-reply@accounts.google.com>",
      body: "Hola, te compartimos el resumen semanal." } },
  ],
  mensaje: [
    { label: "Phishing: falso aviso del banco", value: "Bancolombia: tu cuenta fue bloqueada. Verifica tus datos ahora en https://bit.ly/3xYz9" },
    { label: "Legítimo: ubicación de un amigo", value: "Hola, nos vemos a las 5. Aquí está el mapa: https://www.google.com/maps" },
  ],
};

/* Separa los motivos del análisis de los avisos técnicos de servicios opcionales sin configurar. */
export function splitReasons(motivos) {
  const reasons = [], services = [];
  for (const m of motivos) {
    const found = /^(\S+) no disponible \(sin API key\)$/.exec(m);
    if (found) services.push(COMPONENT_NAMES[found[1]] || found[1]);
    else reasons.push(m);
  }
  return { reasons, services };
}

export const pct = (x, digits = 0) => `${(x * 100).toFixed(digits)}%`;
export const num3 = (x) => Number(x).toFixed(3);

export function fmtDate(iso) {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? String(iso ?? "") : d.toLocaleString("es-CO", { dateStyle: "short", timeStyle: "short" });
}
