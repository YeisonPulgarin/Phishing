/* Utilidades de DOM. Todo el contenido dinámico entra como texto (textContent): nunca se usa
   innerHTML, así que una URL o un correo malicioso no puede inyectar código en la página. */
const SVG_NS = "http://www.w3.org/2000/svg";

function build(node, attrs, children) {
  for (const [name, value] of Object.entries(attrs || {})) {
    if (value == null || value === false) continue;
    if (name === "class") node.setAttribute("class", value);
    else if (name.startsWith("on") && typeof value === "function") node.addEventListener(name.slice(2).toLowerCase(), value);
    else if (name === "vars") for (const [k, v] of Object.entries(value)) node.style.setProperty(k, v);
    else node.setAttribute(name, value === true ? "" : String(value));
  }
  for (const child of children.flat(Infinity)) {
    if (child == null || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

export const h = (tag, attrs = {}, ...children) => build(document.createElement(tag), attrs, children);
export const s = (tag, attrs = {}, ...children) => build(document.createElementNS(SVG_NS, tag), attrs, children);
export const $ = (selector, root = document) => root.querySelector(selector);
export const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

export function clear(node) {
  node.replaceChildren();
  return node;
}

export function icon(name, extra = "") {
  const use = s("use");
  use.setAttribute("href", `#i-${name}`);
  return s("svg", { class: `icon ${extra}`.trim(), "aria-hidden": "true" }, use);
}

export function alertBox(message) {
  return h("div", { class: "alert error", role: "alert" }, icon("alert"), h("span", {}, message));
}

/* Después de insertar el nodo, aplica el valor en el siguiente cuadro para que la transición CSS se vea. */
export function animateVar(node, name, value) {
  requestAnimationFrame(() => requestAnimationFrame(() => node.style.setProperty(name, value)));
}
