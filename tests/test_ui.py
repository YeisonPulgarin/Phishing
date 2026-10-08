"""Tests de la interfaz web propia (app/ui) y de las cabeceras de seguridad que la protegen."""
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app

UI = Path("app/ui")
JS_FILES = sorted(UI.glob("**/*.js"))
client = TestClient(app)


def test_index_is_served_with_login_navigation_and_forms():
    resp = client.get("/")
    assert resp.status_code == 200 and "text/html" in resp.headers["content-type"]
    html = resp.text
    for marker in ('id="login-form"', 'id="nav"', 'id="form-url"', 'id="form-correo"', 'id="form-mensaje"',
                   'id="history-root"', 'id="eval-root"', 'id="como-root"', 'id="detail"'):
        assert marker in html, marker
    assert 'lang="es"' in html and 'name="viewport"' in html


@pytest.mark.parametrize("path", ["/static/styles.css", "/static/favicon.svg", "/static/app.js",
                                  *[f"/static/{p.relative_to(UI).as_posix()}" for p in JS_FILES]])
def test_static_assets_are_served(path):
    assert client.get(path).status_code == 200, path


def test_js_is_served_as_javascript():
    for path in ("/static/app.js", "/static/js/views.js"):
        assert "javascript" in client.get(path).headers["content-type"]


def test_api_client_uses_authenticated_endpoints():
    js = client.get("/static/js/api.js").text
    for endpoint in ("/api/analyze", "/api/analyze-email", "/api/analyze-message", "/api/explain",
                     "/api/analyses", "/api/evaluation", "/api/auth", "X-API-Key"):
        assert endpoint in js, endpoint


def test_every_asset_referenced_by_the_html_and_js_modules_exists():
    html = (UI / "index.html").read_text(encoding="utf-8")
    for ref in re.findall(r'(?:href|src)="(/static/[^"]+)"', html):
        assert (UI / ref.removeprefix("/static/")).is_file(), ref
    for js in JS_FILES:
        for rel in re.findall(r'from "(\./[^"]+)"', js.read_text(encoding="utf-8")):
            assert (js.parent / rel).resolve().is_file(), f"{js}: {rel}"


def test_html_is_csp_compliant_no_inline_script_style_or_handlers():
    html = (UI / "index.html").read_text(encoding="utf-8")
    assert not re.search(r"<script(?![^>]*\bsrc=)", html), "script en línea"
    assert "<style" not in html and not re.search(r"\sstyle=", html), "estilos en línea"
    assert not re.search(r"\son[a-z]+=", html), "manejadores de eventos en línea"
    assert not re.search(r'(?:href|src)="https?://', html), "recursos externos"
    assert "http" not in (UI / "styles.css").read_text(encoding="utf-8").replace("http://www.w3.org", ""), "CSS con recursos externos"


@pytest.mark.parametrize("js", JS_FILES, ids=lambda p: p.name)
def test_js_never_writes_untrusted_html(js):
    """Todo el contenido dinámico entra como texto: ni innerHTML ni eval ni setAttribute('style')."""
    code = re.sub(r"/\*.*?\*/", "", js.read_text(encoding="utf-8"), flags=re.S)   # los comentarios pueden mencionarlos
    for banned in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", 'setAttribute("style"'):
        assert banned not in code, f"{js.name} usa {banned}"


def test_ui_responses_carry_a_strict_csp_and_hardening_headers():
    for path in ("/", "/static/app.js", "/static/styles.css"):
        h = client.get(path).headers
        csp = h["content-security-policy"]
        assert "default-src 'self'" in csp and "script-src 'self'" in csp and "frame-ancestors 'none'" in csp
        assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
        assert h["x-content-type-options"] == "nosniff" and h["x-frame-options"] == "DENY"
        assert h["referrer-policy"] == "no-referrer"


def test_api_responses_are_not_cached_and_docs_keep_working_without_the_ui_csp():
    assert client.get("/health").headers["x-content-type-options"] == "nosniff"
    resp = client.post("/api/auth", json={"api_key": "x"})
    assert resp.headers["cache-control"] == "no-store"
    docs = client.get("/docs")
    assert docs.status_code == 200 and "content-security-policy" not in docs.headers
