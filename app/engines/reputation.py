"""Lista de dominios de reputación: reduce los falsos positivos del motor ML.

El modelo se entrenó con PhiUSIIL, donde casi todas las URLs legítimas son dominios raíz sin
subdominio. Por eso trata `accounts.google.com` o `mail.google.com` como phishing. Para los
dominios registrados que figuran en esta lista (marcas muy conocidas) la estimación del ML se
limita a un valor bajo, y el análisis lo dice en los motivos. Las reglas heurísticas, el motor
de red y los conectores siguen corriendo con normalidad.

Dos salvaguardas, porque el phishing también se aloja en sitios reputados:
- los dominios de plataformas que alojan contenido de terceros (github.io, web.app,
  blogspot.com, etc.) y los acortadores nunca se consideran de reputación, aunque estén en un
  archivo;
- dentro de un dominio de reputación, los hosts con contenido de usuarios (sites.google.com,
  docs.google.com, forms.office.com...) tampoco reciben el beneficio.

Esta lista es un punto de evasión conocido (alojar phishing en un servicio legítimo) y se
documenta como limitación en el análisis del atacante.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterable, List

from app.engines.base import AnalysisContext
from app.engines.heuristic import URL_SHORTENERS

# Dominios registrados que alojan contenido de terceros: nunca son "de reputación".
PLATFORM_DOMAINS = {
    "blogspot.com", "wordpress.com", "weebly.com", "weeblysite.com", "wixsite.com",
    "github.io", "gitlab.io", "web.app", "firebaseapp.com", "herokuapp.com", "netlify.app",
    "vercel.app", "pages.dev", "workers.dev", "azurewebsites.net", "azurestaticapps.net",
    "windows.net", "amazonaws.com", "cloudfront.net", "onrender.com", "glitch.me",
    "repl.co", "replit.app", "notion.site", "godaddysites.com", "000webhostapp.com",
    "myshopify.com", "square.site", "carrd.co", "webflow.io", "framer.website",
    "ngrok.io", "ngrok-free.app", "trycloudflare.com", "duckdns.org", "no-ip.com",
    "ddns.net", "hostfree.pw", "googleusercontent.com", "appspot.com", "tumblr.com",
    "medium.com", "substack.com", "livejournal.com", "sharepoint.com",
    "dropboxusercontent.com",
}

# Hosts con contenido de usuarios dentro de dominios que sí están en la lista.
USER_CONTENT_HOSTS = {
    "sites.google.com", "docs.google.com", "drive.google.com", "script.google.com",
    "onedrive.live.com", "forms.office.com", "forms.microsoft.com", "sway.office.com",
}


class ReputationList:
    """Conjunto de dominios registrados de alta reputación."""

    def __init__(self, domains: Iterable[str] = ()) -> None:
        cleaned = {d.strip().lower() for d in domains if d and d.strip()}
        self._domains = cleaned - PLATFORM_DOMAINS - URL_SHORTENERS

    @classmethod
    def from_files(cls, *paths: str | Path) -> "ReputationList":
        """Lee uno o más archivos (un dominio por línea, `#` para comentarios).

        Los archivos que no existen se ignoran: la lista es opcional.
        """
        domains: List[str] = []
        for path in paths:
            p = Path(path)
            if not p.is_file():
                continue
            for line in p.read_text(encoding="utf-8").splitlines():
                line = line.split("#", 1)[0].strip()
                if line:
                    domains.append(line)
        return cls(domains)

    def __len__(self) -> int:
        return len(self._domains)

    def __contains__(self, domain: str) -> bool:
        return domain.strip().lower() in self._domains

    def is_reputable(self, ctx: AnalysisContext) -> bool:
        registered = (ctx.registered_domain or "").lower()
        if registered not in self._domains:
            return False
        host = (ctx.host or "").lower()
        return not any(host == h or host.endswith("." + h) for h in USER_CONTENT_HOSTS)


def parse_tranco(lines: Iterable[str], top_n: int) -> List[str]:
    """Extrae los primeros `top_n` dominios aptos de un CSV de Tranco (`rango,dominio`)."""
    out: List[str] = []
    for line in lines:
        parts = line.strip().split(",")
        if len(parts) < 2:
            continue
        domain = parts[1].strip().lower()
        if "." not in domain or domain in PLATFORM_DOMAINS or domain in URL_SHORTENERS:
            continue
        out.append(domain)
        if len(out) >= top_n:
            break
    return out
