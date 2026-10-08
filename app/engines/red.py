"""Motor de verificación de red/HTTP.

Ejecuta en paralelo los chequeos de DNS, certificado SSL, antigüedad del dominio (RDAP) y
página (redirecciones y HTML), y los combina en un sub-score. Tiene un presupuesto de tiempo
total (`budget`): un chequeo que no responde a tiempo se omite y se informa, sin demorar el
análisis (RNF2: menos de 5 s por URL). Degrada a "error"/"no_disponible" si el cliente de red
falla, sin romper el análisis (lo tolera el pipeline).

Seguridad: antes de conectarse se verifica que el host sea público (ver `netguard`) y las
redirecciones se siguen a mano validando cada salto, para que la herramienta no pueda usarse
para consultar la red interna (SSRF).
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, wait
from typing import Callable, Optional, Protocol, runtime_checkable

from bs4 import BeautifulSoup

from app.engines.base import AnalysisContext, EngineResult, EngineStatus
from app.engines.netguard import is_public_host

_USER_AGENT = {"User-Agent": "phishing-detector/1.0"}

# Nombre legible de cada chequeo, para informar los que no respondieron a tiempo.
_LABELS = {
    "dns": "DNS",
    "ssl": "certificado SSL",
    "rdap": "antigüedad del dominio (RDAP)",
    "pagina": "la página",
}


@runtime_checkable
class NetworkClient(Protocol):
    """Abstracción de acceso a red, inyectable para testear sin red real."""

    def resolve(self, host: str) -> bool: ...
    def ssl_days_valid(self, host: str) -> Optional[int]: ...
    def redirect_chain_to(self, url: str) -> tuple[int, Optional[str]]: ...
    def rdap_creation_days(self, domain: str) -> Optional[int]: ...
    def fetch_html(self, url: str) -> Optional[str]: ...


class RealNetworkClient:
    """Implementación de producción con requests/dns/ipwhois/BS4."""

    MAX_HOPS = 5
    MAX_BYTES = 200_000

    def __init__(self, timeout: float = 3.0) -> None:
        self._timeout = timeout

    def is_public_host(self, host: str) -> bool:
        return is_public_host(host)

    def resolve(self, host: str) -> bool:
        import socket

        try:
            socket.gethostbyname(host)
            return True
        except OSError:
            return False

    def ssl_days_valid(self, host: str) -> Optional[int]:
        import datetime
        import socket
        import ssl

        if not is_public_host(host):
            return None
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=self._timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    cert = tls.getpeercert()
                    if not cert:
                        return None
                    not_after = datetime.datetime.strptime(
                        cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
                    )
                    days = (not_after - datetime.datetime.utcnow()).days
                    return max(days, 0)
        except (OSError, ssl.SSLError, KeyError, ValueError):
            return 0

    def fetch_page(self, url: str) -> tuple[int, Optional[str], str]:
        """Una sola petición: devuelve (nº de redirecciones, host final, HTML).

        Las redirecciones se siguen a mano (máx. `MAX_HOPS`) y cada salto debe ser http/https
        hacia un host público; si no, se corta ahí y no se conecta.
        """
        import requests
        from urllib.parse import urljoin, urlsplit

        hops, current = 0, url
        try:
            while True:
                parts = urlsplit(current)
                if parts.scheme not in ("http", "https") or not is_public_host(parts.hostname or ""):
                    return hops, parts.hostname, ""
                resp = requests.get(
                    current, timeout=self._timeout, allow_redirects=False,
                    headers=_USER_AGENT, stream=True,
                )
                location = resp.headers.get("Location")
                if resp.is_redirect and location and hops < self.MAX_HOPS:
                    resp.close()
                    current = urljoin(current, location)
                    hops += 1
                    continue
                html = ""
                if resp.status_code == 200:
                    raw = resp.raw.read(self.MAX_BYTES, decode_content=True)
                    html = raw.decode(resp.encoding or "utf-8", errors="replace")
                resp.close()
                return hops, urlsplit(current).hostname, html
        except requests.RequestException:
            return hops, urlsplit(current).hostname, ""

    def redirect_chain_to(self, url: str) -> tuple[int, Optional[str]]:
        hops, final, _ = self.fetch_page(url)
        return hops, final

    def fetch_html(self, url: str) -> Optional[str]:
        return self.fetch_page(url)[2]

    def rdap_creation_days(self, domain: str) -> Optional[int]:
        import datetime

        import requests

        try:
            resp = requests.get(
                f"https://rdap.org/domain/{domain}", timeout=self._timeout
            )
            if resp.status_code != 200:
                return None
            data = resp.json()
            events = data.get("events", [])
            created = None
            for ev in events:
                if ev.get("eventAction") == "registration":
                    created = ev.get("eventDate")
                    break
            if not created:
                return None
            created_dt = datetime.datetime.fromisoformat(
                created.replace("Z", "+00:00")
            ).astimezone(datetime.timezone.utc)
            return max((datetime.datetime.now(datetime.timezone.utc) - created_dt).days, 0)
        except (requests.RequestException, ValueError, KeyError):
            return None


class NetworkEngine:
    """Combina los chequeos de red (en paralelo) en un sub-score."""

    name = "red"

    def __init__(self, client: NetworkClient | None = None, budget: float = 3.5) -> None:
        self._client: NetworkClient = client or RealNetworkClient()
        self._budget = budget

    def analyze(self, ctx: AnalysisContext) -> EngineResult:
        guard = getattr(self._client, "is_public_host", None)
        if guard is not None and not guard(ctx.host):
            return EngineResult(
                sub_score=0.0,
                motivos=["El dominio apunta a una dirección privada o local: "
                         "no se consulta la red por seguridad"],
                estado=EngineStatus.NO_DISPONIBLE,
            )

        tasks: dict[str, Callable[[], object]] = {
            "dns": lambda: self._client.resolve(ctx.host),
            "pagina": lambda: self._page(ctx.url),
        }
        if ctx.scheme == "https":
            tasks["ssl"] = lambda: self._client.ssl_days_valid(ctx.host)
        if ctx.registered_domain:
            tasks["rdap"] = lambda: self._client.rdap_creation_days(ctx.registered_domain)

        results, late, failed = self._run_parallel(tasks)
        if not results:
            return EngineResult(
                sub_score=0.0,
                motivos=["Motor de red no disponible en esta ejecución"],
                estado=EngineStatus.ERROR,
            )

        reasons: list[str] = []
        score = 0.0
        if "dns" in results:
            score += self._score_dns(results["dns"], reasons)
        if "ssl" in results:
            score += self._score_ssl(results["ssl"], reasons)
        if "rdap" in results:
            score += self._score_rdap(results["rdap"], reasons)
        if "pagina" in results:
            count, final, html = results["pagina"]
            score += self._score_redirects(ctx, count, final, reasons)
            score += self._score_html(html, reasons)
        for name in late:
            reasons.append(f"El chequeo de {_LABELS[name]} no respondió a tiempo")

        if not reasons:
            reasons.append("Sin señales de red destacables")
        return EngineResult(sub_score=max(0.0, min(100.0, score)), motivos=reasons)

    # -- ejecución -------------------------------------------------------------------

    def _page(self, url: str) -> tuple[int, Optional[str], Optional[str]]:
        """Redirecciones + HTML en una sola petición si el cliente lo soporta."""
        fetch_page = getattr(self._client, "fetch_page", None)
        if fetch_page is not None:
            return fetch_page(url)
        count, final = self._client.redirect_chain_to(url)
        return count, final, self._client.fetch_html(url)

    def _run_parallel(self, tasks: dict[str, Callable[[], object]]):
        pool = ThreadPoolExecutor(max_workers=len(tasks))
        futures = {name: pool.submit(fn) for name, fn in tasks.items()}
        done, _ = wait(list(futures.values()), timeout=self._budget)
        # No se espera a los rezagados: terminan solos por su propio timeout de socket.
        pool.shutdown(wait=False, cancel_futures=True)

        results: dict[str, object] = {}
        late: list[str] = []
        failed: list[str] = []
        for name, fut in futures.items():
            if fut not in done:
                late.append(name)
                continue
            try:
                results[name] = fut.result()
            except Exception:
                failed.append(name)
        return results, late, failed

    # -- puntaje de cada chequeo -----------------------------------------------------

    @staticmethod
    def _score_dns(resolved, reasons) -> float:
        if not resolved:
            reasons.append("El dominio no resuelve DNS")
            return 45
        return 0

    @staticmethod
    def _score_ssl(days, reasons) -> float:
        if days is None:
            reasons.append("No se pudo verificar el certificado SSL")
            return 20
        if days <= 0:
            reasons.append("Certificado SSL inválido o expirado")
            return 45
        if days < 30:
            reasons.append("Certificado SSL por vencer muy pronto")
            return 25
        return 0

    @staticmethod
    def _score_redirects(ctx, count, final, reasons) -> float:
        if count:
            reasons.append(f"La URL redirige {count} veces")
            score = 10.0
            if final and final != ctx.host:
                reasons.append(f"Redirige a un dominio distinto: {final}")
                score += 25
            return min(score, 40)
        return 0

    @staticmethod
    def _score_rdap(days, reasons) -> float:
        if days is None:
            return 0
        if days <= 30:
            reasons.append(f"El dominio se registró hace {days} días")
            return 40
        if days <= 90:
            reasons.append("El dominio es reciente")
            return 20
        return 0

    @staticmethod
    def _score_html(html, reasons) -> float:
        if not html:
            return 0
        soup = BeautifulSoup(html, "lxml")
        score = 0
        if soup.find("input", {"type": "password"}):
            reasons.append("La página pide una contraseña")
            score += 20
        if soup.find("input", {"type": "text"}):
            score += 5
        return score
