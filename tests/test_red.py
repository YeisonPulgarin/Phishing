"""Tests del motor de red/HTTP (app.engines.red)."""
import pytest

from app.engines.base import AnalysisContext
from app.engines.red import NetworkClient, NetworkEngine


class FakeClient:
    """Cliente de red simulado para tests (sin red real)."""

    def __init__(self, **overrides):
        self.data = {
            "resolve": True,
            "ssl_days_valid": 365,
            "redirect_count": 0,
            "redirect_final_domain": None,
            "rdap_creation_days": 300,
            "html": "<html><form><input type=password></form></html>",
        }
        self.data.update(overrides)

    def resolve(self, host):
        return self.data["resolve"]

    def ssl_days_valid(self, host):
        return self.data["ssl_days_valid"]

    def redirect_chain_to(self, url):
        return self.data["redirect_count"], self.data["redirect_final_domain"]

    def rdap_creation_days(self, domain):
        return self.data["rdap_creation_days"]

    def fetch_html(self, url):
        return self.data["html"]


def _score(client, url):
    engine = NetworkEngine(client)
    return engine.analyze(AnalysisContext.from_url(url)).normalized_score


def test_clean_host_low_score():
    client = FakeClient()
    assert _score(client, "https://www.google.com") < 35


def test_dns_not_resolving_raises_score(monkeypatch):
    client = FakeClient(resolve=False)
    s = _score(client, "https://definitely-not-real-domain-xyz.com")
    assert s >= 35


def test_new_domain_raises_score():
    client = FakeClient(rdap_creation_days=5)
    s = _score(client, "https://brand-new-domain.com")
    assert s >= 35


def test_short_certificate_raises_score():
    client = FakeClient(ssl_days_valid=10)
    s = _score(client, "https://expiring-cert.com")
    assert s >= 35


def test_redirects_to_other_domain_raises_score():
    client = FakeClient(redirect_count=3, redirect_final_domain="evil.io")
    # Host legítimo que redirige a un dominio distinto
    s = _score(client, "https://www.example.com")
    assert s >= 35


def test_password_form_adds_score():
    # HTML con form de password
    client = FakeClient(html="<html><input type='password'></html>")
    benign = FakeClient(html="<html><p>hola</p></html>")
    a = _score(client, "https://login.example.com")
    b = _score(benign, "https://login.example.com")
    assert a > b


def test_network_engine_degrades_on_connection_error():
    class BrokenClient:
        def resolve(self, host):
            raise ConnectionError("red caída")

        def ssl_days_valid(self, host):
            raise ConnectionError("red caída")

        def redirect_chain_to(self, url):
            raise ConnectionError("red caída")

        def rdap_creation_days(self, domain):
            raise ConnectionError("red caída")

        def fetch_html(self, url):
            raise ConnectionError("red caída")

    engine = NetworkEngine(BrokenClient())
    result = engine.analyze(AnalysisContext.from_url("https://x.com"))
    assert result.estado == "error"
    assert "no disponible" in " ".join(result.motivos).lower() or any(
        "red" in m.lower() for m in result.motivos
    )


# ---------------------------------------------------------------------------------------
# Paralelismo, presupuesto de tiempo (RNF2) y seguridad (SSRF)
# ---------------------------------------------------------------------------------------
import time

from app.engines.base import EngineStatus


class SlowClient(FakeClient):
    """Cada chequeo tarda `delay` segundos."""

    def __init__(self, delay=0.4, slow=None, **overrides):
        super().__init__(**overrides)
        self._delay = delay
        self._slow = slow  # None = todos lentos; o el nombre de un único método lento

    def _wait(self, name):
        if self._slow is None or self._slow == name:
            time.sleep(self._delay)

    def resolve(self, host):
        self._wait("resolve")
        return super().resolve(host)

    def ssl_days_valid(self, host):
        self._wait("ssl")
        return super().ssl_days_valid(host)

    def redirect_chain_to(self, url):
        self._wait("redirect")
        return super().redirect_chain_to(url)

    def rdap_creation_days(self, domain):
        self._wait("rdap")
        return super().rdap_creation_days(domain)

    def fetch_html(self, url):
        self._wait("html")
        return super().fetch_html(url)


def test_checks_run_in_parallel():
    """Cinco chequeos de 0,4 s en serie tardarían 2 s; en paralelo, cerca de 0,8 s."""
    engine = NetworkEngine(SlowClient(delay=0.4), budget=3.0)
    t0 = time.monotonic()
    result = engine.analyze(AnalysisContext.from_url("https://www.example.com"))
    elapsed = time.monotonic() - t0
    assert result.estado == EngineStatus.OK
    assert elapsed < 1.4


def test_slow_check_is_skipped_within_budget():
    engine = NetworkEngine(SlowClient(delay=1.5, slow="rdap"), budget=0.3)
    t0 = time.monotonic()
    result = engine.analyze(AnalysisContext.from_url("https://www.example.com"))
    elapsed = time.monotonic() - t0
    assert elapsed < 1.0
    assert result.estado == EngineStatus.OK
    assert any("antigüedad del dominio" in m and "no respondió" in m for m in result.motivos)


def test_partial_failure_keeps_other_checks():
    class RdapDown(FakeClient):
        def rdap_creation_days(self, domain):
            raise ConnectionError("rdap caído")

    result = NetworkEngine(RdapDown(resolve=False)).analyze(
        AnalysisContext.from_url("https://www.example.com")
    )
    assert result.estado == EngineStatus.OK
    assert any("no resuelve" in m for m in result.motivos)


def test_private_host_is_not_queried():
    class PrivateClient(FakeClient):
        def is_public_host(self, host):
            return False

        def resolve(self, host):
            raise AssertionError("no debe consultar la red de un host privado")

    result = NetworkEngine(PrivateClient()).analyze(AnalysisContext.from_url("http://10.0.0.5/admin"))
    assert result.estado == EngineStatus.NO_DISPONIBLE
    assert any("privada" in m for m in result.motivos)


class _Resp:
    def __init__(self, status=200, location=None, body=b"<html>ok</html>"):
        self.status_code = status
        self.headers = {"Location": location} if location else {}
        self.is_redirect = bool(location) and status in (301, 302, 303, 307, 308)
        self.encoding = "utf-8"
        self._body = body
        self.raw = self
        self.closed = False

    def read(self, n, decode_content=True):
        return self._body[:n]

    def close(self):
        self.closed = True


def test_fetch_page_does_not_follow_redirect_to_private_network(monkeypatch):
    import requests

    from app.engines import red

    calls = []

    def fake_get(url, **kwargs):
        calls.append(url)
        assert kwargs["allow_redirects"] is False
        return _Resp(302, location="http://169.254.169.254/latest/meta-data")

    monkeypatch.setattr(requests, "get", fake_get)
    monkeypatch.setattr(red, "is_public_host", lambda h: h != "169.254.169.254")

    hops, final, html = red.RealNetworkClient().fetch_page("https://acortado.example.com/x")
    assert calls == ["https://acortado.example.com/x"]   # nunca se pidió la IP interna
    assert hops == 1 and final == "169.254.169.254" and html == ""


def test_fetch_page_returns_html_and_follows_public_redirects(monkeypatch):
    import requests

    from app.engines import red

    responses = iter([_Resp(301, location="/nuevo"), _Resp(200, body=b"<html>hola</html>")])
    monkeypatch.setattr(requests, "get", lambda url, **kw: next(responses))
    monkeypatch.setattr(red, "is_public_host", lambda h: True)

    hops, final, html = red.RealNetworkClient().fetch_page("https://example.com/viejo")
    assert (hops, final, html) == (1, "example.com", "<html>hola</html>")


def test_fetch_page_stops_after_max_hops(monkeypatch):
    import requests

    from app.engines import red

    calls = []

    def loop(url, **kwargs):
        calls.append(url)
        return _Resp(302, location="https://example.com/otra")

    monkeypatch.setattr(requests, "get", loop)
    monkeypatch.setattr(red, "is_public_host", lambda h: True)

    hops, _, html = red.RealNetworkClient().fetch_page("https://example.com/a")
    assert hops == red.RealNetworkClient.MAX_HOPS
    assert len(calls) == red.RealNetworkClient.MAX_HOPS + 1
    assert html == ""
