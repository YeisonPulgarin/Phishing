"""Tests de la guarda SSRF (app.engines.netguard)."""
import socket

import pytest

from app.engines.netguard import is_public_host


@pytest.mark.parametrize("host", [
    "127.0.0.1", "10.0.0.5", "172.16.3.4", "192.168.1.1",
    "169.254.169.254",          # metadatos de nube
    "0.0.0.0", "::1", "[::1]", "::ffff:127.0.0.1", "100.64.0.1", "224.0.0.1", "",
])
def test_non_public_addresses_are_blocked(host):
    assert is_public_host(host) is False


@pytest.mark.parametrize("host", ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])
def test_public_addresses_are_allowed(host):
    assert is_public_host(host) is True


def _fake_resolver(addresses):
    def _getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, 0)) for a in addresses]
    return _getaddrinfo


def test_hostname_resolving_to_private_ip_is_blocked(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_resolver(["10.1.2.3"]))
    assert is_public_host("intranet.evil.com") is False


def test_hostname_with_any_private_address_is_blocked(monkeypatch):
    # Basta una dirección privada entre varias para bloquear.
    monkeypatch.setattr(socket, "getaddrinfo", _fake_resolver(["93.184.216.34", "127.0.0.1"]))
    assert is_public_host("mixto.example.com") is False


def test_hostname_resolving_to_public_ip_is_allowed(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_resolver(["93.184.216.34"]))
    assert is_public_host("example.com") is True


def test_unresolvable_hostname_is_not_blocked(monkeypatch):
    def _boom(*args, **kwargs):
        raise socket.gaierror("no resuelve")
    monkeypatch.setattr(socket, "getaddrinfo", _boom)
    # No hay a qué conectarse; el chequeo DNS del motor lo reporta como señal.
    assert is_public_host("no-existe.example") is True
