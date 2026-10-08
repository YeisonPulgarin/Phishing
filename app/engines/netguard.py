"""Protección contra SSRF para el motor de red.

El detector se conecta a hosts que elige el usuario. Sin esta guarda, alguien podría pedir el
análisis de `http://127.0.0.1:8000`, `http://169.254.169.254/` (metadatos de nube) o de una
IP de la red interna y usar al servidor como proxy. `is_public_host` devuelve False si el
host es, o resuelve a, una dirección privada, loopback, link-local, reservada o multicast.

Limitación conocida: entre la resolución de esta guarda y la conexión real un atacante con
control de su DNS podría cambiar la respuesta (DNS rebinding). Se documenta en el análisis de
limitaciones; no se intenta resolver acá.
"""
from __future__ import annotations

import ipaddress
import socket


def _ip_is_public(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    # ::ffff:127.0.0.1 y similares: se evalúa la IPv4 embebida.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def is_public_host(host: str) -> bool:
    """True si es seguro conectarse al host (todas sus direcciones son públicas)."""
    host = (host or "").strip().strip("[]").rstrip(".")
    if not host:
        return False
    try:
        return _ip_is_public(ipaddress.ip_address(host))
    except ValueError:
        pass  # es un nombre de dominio: se resuelve abajo

    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        # No resuelve: no hay a qué conectarse. El chequeo DNS del motor lo reporta.
        return True

    addresses = {info[4][0].split("%")[0] for info in infos}
    return all(_ip_is_public(ipaddress.ip_address(a)) for a in addresses)
