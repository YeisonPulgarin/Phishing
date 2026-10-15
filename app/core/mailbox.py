"""Lectura del buzón por IMAP.

Conecta con el servidor de correo propio (Dovecot) para traer los correos recibidos y
poder clasificarlos con el mismo motor que analiza correos pegados a mano. También puede
mover un correo a una carpeta de cuarentena cuando el veredicto es phishing.

Solo usa la librería estándar (`imaplib`), así que no agrega dependencias al proyecto.
"""
from __future__ import annotations

import imaplib
import ssl
from dataclasses import dataclass
from typing import List


class MailboxError(RuntimeError):
    """Falla al hablar con el servidor IMAP (conexión, credenciales o buzón)."""


@dataclass
class InboxMessage:
    """Un correo tal como vino del servidor, sin interpretar."""

    uid: str
    raw: str


def _tls_context() -> ssl.SSLContext:
    """TLS aceptando el certificado autofirmado que trae el servidor del laboratorio.

    Cifra la contraseña en tránsito, que es lo que exige Dovecot, sin pedir una autoridad
    certificadora real: en un servidor de producción habría que validar el certificado.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _decode(data: bytes | str) -> str:
    if isinstance(data, bytes):
        # Los correos pueden traer cualquier codificación; no queremos que un byte raro
        # tumbe la bandeja completa, así que reemplazamos lo que no se pueda decodificar.
        return data.decode("utf-8", "replace")
    return str(data)


class Mailbox:
    """Cliente IMAP mínimo: listar los últimos correos y mover uno de carpeta."""

    def __init__(
        self,
        host: str = "",
        port: int = 143,
        user: str = "",
        password: str = "",
        use_ssl: bool = False,
        mailbox: str = "INBOX",
        timeout: float = 8.0,
        starttls: bool = True,
    ) -> None:
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.use_ssl = use_ssl
        self.mailbox = mailbox
        self.timeout = timeout
        self.starttls = starttls

    @property
    def enabled(self) -> bool:
        """Sin host y usuario configurados la bandeja simplemente no se ofrece."""
        return bool(self.host and self.user)

    # ------------------------------------------------------------------ conexión
    def _connect(self):
        if not self.enabled:
            raise MailboxError("La bandeja no está configurada (falta PD_IMAP_HOST o PD_IMAP_USER).")
        try:
            if self.use_ssl:
                conn = imaplib.IMAP4_SSL(self.host, self.port, ssl_context=_tls_context(), timeout=self.timeout)
            else:
                conn = imaplib.IMAP4(self.host, self.port, timeout=self.timeout)
        except OSError as exc:
            raise MailboxError(
                f"No se pudo conectar con el servidor de correo en {self.host}:{self.port}. "
                "Revisa que la máquina virtual esté encendida y que Dovecot esté corriendo."
            ) from exc

        # Dovecot no acepta la contraseña por una conexión sin cifrar (PRIVACYREQUIRED).
        # Si ofrece STARTTLS, subimos la misma conexión a TLS antes de autenticarnos: así
        # la contraseña viaja cifrada y no hay que debilitar la configuración del servidor.
        if not self.use_ssl and self.starttls and "STARTTLS" in getattr(conn, "capabilities", ()):
            try:
                conn.starttls(ssl_context=_tls_context())
            except (imaplib.IMAP4.error, OSError, ValueError):
                pass        # si falla, seguimos: el login dirá el motivo real

        try:
            conn.login(self.user, self.password)
        except imaplib.IMAP4.error as exc:
            self._close(conn)
            reason = _decode(exc.args[0]) if exc.args else ""
            if "PRIVACYREQUIRED" in reason or "Plaintext authentication" in reason:
                raise MailboxError(
                    "El servidor exige una conexión cifrada para autenticarse y no se pudo "
                    "establecer. Prueba con IMAP sobre SSL: PD_IMAP_PORT=993 y PD_IMAP_SSL=true."
                ) from exc
            raise MailboxError(
                f"El servidor rechazó el usuario '{self.user}'. "
                f"{reason or 'Revisa el usuario y la contraseña.'}"
            ) from exc
        return conn

    @staticmethod
    def _close(conn) -> None:
        try:
            conn.logout()
        except Exception:
            pass

    def _select(self, conn, mailbox: str, readonly: bool = True) -> None:
        status, _ = conn.select(f'"{mailbox}"', readonly=readonly)
        if status != "OK":
            raise MailboxError(f"No se pudo abrir el buzón '{mailbox}'.")

    # ------------------------------------------------------------------ lectura
    def fetch_recent(self, limit: int = 20) -> List[InboxMessage]:
        """Trae los últimos `limit` correos del buzón, del más reciente al más antiguo."""
        conn = self._connect()
        try:
            self._select(conn, self.mailbox, readonly=True)
            status, data = conn.uid("search", None, "ALL")
            if status != "OK":
                raise MailboxError("El servidor no pudo listar los correos del buzón.")
            uids = (data[0] or b"").split()
            recent = uids[-max(1, limit):]
            out: List[InboxMessage] = []
            for uid in reversed(recent):                      # más reciente primero
                status, payload = conn.uid("fetch", uid, "(RFC822)")
                if status != "OK" or not payload or not isinstance(payload[0], tuple):
                    continue
                out.append(InboxMessage(uid=uid.decode(), raw=_decode(payload[0][1])))
            return out
        finally:
            self._close(conn)

    # ------------------------------------------------------------------ cuarentena
    def move(self, uid: str, folder: str) -> None:
        """Mueve un correo a `folder`, creándola si no existe (cuarentena)."""
        conn = self._connect()
        try:
            conn.create(f'"{folder}"')                        # si ya existe, el servidor responde NO y seguimos
            conn.subscribe(f'"{folder}"')
            self._select(conn, self.mailbox, readonly=False)
            target = uid.encode() if isinstance(uid, str) else uid

            # MOVE (RFC 6851) es atómico y Dovecot lo soporta; si no está, copiamos y borramos.
            try:
                status, _ = conn.uid("move", target, f'"{folder}"')
            except imaplib.IMAP4.error:
                status = "NO"
            if status != "OK":
                status, _ = conn.uid("copy", target, f'"{folder}"')
                if status != "OK":
                    raise MailboxError(f"No se pudo copiar el correo a la carpeta '{folder}'.")
                conn.uid("store", target, "+FLAGS", "(\\Deleted)")
                conn.expunge()
        finally:
            self._close(conn)
