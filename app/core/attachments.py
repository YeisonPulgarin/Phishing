"""Revisión de los archivos adjuntos de un correo.

No se abre ni se ejecuta nada: solo se miran el nombre del archivo, el tipo que declara el
correo y los primeros bytes del contenido (su "firma"). Con eso basta para reconocer las
trampas típicas del phishing con adjuntos:

- programas y scripts (.exe, .scr, .js, .vbs, .bat, .ps1, .hta, .lnk, ...);
- doble extensión: "factura.pdf.exe" se ve como un PDF pero es un programa;
- el truco RTLO: un carácter invisible que invierte el texto ("factura‮fdp.exe" se ve
  como "facturaexe.pdf");
- archivo disfrazado: dice ser .pdf o .jpg pero por dentro es un programa de Windows;
- imágenes de disco (.iso, .img) usadas para colar programas esquivando avisos;
- comprimidos .zip que esconden un ejecutable o vienen con contraseña;
- documentos de Office con macros y páginas web (.html, .svg) que imitan un inicio de sesión.
"""
from __future__ import annotations

import io
import re
import zipfile
from dataclasses import dataclass, field
from typing import List, Optional

# Programas y scripts: abrirlos ejecuta código en el equipo.
EXECUTABLE_EXT = {
    "exe", "scr", "com", "pif", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "wsh", "ps1",
    "psm1", "msi", "msp", "hta", "cpl", "jar", "lnk", "reg", "dll", "apk", "app", "sh", "run",
    "appx", "appxbundle", "msix", "scf", "url", "chm", "gadget", "inf",
}
# Imágenes de disco: se montan como una unidad y saltan avisos de seguridad de Windows.
DISK_IMAGE_EXT = {"iso", "img", "vhd", "vhdx"}
# Office con macros: pueden ejecutar código si se "habilita el contenido".
MACRO_EXT = {"docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppam", "ppsm", "sldm"}
# Páginas web adjuntas: suelen imitar un formulario de inicio de sesión.
HTML_EXT = {"html", "htm", "shtml", "xhtml", "svg", "mht", "mhtml"}
# Comprimidos: pueden esconder cualquiera de los anteriores.
ARCHIVE_EXT = {"zip", "rar", "7z", "gz", "tgz", "tar", "cab", "ace", "arj", "bz2", "xz", "lzh"}
# Extensiones "inofensivas" que se usan como disfraz delante de la real.
DECOY_EXT = {
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "jpg", "jpeg", "png",
    "gif", "bmp", "csv", "odt", "ods", "mp3", "mp4", "zip",
}
# Tipos MIME que declaran abiertamente un programa.
EXECUTABLE_MIME = {
    "application/x-msdownload", "application/x-msdos-program", "application/x-dosexec",
    "application/x-executable", "application/vnd.microsoft.portable-executable",
    "application/x-ms-installer", "application/x-msi", "application/hta",
}
# Caracteres de control de dirección (invisibles) que permiten invertir cómo se ve el nombre.
_BIDI = set("‪‫‬‭‮⁦⁧⁨⁩‎‏")

ALTO, MEDIO, BAJO = "alto", "medio", "bajo"
_ORDER = {BAJO: 0, MEDIO: 1, ALTO: 2}
# Cuánto aporta cada nivel al puntaje del correo (0-100), igual que un enlace analizado.
RISK_SCORE = {ALTO: 85.0, MEDIO: 45.0, BAJO: 0.0}
MAX_ZIP_ENTRIES = 200


@dataclass
class Attachment:
    """Un adjunto y lo que se encontró en él."""

    nombre: str
    tipo: str = ""
    tamano: int = 0
    riesgo: str = BAJO
    motivos: List[str] = field(default_factory=list)

    def _raise(self, level: str, reason: str) -> None:
        if _ORDER[level] > _ORDER[self.riesgo]:
            self.riesgo = level
        if reason not in self.motivos:
            self.motivos.append(reason)

    @property
    def score(self) -> float:
        return RISK_SCORE[self.riesgo]

    def as_dict(self) -> dict:
        return {"nombre": self.nombre, "tipo": self.tipo, "tamano": self.tamano,
                "riesgo": self.riesgo, "motivos": list(self.motivos)}


def safe_name(name: str) -> str:
    """Nombre con los caracteres invisibles de dirección a la vista ("[RTLO]"), para que al
    mostrarlo en un aviso no se invierta ni engañe a quien lo lee."""
    return "".join("[RTLO]" if ch in _BIDI else ch for ch in (name or ""))


def _split_name(name: str) -> tuple[str, str]:
    """(extensión real, extensión anterior) en minúsculas. Windows ignora puntos y
    espacios al final del nombre, así que también se ignoran aquí."""
    clean = name.strip().lower().rstrip(". ")
    parts = clean.split(".")
    if len(parts) < 2:
        return "", ""
    ext = parts[-1].strip()
    prev = parts[-2].strip() if len(parts) > 2 else ""
    return ext, prev


def _check_name(att: Attachment, name: str, inside: Optional[str] = None) -> None:
    """Señales que salen solo del nombre. `inside` = nombre del comprimido que lo contiene."""
    where = f"El comprimido trae «{safe_name(name)}»: " if inside else ""
    if any(ch in _BIDI for ch in name):
        att._raise(ALTO, f"{where}El nombre trae un carácter invisible que invierte el texto "
                         "(truco RTLO): lo que ves no es la extensión real")
        name = "".join(ch for ch in name if ch not in _BIDI)
    ext, prev = _split_name(name)

    if ext in EXECUTABLE_EXT:
        if prev in DECOY_EXT:
            att._raise(ALTO, f"{where}Doble extensión: parece un archivo .{prev}, "
                             f"pero en realidad es un programa .{ext}")
        else:
            att._raise(ALTO, f"{where}Es un programa o script (.{ext}): "
                             "abrirlo ejecuta código en tu equipo")
    elif ext in DISK_IMAGE_EXT:
        att._raise(ALTO, f"{where}Es una imagen de disco (.{ext}): se usa para colar programas "
                         "esquivando los avisos de seguridad de Windows")
    elif ext in MACRO_EXT:
        att._raise(MEDIO, f"{where}Documento de Office con macros (.{ext}): puede ejecutar "
                          "código si le das a «Habilitar contenido»")
    elif ext in HTML_EXT:
        att._raise(MEDIO, f"{where}Página web adjunta (.{ext}): suele imitar un formulario de "
                          "inicio de sesión para robar contraseñas")

    # Muchos espacios seguidos empujan la extensión real fuera de la vista.
    if re.search(r"\s{4,}", name):
        att._raise(MEDIO, f"{where}El nombre tiene muchos espacios seguidos para esconder "
                          "su extensión real")


def _check_zip(att: Attachment, data: bytes) -> None:
    """Mira la lista de archivos de un .zip (sin descomprimir nada)."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infos = zf.infolist()[:MAX_ZIP_ENTRIES]
    except (zipfile.BadZipFile, OSError, ValueError, RuntimeError):
        att._raise(MEDIO, "Dice ser un comprimido, pero no se pudo leer su contenido")
        return
    if any(info.flag_bits & 0x1 for info in infos):
        att._raise(MEDIO, "Comprimido protegido con contraseña: así los antivirus no pueden "
                          "revisar lo que trae")
    for info in infos:
        if info.is_dir():
            continue
        inner = info.filename.rsplit("/", 1)[-1]
        _check_name(att, inner, inside=att.nombre)


def classify(name: Optional[str], content_type: str = "", data: bytes = b"") -> Attachment:
    """Clasifica un adjunto por su nombre, su tipo declarado y su firma (primeros bytes)."""
    raw_name = (name or "").strip() or "(sin nombre)"
    att = Attachment(nombre=raw_name, tipo=(content_type or "").lower(), tamano=len(data or b""))

    _check_name(att, raw_name)
    ext, _ = _split_name("".join(ch for ch in raw_name if ch not in _BIDI))
    head = (data or b"")[:4]
    is_program = head[:2] == b"MZ" or head == b"\x7fELF"
    if is_program and ext not in EXECUTABLE_EXT | DISK_IMAGE_EXT:
        shown = f".{ext}" if ext else "un archivo sin extensión"
        att._raise(ALTO, f"Está disfrazado: dice ser {shown}, pero por dentro es un programa")
    if att.tipo in EXECUTABLE_MIME and ext not in EXECUTABLE_EXT:
        att._raise(ALTO, "El correo lo declara como un programa ejecutable, aunque su nombre "
                         "no lo parezca")

    if ext == "zip" or (head[:2] == b"PK" and ext in ARCHIVE_EXT):
        _check_zip(att, data or b"")
    elif ext in ARCHIVE_EXT and att.riesgo == BAJO:
        att.motivos.append(f"Comprimido .{ext}: no se puede revisar por dentro; ábrelo solo si "
                           "lo esperabas")
    return att
