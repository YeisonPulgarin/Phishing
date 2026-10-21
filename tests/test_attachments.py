"""Tests de la revisión de archivos adjuntos (app.core.attachments y su uso en correos)."""
import base64
import io
import zipfile

from app.core.attachments import ALTO, BAJO, MEDIO, classify
from app.core.email_analysis import parse_email
from tests.test_email_analysis import analyzer

PE_HEADER = b"MZ\x90\x00\x03\x00\x00\x00"          # firma de un programa de Windows


def _zip(*names, encrypted=False) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name in names:
            zf.writestr(name, b"contenido")
    data = bytearray(buf.getvalue())
    if encrypted:
        # zipfile no escribe zips cifrados: se marca el bit 0 ("cifrado") a mano en los
        # encabezados local (PK\3\4, offset 6) y central (PK\1\2, offset 8), como haría
        # un compresor real al poner contraseña.
        for sig, offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            pos = data.find(sig)
            while pos != -1:
                data[pos + offset] |= 0x1
                pos = data.find(sig, pos + 4)
    return bytes(data)


# -- clasificación por nombre ----------------------------------------------------------

def test_executable_is_high_risk():
    att = classify("programa.exe")
    assert att.riesgo == ALTO
    assert "programa o script" in att.motivos[0]


def test_double_extension_is_detected():
    att = classify("factura.pdf.exe")
    assert att.riesgo == ALTO
    assert "Doble extensión" in att.motivos[0] and ".pdf" in att.motivos[0]


def test_rtlo_trick_is_detected():
    # Se ve como "facturaexe.pdf", pero la extensión real es .exe
    att = classify("factura‮fdp.exe")
    assert att.riesgo == ALTO
    assert any("RTLO" in m for m in att.motivos)


def test_padding_with_spaces_is_detected():
    att = classify("documento.pdf          .exe")
    assert att.riesgo == ALTO
    assert any("espacios" in m for m in att.motivos)


def test_disk_image_macros_and_html():
    assert classify("pedido.iso").riesgo == ALTO
    assert classify("informe.docm").riesgo == MEDIO
    assert classify("inicio-sesion.html").riesgo == MEDIO


def test_normal_documents_are_low_risk():
    for name in ("reporte.pdf", "foto.JPG", "notas.txt", "datos.xlsx"):
        att = classify(name, data=b"%PDF-1.7")
        assert att.riesgo == BAJO and att.motivos == [], name


def test_missing_name_does_not_break():
    att = classify(None)
    assert att.nombre == "(sin nombre)" and att.riesgo == BAJO


# -- clasificación por contenido -------------------------------------------------------

def test_disguised_program_is_detected_by_signature():
    att = classify("foto.jpg", "image/jpeg", PE_HEADER)
    assert att.riesgo == ALTO
    assert "disfrazado" in att.motivos[0] and ".jpg" in att.motivos[0]


def test_executable_mime_type_is_detected():
    att = classify("factura.pdf", "application/x-msdownload", b"%PDF")
    assert att.riesgo == ALTO


def test_zip_hiding_an_executable():
    att = classify("documentos.zip", "application/zip", _zip("leeme.txt", "factura.pdf.exe"))
    assert att.riesgo == ALTO
    assert any("factura.pdf.exe" in m for m in att.motivos)


def test_rtlo_inside_a_zip_is_detected():
    att = classify("pagos.zip", "application/zip", _zip("recibo‮fdp.exe"))
    assert att.riesgo == ALTO
    assert any("RTLO" in m and "[RTLO]" in m for m in att.motivos)


def test_clean_zip_is_low_risk():
    att = classify("fotos.zip", "application/zip", _zip("a.jpg", "b.png"))
    assert att.riesgo == BAJO


def test_password_protected_zip_is_suspicious():
    att = classify("secreto.zip", "application/zip", _zip("datos.pdf", encrypted=True))
    assert att.riesgo == MEDIO
    assert any("contraseña" in m for m in att.motivos)


def test_uninspectable_archive_only_informs():
    att = classify("paquete.rar")
    assert att.riesgo == BAJO and "no se puede revisar" in att.motivos[0]


# -- integración con el análisis del correo --------------------------------------------

def _eml_with(filename: str, payload: bytes, ctype: str = "application/octet-stream") -> str:
    b64 = base64.b64encode(payload).decode()
    return f"""\
From: Carlos Arciniegas <carlos@correo.local>
To: yeison@correo.local
Subject: Factura del mes
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="ZZ"

--ZZ
Content-Type: text/plain; charset=utf-8

Hola, te envío la factura. Saludos.
--ZZ
Content-Type: image/png
Content-Disposition: inline; filename="logo.png"
Content-Transfer-Encoding: base64

iVBORw0KGgo=
--ZZ
Content-Type: {ctype}; name="{filename}"
Content-Disposition: attachment; filename="{filename}"
Content-Transfer-Encoding: base64

{b64}
--ZZ--
"""


def test_parse_email_reads_attachments_and_skips_inline_logos():
    m = parse_email(_eml_with("factura.pdf.exe", PE_HEADER))
    assert [a.nombre for a in m.attachments] == ["factura.pdf.exe"]   # el logo no cuenta
    assert m.attachments[0].riesgo == ALTO
    assert m.attachments[0].tamano == len(PE_HEADER)
    assert "factura" in m.body and m.urls == []


def test_dangerous_attachment_alone_makes_the_email_phishing():
    # Remitente interno, sin enlaces ni palabras raras: solo el adjunto lo delata.
    res = analyzer(trusted_domains={"correo.local"}).analyze(
        parse_email(_eml_with("factura.pdf.exe", PE_HEADER)))
    assert res["veredicto"] == "phishing"
    assert res["motivos"][0].startswith("Adjunto «factura.pdf.exe»")
    assert res["desglose"]["adjuntos"] == 85.0
    assert res["adjuntos"][0]["riesgo"] == ALTO


def test_warnings_never_carry_the_invisible_character():
    # El aviso no debe invertirse en pantalla: el nombre va con la marca [RTLO] a la vista.
    res = analyzer(trusted_domains={"correo.local"}).analyze(
        parse_email(_eml_with("comprobante.exe", PE_HEADER).replace(
            'filename="comprobante.exe"', "filename*=utf-8''comprobante%E2%80%AEfdp.exe")))
    assert res["veredicto"] == "phishing"
    assert all("‮" not in m for m in res["motivos"])
    assert res["motivos"][0].startswith("Adjunto «comprobante[RTLO]fdp.exe»")
    assert res["adjuntos"][0]["nombre"] == "comprobante‮fdp.exe"   # el dato original se conserva


def test_harmless_attachment_keeps_email_safe():
    res = analyzer(trusted_domains={"correo.local"}).analyze(
        parse_email(_eml_with("factura.pdf", b"%PDF-1.7 ...", "application/pdf")))
    assert res["veredicto"] == "seguro"
    assert res["adjuntos"][0]["riesgo"] == BAJO
    assert res["desglose"]["adjuntos"] == 0.0


def test_email_without_attachments_has_empty_list():
    res = analyzer().analyze(parse_email(
        "From: Ana <ana@universidad.edu.co>\nSubject: Hola\n\nNos vemos el lunes."))
    assert res["adjuntos"] == []
    assert "adjuntos" not in res["desglose"]
