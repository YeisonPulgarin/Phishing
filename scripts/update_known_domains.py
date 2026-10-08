"""Amplía la lista de dominios de reputación con el ranking público Tranco.

Uso:
    python scripts/update_known_domains.py [N]        # N = cuántos dominios (default 5000)

Descarga la lista Tranco más reciente (https://tranco-list.eu), descarta plataformas que alojan
contenido de terceros y acortadores, y escribe `data/known_domains_tranco.txt`. El pipeline la
suma a `data/known_domains.txt` si existe. Necesita internet. Si la descarga falla, baja el CSV
a mano de https://tranco-list.eu y pasá su ruta:  python scripts/update_known_domains.py 5000 ruta.csv
"""
from __future__ import annotations

import io
import sys
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.engines.reputation import parse_tranco  # noqa: E402

URL = "https://tranco-list.eu/top-1m.csv.zip"
OUT = ROOT / "data/known_domains_tranco.txt"


def read_csv_text(local: str | None) -> str:
    if local:
        return Path(local).read_text(encoding="utf-8")
    request = urllib.request.Request(URL, headers={"User-Agent": "phishing-detector/1.0"})
    with urllib.request.urlopen(request, timeout=90) as resp:
        data = resp.read()
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        return zf.read(zf.namelist()[0]).decode("utf-8")


def main() -> None:
    top_n = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    local = sys.argv[2] if len(sys.argv) > 2 else None
    try:
        text = read_csv_text(local)
    except OSError as exc:
        sys.exit(f"No pude obtener la lista Tranco ({exc}). Bajala a mano y pasá la ruta del CSV.")
    domains = parse_tranco(text.splitlines(), top_n)
    OUT.write_text(
        "# Generado por scripts/update_known_domains.py a partir del ranking Tranco.\n"
        + "\n".join(domains) + "\n",
        encoding="utf-8",
    )
    print(f"Guardados {len(domains)} dominios en {OUT}")


if __name__ == "__main__":
    main()
