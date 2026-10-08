"""Genera un dataset sintético de URLs etiquetadas para el entrenamiento inicial.

Produce `data/dataset/phishing.csv` con el vector de features léxicas (mismas que el
`FeatureExtractor` del motor ML) y una etiqueta 1 (phishing) / 0 (benigno).

No usa red: las URLs se sintetizan con combinaciones conocidas de señales. Un dominio
de entrenamiento ampliado con datos reales (p.ej. dataset UCI) puede reemplazar este
archivo manteniendo el mismo formato de columnas.
"""
from __future__ import annotations

import csv
import random
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "data/dataset/phishing.csv"

# Nombres de las features, en el mismo orden que FeatureExtractor.extract().
FEATURES = [
    "url_len", "num_dots", "num_dashes", "path_depth", "num_subdomains",
    "is_ip", "has_at", "uses_https", "digit_ratio", "keyword_hits",
    "encoded_ratio", "host_entropy", "short_host",
]

_BRANDS = ["paypal", "google", "amazon", "apple", "microsoft", "wellsfargo", "hsbc", "netflix"]
_KEYWORDS = ["login", "verify", "secure", "account", "password", "webscr", "signin", "confirm", "token"]


def heuristic_label(fv: list) -> int:
    """Etiqueta según señales (misma lógica aproximada que la heurística)."""
    url_len, dots, dashes, depth, subdomains, is_ip, has_at, https, digit_ratio, keywords, encoded, entropy, short = fv
    score = 0.0
    if is_ip:
        score += 40
    if has_at:
        score += 30
    if not https:
        score += 7
    if keywords >= 2:
        score += 12
    if subdomains >= 3:
        score += 12
    if dashes >= 2:
        score += 8
    if entropy < 3.2 and len(str(digit_ratio)) > 0:
        pass
    return 1 if score >= 30 else 0


def random_url_features(malicious: bool) -> list:
    if malicious:
        return [
            random.randint(60, 160),                       # url_len
            random.randint(2, 5),                          # num_dots
            random.randint(1, 5),                          # num_dashes
            random.randint(2, 7),                          # path_depth
            random.randint(0, 4),                          # num_subdomains
            float(random.random() < 0.4),                  # is_ip
            float(random.random() < 0.3),                  # has_at
            float(random.random() < 0.4),                  # uses_https
            round(random.random() * 0.6, 4),               # digit_ratio
            float(random.randint(2, 6)),                   # keyword_hits
            round(random.random() * 0.4, 4),               # encoded_ratio
            round(random.uniform(2.0, 4.2), 4),            # host_entropy
            float(random.random() < 0.3),                  # short_host
        ]
    return [
        random.randint(20, 60),                            # url_len
        random.randint(1, 2),                              # num_dots
        random.randint(0, 1),                              # num_dashes
        random.randint(1, 3),                              # path_depth
        0.0,                                               # num_subdomains
        0.0,                                               # is_ip
        0.0,                                               # has_at
        1.0,                                               # uses_https
        round(random.random() * 0.2, 4),                   # digit_ratio
        float(random.randint(0, 1)),                       # keyword_hits
        round(random.random() * 0.1, 4),                   # encoded_ratio
        round(random.uniform(3.4, 4.6), 4),                # host_entropy
        float(random.random() < 0.1),                      # short_host
    ]


def main(n: int = 11000) -> None:
    random.seed(42)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    for _ in range(n):
        malicious = random.random() < 0.5
        fv = random_url_features(malicious)
        # La etiqueta se deriva de las features para que el RF aprenda las combinaciones.
        rows.append([*fv, heuristic_label(fv)])

    with OUT.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([*FEATURES, "label"])
        writer.writerows(rows)
    print(f"Dataset generado: {OUT} ({len(rows)} filas, 11k esperadas)")


if __name__ == "__main__":
    main()
