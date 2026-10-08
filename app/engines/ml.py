"""Motor de detección ML.

Extrae features léxicas de la URL y usa un clasificador entrenado (Random Forest) para
producir un sub-score = probabilidad de phishing × 100. El modelo se inyecta (o se carga
desde `model.joblib`) para poder testear con un clasificador fake sin red.
"""
from __future__ import annotations

import math
from typing import TYPE_CHECKING, List, Protocol, runtime_checkable
from urllib.parse import urlsplit

from app.engines.base import AnalysisContext, EngineResult

if TYPE_CHECKING:
    from app.engines.reputation import ReputationList

_CREDENTIAL_WORDS = {
    "login", "verify", "secure", "account", "password", "banking",
    "webscr", "update", "signin", "bill", "invoice", "confirm",
    "token", "auth", "wallet", "benefit",
}


# Las 13 features léxicas originales, en el orden de `FeatureExtractor.extract`.
LEGACY_FEATURES = [
    "url_len", "num_dots", "num_dashes", "path_depth", "num_subdomains", "is_ip",
    "has_at", "uses_https", "digit_ratio", "keyword_hits", "encoded_ratio",
    "host_entropy", "short_host",
]

# Features que ve el modelo: solo estructura del dominio (ver `canonical_ml_url`). Se omiten
# `url_len` (redundante con `host_len`) y las que son constantes al quitar esquema y ruta
# (`path_depth`, `uses_https`, `keyword_hits`, `encoded_ratio`).
ML_FEATURES = [
    "num_dots", "num_dashes", "num_subdomains", "is_ip", "has_at", "digit_ratio",
    "host_entropy", "short_host", "host_len", "domain_label_len", "tld_len", "num_labels",
    "max_label_len", "digits_in_host", "longest_digit_run", "hyphens_in_domain",
    "hyphen_in_subdomain", "digit_in_subdomain", "subdomain_len", "vowel_ratio",
    "longest_consonant_run", "domain_entropy", "tld_com", "tld_org_net_edu_gov",
    "multi_level_suffix",
]

# Descripción en lenguaje simple de cada feature (RNF5: salida comprensible sin jerga).
FEATURE_LABELS = {
    "num_dots": "Cantidad de puntos en el dominio",
    "num_dashes": "Cantidad de guiones en el dominio",
    "num_subdomains": "Cantidad de subdominios",
    "is_ip": "El dominio es una dirección IP",
    "has_at": "La dirección tiene un usuario antes del dominio (@)",
    "digit_ratio": "Proporción de números en el dominio",
    "host_entropy": "Qué tan aleatorio parece el dominio",
    "short_host": "Dominio muy corto",
    "host_len": "Longitud del dominio completo",
    "domain_label_len": "Longitud del nombre principal del dominio",
    "tld_len": "Longitud de la terminación (.com, .tk...)",
    "num_labels": "Cantidad de partes separadas por puntos",
    "max_label_len": "Longitud de la parte más larga del dominio",
    "digits_in_host": "Cantidad de números en el dominio",
    "longest_digit_run": "Racha más larga de números seguidos",
    "hyphens_in_domain": "Guiones en el nombre principal",
    "hyphen_in_subdomain": "Hay guiones en el subdominio",
    "digit_in_subdomain": "Hay números en el subdominio",
    "subdomain_len": "Longitud del subdominio",
    "vowel_ratio": "Proporción de vocales en el nombre principal",
    "longest_consonant_run": "Racha más larga de consonantes seguidas",
    "domain_entropy": "Qué tan aleatorio parece el nombre principal",
    "tld_com": "Termina en .com",
    "tld_org_net_edu_gov": "Termina en .org, .net, .edu o .gov",
    "multi_level_suffix": "Terminación de varios niveles (p. ej. .co.uk)",
}

_VOWELS = set("aeiou")


def _shannon(s: str) -> float:
    if not s:
        return 0.0
    from collections import Counter

    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def _longest_run(s: str, pred) -> int:
    best = cur = 0
    for ch in s:
        cur = cur + 1 if pred(ch) else 0
        best = max(best, cur)
    return best


@runtime_checkable
class Classifier(Protocol):
    """Clasificador con método predict_proba al estilo scikit-learn."""

    def predict_proba(self, X) -> "np.ndarray": ...


def canonical_ml_url(url: str) -> str:
    """Forma canónica de una URL para el modelo ML: solo la estructura del dominio.

    Se descartan esquema, `www.`, puerto, ruta y query. Motivo: en PhiUSIIL el 100% de las
    URLs legítimas son `https://www.<dominio>` sin ruta, así que esos rasgos delatan la
    clase por cómo se armó el dataset y no por el sitio. Entrenar con ellos haría que
    `https://www.google.com/about` saliera como phishing. Las palabras sensibles en la ruta
    las cubre el motor heurístico. Entrenamiento y servicio usan esta misma función.
    """
    parts = urlsplit(url if "://" in url else "https://" + url)
    host = (parts.hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    userinfo = f"{parts.username}@" if parts.username else ""
    return f"https://{userinfo}{host}"


class FeatureExtractor:
    """Convierte un AnalysisContext en un vector de features léxicas."""

    def extract(self, ctx: AnalysisContext) -> List[float]:
        host = ctx.host
        url = ctx.url
        path = ctx.path + ctx.query

        def _is_ip(h):
            try:
                import ipaddress
                ipaddress.ip_address(h)
                return True
            except ValueError:
                return False

        def _entropy(s: str) -> float:
            if not s:
                return 0.0
            from collections import Counter
            probs = [c / len(s) for c in Counter(s).values()]
            return -sum(p * math.log2(p) for p in probs)

        subdomain_levels = len([l for l in ctx.subdomain.split(".") if l])
        digit_ratio = sum(c.isdigit() for c in host) / max(len(host), 1)
        keyword_hits = sum(1 for w in _CREDENTIAL_WORDS if w in path.lower())
        encoded_ratio = url.count("%") / max(len(url), 1)

        features = [
            float(len(url)),                      # longitud URL
            float(url.count(".")),                # puntos
            float(url.count("-")),                # guiones
            float(len(ctx.path.split("/"))),      # profundidad de path
            float(subdomain_levels),              # nº subdominios
            1.0 if _is_ip(host) else 0.0,         # es IP
            1.0 if ctx.username else 0.0,         # tiene @
            1.0 if ctx.scheme == "https" else 0.0,  # usa https
            float(digit_ratio),                   # ratio de dígitos
            float(keyword_hits),                  # keywords sensibles
            float(encoded_ratio),                 # ratio de % encoded
            _entropy(host),                       # entropía del host
            1.0 if len(host) < 10 else 0.0,       # host corto
        ]
        return [round(x, 6) for x in features]


    def extract_domain(self, ctx: AnalysisContext) -> List[float]:
        """Vector de las `ML_FEATURES` (estructura del dominio). Espera un ctx canónico."""
        named = dict(zip(LEGACY_FEATURES, self.extract(ctx)))
        host = ctx.host
        sub = ctx.subdomain.lower()
        sub = "" if sub == "www" else (sub[4:] if sub.startswith("www.") else sub)
        dom = (ctx.registered_domain or host).split(".")[0]
        tld = ctx.suffix.split(".")[-1] if ctx.suffix else ""
        labels = [l for l in host.split(".") if l]
        letters = [c for c in dom if c.isalpha()]
        named.update(
            host_len=len(host),
            domain_label_len=len(dom),
            tld_len=len(tld),
            num_labels=len(labels),
            max_label_len=max((len(l) for l in labels), default=0),
            digits_in_host=sum(c.isdigit() for c in host),
            longest_digit_run=_longest_run(host, str.isdigit),
            hyphens_in_domain=dom.count("-"),
            hyphen_in_subdomain=1.0 if "-" in sub else 0.0,
            digit_in_subdomain=1.0 if any(c.isdigit() for c in sub) else 0.0,
            subdomain_len=len(sub),
            vowel_ratio=sum(c in _VOWELS for c in letters) / max(len(letters), 1),
            longest_consonant_run=_longest_run(dom, lambda c: c.isalpha() and c not in _VOWELS),
            domain_entropy=_shannon(dom),
            tld_com=1.0 if tld == "com" else 0.0,
            tld_org_net_edu_gov=1.0 if tld in {"org", "net", "edu", "gov"} else 0.0,
            multi_level_suffix=1.0 if "." in ctx.suffix else 0.0,
        )
        return [round(float(named[name]), 6) for name in ML_FEATURES]


# Tope de la estimación del ML para dominios de la lista de reputación.
REPUTABLE_ML_CAP = 10.0


class MlEngine:
    """Usa el clasificador para puntuar la probabilidad de phishing."""

    name = "ml"

    def __init__(self, model: Classifier, reputation: "ReputationList | None" = None) -> None:
        self._model = model
        self._extractor = FeatureExtractor()
        self._reputation = reputation

    @property
    def model(self) -> Classifier:
        return self._model

    def analyze(self, ctx: AnalysisContext) -> EngineResult:
        canonical = AnalysisContext.from_url(canonical_ml_url(ctx.url))
        feats = [self._extractor.extract_domain(canonical)]
        # predict_proba devuelve [[p_benign, p_malicious]]
        prob = float(self._model.predict_proba(feats)[0][1])
        score = prob * 100
        if (self._reputation is not None and score > REPUTABLE_ML_CAP
                and self._reputation.is_reputable(ctx)):
            # El modelo no distingue subdominios legítimos de phishing: se limita su peso.
            return EngineResult(
                sub_score=REPUTABLE_ML_CAP,
                motivos=[f"Dominio de alta reputación ({ctx.registered_domain}): se reduce el "
                         f"peso del modelo ML (estimaba {score:.0f}%)"],
            )
        return EngineResult(
            sub_score=score,
            motivos=[f"Modelo ML estima {score:.0f}% de probabilidad de phishing"],
        )


def load_model(path: str) -> Classifier:
    """Carga el modelo persistido con joblib."""
    import joblib

    model = joblib.load(path)
    expected = getattr(model, "n_features_in_", None)
    if expected is not None and expected != len(ML_FEATURES):
        raise RuntimeError(
            f"El modelo en {path} espera {expected} features pero el código usa "
            f"{len(ML_FEATURES)}. Reentrená con: python scripts/train_model.py"
        )
    return model
