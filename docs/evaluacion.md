# Evaluación comparativa: reglas vs ML vs combinado

Test: 52147 URLs de dominios que el modelo no vio (25296 phishing, 26851 legítimas). Generado con `python scripts/evaluate.py`.

El motor de red y los conectores quedan fuera: dependen de consultas en vivo.

## Alerta desde score 35 (sospechoso o phishing)

| Sistema | Accuracy | Precisión | Recall | F1 | AUC-ROC |
|---|---|---|---|---|---|
| Reglas heurísticas (URL completa) | 0.565 | 0.949 | 0.108 | 0.195 | 0.727 |
| Reglas heurísticas (solo dominio) | 0.565 | 0.949 | 0.108 | 0.195 | 0.563 |
| Modelo ML | 0.817 | 0.805 | 0.821 | 0.813 | 0.898 |
| Combinado: heurística (URL completa) + ML | 0.862 | 0.935 | 0.769 | 0.844 | 0.928 |
| Combinado: heurística (solo dominio) + ML | 0.858 | 0.935 | 0.761 | 0.839 | 0.901 |

## Alerta desde score 60 (solo phishing)

| Sistema | Accuracy | Precisión | Recall | F1 | AUC-ROC |
|---|---|---|---|---|---|
| Reglas heurísticas (URL completa) | 0.519 | 1.000 | 0.009 | 0.018 | 0.727 |
| Reglas heurísticas (solo dominio) | 0.519 | 1.000 | 0.009 | 0.018 | 0.563 |
| Modelo ML | 0.847 | 0.955 | 0.719 | 0.820 | 0.898 |
| Combinado: heurística (URL completa) + ML | 0.823 | 0.995 | 0.639 | 0.778 | 0.928 |
| Combinado: heurística (solo dominio) + ML | 0.819 | 0.995 | 0.629 | 0.771 | 0.901 |
