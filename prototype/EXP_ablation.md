# Ablation study — provenance oracle components

| Variant | FP / 24 valid | format-safe wrongly flagged? | format-confusion caught | JWE bomb caught |
|---|---|---|---|---|
| D0 naive differential | 9 | no | yes | **no (miss)** |
| D1 provenance (full) | 0 | no | yes | yes |
| D2  − belief refinement | 0 | **yes (FP)** | yes | yes |
| D3  − resource oracle | 0 | no | yes | **no (miss)** |

Each removed component breaks exactly one guarantee: the belief refinement prevents mislabelling a format-safe verifier as an attack; the resource oracle is the only component that catches the decompression bomb; and provenance itself is what drives the false-positive rate from 37.5% (D0) to 0% (D1).
