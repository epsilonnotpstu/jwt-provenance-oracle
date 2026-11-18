# PREREG-G4 — Scaling the G3 grammar to saturation with a pre-declared stopping rule; NumericDate as its own stratum

> Study-specific instance of `PREREG_METHODOLOGY.md`. It is registered when this file, `corpus_g4/gen_corpus_g4.py`,
> `g4_interim.py` and `analyze_g4.py` are committed **before** batch 1 is generated. Deviations are appended at
> the end and never edited.

## 0. Motivation (from EXP_g3)

1. **The G3 grammar is not saturated.** It shows 593 distinct acceptance vectors, Chao1 ≈ 914 and Good–Turing
   P(new) = 4.05%. More tokens under this grammar should show new cross-verifier behaviour, so the corpus is scaled
   until a pre-declared saturation criterion is met.
2. **91% of G3's v4-IJ false positives came from NumericDate truncation.** That is a single, well-understood,
   low-impact coercion class. The decision to separate it was made **after** seeing G3, so it is tested here on
   fresh data only. The post-hoc G3 value (0.46%) is never pooled with G4.

## 1. Subjects and oracle

- **Subjects.** As in `PREREG_g3.md` §1: 32 primary implementations plus 3 new-ecosystem implementations
  (descriptive). Adapters are at commit `8f19c99`: PHP fix `2e8eb2f`, output-encoding fixes D1 and D2.
- **Oracle.** v4-IJ exactly as in `PREREG_g3.md` §3 (primary). v4-exact and v3 are reported as in G3.

## 2. Corpus and stopping rule

- **Grammar.** `corpus_g3/gen_corpus_g3.py`, frozen at `948d312`, unchanged.
- **Batches.** Batch *k* = 1, 2, … has 4,000 tokens (800 per depth d = 0..4), with seed `20261100 + k`. Case ids
  are `G4/b<k>/d<d>/<i>`.
- **Interim look (after each batch).** `g4_interim.py` computes **only** acceptance vectors over the 32 primary
  implementations for all batches so far:
  - distinct vectors;
  - Good–Turing P(new) = f1 / N;
  - Chao1.
  It does **not** compute v4, v3 or any baseline.
- **Stop** when Good–Turing P(new) < 0.5%, or when N reaches 24,000 (6 batches), whichever comes first. The final
  batch count and the interim table are reported.
- **Denominators.** Because the stopping rule looks at acceptance vectors only, and those are not the FP outcome,
  the FP analysis is run once, after stopping, on all batches.

**Strata.** The primary stratum excludes `nonconformant`, `must_reject`, `parse_ambiguous`, `non_ijson`
(as in G3) **and `numdate_frac`** (new). `numdate_frac` is reported as its own stratum.

## 3. Hypotheses

| id | statement | test |
|---|---|---|
| H4-1 | Primary FPR_v4-IJ ≤ 1.0%; token-clustered bootstrap upper ≤ 2.0%; per-accepted ≤ 1.0% | single pre-specified decision |
| H4-2 | v4-IJ token-level flags < B0 and < B2. B1 expected quieter than v4, as in g2/G3 (reported) | exact McNemar, Holm, α = 0.05 |
| H4-3 | ≥ 24 of 32 implementations have 0 A and a rule-of-three bound ≤ 0.1%. **Expected in advance: not met**, because the class-level coercions seen in G3 (`{}`→`[]`, big-int-as-string, claim-name normalization) are not NumericDate-related | reported as achieved |
| H4-4 | B0 honest-FP rises with depth (replication of H3-4) | one-sided Cochran–Armitage, α = 0.05 |
| H4-5 | The stopping rule is met within 24,000 tokens | reported with the interim table |

**Descriptive**
- the `numdate_frac` stratum, per implementation;
- the coercion catalogue by class;
- conformance strata;
- the new-ecosystem set;
- the v1 resource `PROV` column (excluded from all tests).

`analyze_g4.py` reuses `analyze_g3.py` (frozen at `948d312`), with the stratum set above. Its printed labels
H3-1…H3-5 map to H4-1, H4-2, H4-3, H4-4 and (descriptive vs g2) respectively. H4-5 comes from `g4_interim.py`.

## 4. Interpretation and threats

These are as in `PREREG_g3.md` §§5–6, with one addition, which follows the amended disclosure policy
(`PLAN_scale30.md` §0.5 amendment, 2026-09-25). The claim-name normalization lead observed in G3 is reported
privately to its maintainer. The paper may name the implementation and describe the behaviour, but gives no exploit
or crafted token. Its counts are included in all pre-registered rates.

## 5. Frozen artefacts

| artefact | value |
|---|---|
| seeds | 20261101, 20261102, … (one per batch) |
| generator | `corpus_g3/gen_corpus_g3.py` @ `948d312`, called through `corpus_g4/gen_corpus_g4.py` |
| adapters | @ `8f19c99` |
| analysis | commit that adds this file |

## Deviations
