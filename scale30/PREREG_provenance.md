# PREREG-P — Confirmatory evaluation of an issuer-provenance oracle: false-positive and detection rates

> **Status: DRAFT. Not yet registered.** It counts as registered only once it is committed **before**
> the fresh corpus (`corpus_p/`) is generated and before any adapter runs on it. Every `[DECIDE]` field
> must be filled before that commit. Later changes go in *Deviations*, with the date and reason.
> Earlier text is never edited.

## 0. Why this study exists, and what it deliberately does not re-test

The earlier evaluation (`PREREG.md`, `EXP_scale30.md`) already measured false positives (FP) on
honestly issued tokens. Two of its facts shape this design:

1. **Claim-path FP on honest tokens is zero by construction.** This follows from the soundness property
   in `ORACLE_FORMAL_v2.md`. Re-measuring it and presenting it as a confirmatory finding would be
   circular. Here it is an **integrity check** (H-P4). A non-zero value would mean a harness defect,
   such as lossy claim extraction or a wrong reference parse. It would not mean the oracle is imprecise.
2. **Detection on independently established positives was never tested under a pre-registration**
   (`PREREG.md` deviation D3). This study makes detection rate its primary confirmatory target.

This study also tests the **combined** oracle (claim path + resource path v2) on data it has never seen.
Resource v2 has so far been evaluated only on its own fresh corpus (`PREREG_resource.md`).

## 1. Definitions

- **Token** `t`; **verifier** `i` (an implementation under a fixed, documented configuration).
- **Observation** = the pair `(i, t)`. Each observation carries the adapter output `(accepted, claims, error, stage, ns)`.
- **Signed(t)**: the set of claim (name, value) pairs covered by a valid issuer signature on `t`.
  The generator computes it from construction provenance and cross-checks it with a reference parse
  (see `DESIGN_generator.md` §5).
- **belief(i, t)**: the normalized claims that `i` exposes when it accepts `t` (⊥ if it rejects).
- **Oracle labels:** OK, C (capability/strictness difference), A (security violation). The rule is in `ORACLE_FORMAL_v2.md` §3.
- **Oracle version under test:** `[DECIDE: v3 (authority-claim projection, as in oracle.py today) or v4 (full claim-set comparison)]`.
  The version is fixed by the commit hash of the analysis code recorded in §8.

## 2. Ground-truth sets (fixed before data collection)

| set | content | label source (independent of the oracle) |
|---|---|---|
| **N_h** (negatives) | every gate-passing verifier × every honestly issued token in `corpus_p` | honest issuance by construction |
| **P** (positives) | a panel of (verifier, token-family) pairs known to be defective | external evidence: a published fix with a before/after version pair, **or** a synthetic target with a documented injected defect |
| **U** (unlabelled) | current verifiers × forged tokens | none a priori; reported descriptively |

- **Panel P is fixed now.** Its list is kept in a private file. Only its SHA-256 is committed here:
  `panel_sha256 = [DECIDE]`. The list is revealed at write-up time, or later if any entry is under
  coordinated disclosure.
- A panel entry counts only if its defect **reproduces** in this pipeline. The reproduction criterion is
  written in the panel file *before* running it. Non-reproducing entries are excluded and listed with
  reasons, and they are not counted as misses.
- **P is split into two strata, each reported separately:**
  - **P_claim** — defects that surface as an unsigned claim in `belief`. Detecting these is close to
    definitional, so they mainly test belief-extraction fidelity.
  - **P_res** — resource defects. Detecting these is empirical.
- **Reclassification rule.** Suppose an A on N_h is confirmed by hand as a genuine violation, for example
  a verifier that exposes material from outside the signed payload. It is then **not** silently removed
  from the FP count. It is reported twice: once as an FP under the pre-registered labels, and once as a
  finding. The finding is never added to P after the fact.

## 3. Metrics

The unit is the observation `(i, t)`. A token-level aggregate ("any verifier flags `t`") is secondary,
because it is the only level at which the differential baselines are defined.

- **FPR** = #{A on N_h} / |N_h|
- **TPR** = #{A on P, reproduced} / |P, reproduced|, reported per stratum
- **FNR** = 1 − TPR
- Every proportion is reported with a Wilson 95% CI. Pair-level CIs also get a **token-clustered bootstrap**
  CI (10,000 resamples), because observations sharing a token are not independent.
- Baselines use the same data: B0 (any disagreement), B1 (accept-minority), B2 (capability profile), all as
  defined in `PREREG.md` §5. They are compared at token level.

## 4. Hypotheses (confirmatory)

- **H-P1 (detection).** PROV labels A on every reproduced entry of P. One reproduced miss falsifies H-P1.
  TPR and its Wilson lower bound are reported per stratum. No "high recall" claim is made beyond the panel.
- **H-P2 (combined FP on fresh data).** The pair-level FPR of combined PROV (claim + resource v2) on N_h is
  ≤ `[DECIDE, suggested 0.5%]`, and the upper Wilson bound is ≤ `[DECIDE, suggested 1%]`. If either
  threshold is exceeded, H-P2 is falsified.
- **H-P3 (comparison, expected direction stated in advance).** On honest tokens, PROV's token-level FP is
  lower than B0, B1 and B2. Tested with a paired exact McNemar test per baseline, Holm-corrected across the
  three tests, α = 0.05. Earlier results make this the expected outcome, so it is reported as a replication,
  not as a discovery.
- **H-P4 (integrity check, not a finding).** Claim-path FPR on N_h = 0. Any non-zero count triggers a
  root-cause analysis, which is reported. The harness is **not** fixed and re-run under this pre-registration.
- **Descriptive only:** outcomes on U; alerts per 1,000 tokens; error-class clusters; timeout and keyload rates.

## 5. Exclusions and missing data

- Adapter gate G1–G4 and the keyload > 5% rule apply exactly as in `PREREG.md` §3.
- `stage = keyload` observations are removed from both numerator and denominator, and their count is reported.
- A timeout (per-case wall clock > `[DECIDE, suggested 10 s]`) is recorded as a rejection with
  `stage = timeout`. Timeouts are reported separately, and a timeout is **not** automatically an A.
- A crash of the adapter process is re-run once. If it crashes again, the observation is recorded as
  `stage = crash` and excluded, and the count is reported.

## 6. Analysis procedure

1. Regression check first: the old pipeline configuration must reproduce the 9/24 B0 result (`PREREG.md` §7).
   If it does not, nothing is reported.
2. Positive/negative controls from `DESIGN_generator.md` §6 must pass for every included verifier.
3. Run the analysis script at the commit hash in §8. Report every metric in §3, including the ones that go
   against the hypotheses.
4. Holm correction applies only to H-P3. H-P1 and H-P2 are single pre-specified decisions.

## 7. Threats to validity (acknowledged in advance)

**Construct validity**
- `belief` is what the library exposes, not what an application does with it. Violations that only appear
  when an application re-parses the raw token are out of scope unless the application layer is modelled
  as a separate target.
- `Signed(t)` depends on a reference parse. Where parsers legitimately disagree (duplicate member names,
  number precision, Unicode normalization), the reference choice can create FPs or FNs. These cases are
  tagged in the corpus and reported separately.
- If the oracle version under test is v3, it projects `Signed` onto one authority claim. Escalation through
  any other claim is invisible to it (see `ORACLE_FORMAL_v2.md` §6).
- A "capability difference" (C) can also be an interoperability bug. C only means "not a security violation".

**Internal validity**
- Adapter configuration choices are researcher degrees of freedom. Adapters are frozen by commit hash after
  the gate and before the main run, and config follows each library's documented safe usage.
- Timing noise affects the resource path. The v2 parameters (alg-matched baseline, repeated confirmation,
  absolute floor) are fixed from `PREREG_resource.md` and are not tuned on this corpus.
- Bugs in the generator itself are guarded against by the label controls in `DESIGN_generator.md` §6.

**External validity**
- The verifier sample follows the selection rule, not a random draw from all deployments.
- Only safe-usage configurations are tested, so misuse-prone configurations are under-represented.
- The positive panel is small and partly synthetic, so TPR generalizes weakly beyond defect classes like
  those in the panel.

**Statistical conclusion validity**
- Observations are clustered by token and by verifier. Clustered bootstrap CIs are reported next to the naive ones.
- With a small P, a TPR of 1 is still compatible with substantially lower true recall. The Wilson lower
  bound is always stated alongside it.

## 8. Frozen artefacts (filled at registration)

| artefact | value |
|---|---|
| generator commit | `[hash]` |
| corpus seed(s) | `[DECIDE]` |
| analysis script commit | `[hash]` |
| adapter commits | `[per ecosystem]` |
| toolchain / lockfile hashes | `[sha256 of each lockfile]` |
| panel list hash | `[sha256]` |

## Deviations
(none yet)
