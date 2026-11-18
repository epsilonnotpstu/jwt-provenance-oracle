# PREREG-G3 — Extended grammar, compact-only honest corpus, number-policy v4 oracle (confirmatory follow-up to EXP_g2)

> Study-specific instance of `PREREG_METHODOLOGY.md`. It is registered when this file,
> `corpus_g3/gen_corpus_g3.py` and `analyze_g3.py` are committed **before** the G3 corpus is generated with the
> master seed and before any verifier runs on it. Deviations are appended at the end and never edited.

## 0. What EXP_g2 taught us, and what this study changes

| EXP_g2 observation | G3 design response |
|---|---|
| Distinct acceptance patterns saturate on g2's compact tokens: 57 observed, Chao1 57.2, Good–Turing P(new) = 0.2% | More tokens under the same grammar add nothing, so **new grammar dimensions** are added (§2) |
| No primary implementation accepts JSON serialization (RFC 7519 §7.2), so these tokens diluted the denominator and drove a Simpson effect | **Compact only** |
| `precision` stratum FPR_v4 = 16.7%, because exact comparison is unusable for binary64 runtimes | A **pre-declared number policy** (I-JSON, RFC 7493 §2.2) becomes the primary v4 |
| Two of the four v4 false-positive clusters were PHP adapter artefacts | Adapter fixed and re-gated before this registration (commit `2e8eb2f`, `LOG.md`) |
| Within compact tokens, B0 false positives rose with mutation depth (exploratory, post hoc) | Tested here **confirmatorily** on fresh data (H3-4) |

The number policy and the depth hypothesis were chosen **after** seeing g2. That is why they are tested only on
this fresh corpus, and g2 numbers are never pooled with G3.

## 1. Subjects

- **Primary set.** The same 32 primary implementations as scale30 and g2. The PHP adapter is at commit `2e8eb2f`;
  every other adapter is unchanged.
- **New-ecosystem set.** `c/libjwt`, `erlang/erlang-jose` and `dart/dart_jsonwebtoken`, reported descriptively.
- **Keyload.** Keyload observations are excluded and counted.
- **B2 profile.** As in g2: learned on scale30 V1 seed 1.

## 2. Corpus

The base grammar and mutation operators are those of `PREREG_g2.md` §2, with two changes: **serialization is
compact only** and `m_ser` is removed. The generator also adds the following dimensions, all issuer-signed and
all `honestly_issued=True`:

| dimension | content | tag |
|---|---|---|
| NumericDate forms | `iat`/`exp`/`nbf` written with a fractional part (for example `.5`) | `numdate_frac` |
| member names | non-ASCII key, empty key `""`, 256-character key, key with a space, key with U+2028 | `keyname` |
| number edges | `-0`, `0e0`, `1E+2`, `-0.0`, `1e308`, `5e-324`, `2.2250738585072014e-308`, a 30-digit integer, `1e400` | `numedge`; `1e400` also `non_ijson` |
| string edges | U+2028, U+FEFF inside a string, the escaped lone surrogate `\ud800` | `stredge`; the lone surrogate also `parse_ambiguous` |
| size / nesting | 20- or 64-level nesting, a 1,000-element array, a 16 KiB string | `limits` |
| typ values | adds `JOSE` and `application/jwt` | `typ` |
| registered-claim type violations (RFC 7519 types broken by the issuer) | `iss`/`sub`/`jti`/`aud` as a number; `exp`/`iat`/`nbf` as a string | `nonconformant` |
| unknown critical header | `crit: ["x_must"]` (RFC 7515 §4.1.11 requires rejection) | `must_reject` |

**New issuer-side mutation operators:** `m_numdate`, `m_keyname`, `m_numedge` and `m_stredge`. Each adds or
rewrites one element of the corresponding dimension.

**Size: 6,000 tokens, 1,200 per depth d = 0..4.** The size is set by a per-implementation bound. If an
implementation shows zero A, the rule-of-three 95% upper bound is 3/n_accepted. Reaching ≤ 0.1% needs about
3,000 accepted observations per implementation, and at g2's compact acceptance rate (~80%) that is ≈ 4,000–6,000
tokens. The size is **not** chosen to improve pattern discovery, which saturated in g2.

**Seeds.** Master seed 20261001; per-depth RNG `HMAC(master, "d"+d)`. The generator self-check (§2 of
PREREG_g2) applies unchanged.

**Strata.** The following are excluded from the primary stratum and reported on their own:

| stratum | why excluded |
|---|---|
| `nonconformant`, `must_reject` | conformance probes; rejection is the specified behaviour |
| `parse_ambiguous` | Signed(t) is not a Unicode string |
| `non_ijson` | outside binary64 range |

Unlike g2, `precision` and `decimal_inexact` are **in** the primary stratum, because the number policy covers them.

## 3. Oracle

- **Primary: v4-IJ.** This is v4 exactly as in `PREREG_g2.md` §3 (ν, E1, E2, A_v4, kinds, drops), with one
  change: numbers compare at binary64 precision. A belief number equals a Signed number iff both round (IEEE-754
  round-half-even) to the same finite double. Rationale: RFC 7493 §2.2 sets binary64 as the interoperable number
  model for JSON protocols. A verifier that exposes a number at binary64 precision has not changed what the
  issuer signed in any sense an I-JSON consumer can observe.
- **Secondary: v4-exact** (the g2 rule). Reported for every stratum. It is not tested.
- **v3** is reported as the integrity check.

## 4. Hypotheses (confirmatory unless marked)

- **H3-0 (integrity).** v3 claim-path A on honest tokens = 0.
- **H3-1 (FP bound, replication of H-G1).** Primary stratum, 32 primary implementations, observation level:
  FPR_v4-IJ ≤ 1.0%, and the token-clustered bootstrap upper bound ≤ 2.0%. The rate per *accepted* observation
  is also reported and must also be ≤ 1.0%. This closes the g2 denominator caveat.
- **H3-2 (comparison).** Token level, primary stratum, paired exact McNemar per baseline, Holm-corrected,
  α = 0.05. Expected: v4-IJ < B0 and v4-IJ < B2. Also expected, stated in advance: **v4-IJ is not below B1**,
  as in g2. This is reported as a replication of B1's quietness on honest tokens, not as a defeat or a win.
- **H3-3 (per implementation, descriptive with target).** For each primary implementation, report A,
  n_accepted and the Wilson upper bound. Target, fixed now: at least 24 of 32 implementations have 0 A with a
  rule-of-three upper bound ≤ 0.1%. The number achieved is reported whether or not it meets the target.
- **H3-4 (depth, confirmatory test of the g2 exploratory finding).** Token-level B0 honest-FP rate increases with
  mutation depth. Test: one-sided Cochran–Armitage test over d = 0..4, z > 0, α = 0.05.
- **H3-5 (new dimensions add behaviour).** At the same size as g2's compact set (n = 978, 1,000 subsamples), G3
  shows more distinct acceptance vectors than g2's 57 in ≥ 95% of draws. Saturation at full N is also reported
  (Chao1, Good–Turing P(new)).

**Descriptive only**
- **Conformance strata.** Per-implementation acceptance of `nonconformant` (by claim) and `must_reject`. An
  acceptance there is a conformance observation. If it could have security impact, it goes through the project's
  disclosure rules before any public mention.
- the `limits` stratum (rejections and timeouts);
- v4-exact against v4-IJ;
- the coercion catalogue;
- the new-ecosystem set;
- the v1 resource `PROV` column.

## 5. Interpretation rules

These are as in `PREREG_g2.md` §5 (source inspection, reclassification, no detection claim). One addition: an
A_v4-IJ cluster whose source is an adapter is counted in the pre-registered rate and then reported with the
adapter excluded as a sensitivity analysis, exactly as in EXP_g2.

## 6. Threats to validity

- **Construct.** The binary64 policy is a choice. Under it, a verifier that silently rounds a 64-bit integer is
  *not* flagged. v4-exact is reported so readers can apply the stricter rule.
- **Internal.** The policy, the compact-only design and H3-4 were all motivated by g2. They are tested only on
  fresh G3 data. The PHP adapter changed between g2 and G3, so g2 and G3 PHP numbers are not comparable.
- **External.** Only safe-usage configurations are tested. The algorithm mix is uniform.
- **Statistical.** Clustering is handled as in g2. The per-implementation bounds are 32 separate intervals and are
  not corrected for multiplicity. They are descriptive.

## 7. Frozen artefacts

| artefact | value |
|---|---|
| master seed | 20261001 |
| dev seed (generator and analysis testing only; its corpus never touches a verifier) | 0 |
| adapters | PHP at `2e8eb2f`; all others as in scale30 |
| generator / analysis commit | the commit that adds this file |
| pre-freeze testing | dev seed 0 only: 6,000/6,000 self-check passed and payload bytes are deterministic. `analyze_g3.py` was smoke-tested on synthetic stub results (a binary64 echo stub with an injected type coercion). The injected coercion was caught at exactly 1/32. No real verifier output on G3 existed before the freeze. |

## Deviations

- **D1 (2026-09-25, after freeze, before any G3 result was analysed).** The Python adapter crashed on case
  `G3/d0/0131` (tag `parse_ambiguous`). Cause: an accepted claim containing the lone surrogate U+D800 cannot be
  written as UTF-8 with `ensure_ascii=False`. The fix writes adapter output with `ensure_ascii=True`, which
  produces the same JSON values, with non-ASCII escaped. The Python gate was re-run: 7/7 impls pass, with zero
  verdict or claim differences. The run was restarted from scratch. The partial output (131 lines of one impl)
  was never analysed.
- **D2 (2026-09-25, after freeze, before any G3 result was analysed).** On the restarted run, two more adapters
  crashed while *writing* their output:
  - The Java adapter (at nimbus-jose-jwt, line 66) hit a UTF-8 write of a lone-surrogate claim.
  - The Ruby adapter (at ruby-jwt, line 76) got a claim that the library had parsed from `1e400` to Infinity.
  - **Fixes.** Java output is now ASCII-escaped with Jackson `ESCAPE_NON_ASCII`. Ruby output uses
    `allow_nan: true` and scrubs invalid UTF-8 to U+FFFD. Scrubbing can only change claims in the excluded
    `parse_ambiguous` stratum.
  - **Re-gate.** Java 4/4 and Ruby 2/2 pass, each with zero verdict or claim differences from the frozen gate.
  - **Re-run.** Only the Java, Ruby and .NET adapters were re-run on G3. .NET had not run yet, because `run_all.sh`
    stops at the first failure. The other languages' G3 output was complete: 6,000 lines each, produced by
    unchanged adapters.
  - **Partial files.** They are kept, not deleted, in `corpus_g3/partial_crashed/`.
  - **Adapter-side artefacts to expect in excluded strata.** Node `JSON.stringify` writes Infinity as `null`, and
    PHP `json_encode` with partial output writes INF as `0`. Both affect only `non_ijson` tokens.
