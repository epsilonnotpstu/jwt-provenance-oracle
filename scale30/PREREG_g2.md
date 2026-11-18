# PREREG-G2 — Grammar-generated, issuer-mutated honest corpus: false positives of a full-claim provenance oracle

> Study-specific instance of the generic preregistration (`PREREG_METHODOLOGY.md`). It is registered when this
> file, `corpus_g2/gen_corpus_g2.py` and `analyze_g2.py` are committed **before** the main corpus is generated
> with the master seed and before any verifier runs on it. Later changes go in *Deviations* (append-only).
>
> **Pilot disclosure.** `corpus_g/` (68 honest cases) was generated and run on 34 implementations before any
> preregistration. It is a pilot. It was **not judged or analysed before this file was written**. After the
> freeze it is used only to debug `analyze_g2.py`, and its numbers are reported as exploratory.

## 0. Why this study, and why the oracle under test is v4

The current claim oracle (v3, `oracle.py`) returns OK for every *accepted honest* token by construction. On an
honest-only corpus its false-positive rate is therefore 0 by definition, so measuring it would tell us nothing.
That is H-G0 below, an integrity check only.

The informative question is the one that v3 skips. It checks only the authority claim. **v4** checks the full
claim set: it compares everything the verifier exposes against everything the issuer signed. v4 can produce
false positives on honest tokens whenever a verifier coerces a claim, for example through number precision,
type changes or string handling. Those false positives are empirical, not definitional. This study measures
them on a corpus built to stress exactly those dimensions.

## 1. Subjects

- **Primary set.** The 32 primary implementations of `results/analysis.json` (`primary_impls`), with the adapters
  at their committed versions. The candidate list is unchanged; no gate re-selection happens here.
- **New-ecosystem set.** The 3 gate-passing implementations of `PREREG_newlangs.md` (`c/libjwt`,
  `erlang/erlang-jose`, `dart/dart_jsonwebtoken`). They are reported **descriptively only** and are not part of
  any confirmatory test.
- `stage = keyload` observations are removed from numerator and denominator, and their count is reported.
  An implementation above 5% keyload on this corpus is reported but not excluded, because the exclusion rule
  belongs to the gate.

## 2. Corpus (generation + issuer-side mutation; all tokens honest)

Every token is signed by the issuer with the issuer's key, **after** the mutation step. There are no forged or
attacker-constructed tokens in this corpus. `truth = (honestly_issued=True, legit_role="user")` for all.

**Generation grammar** (seeded; `gen_corpus_g2.py` is the normative version)

```
Token    := Ser(Header, Payload, alg)
alg      := HS256|HS384|HS512|RS256|RS384|RS512|PS256|PS384|PS512|ES256|ES384|ES512|EdDSA   (uniform)
key      := HS: hash-size secret ("min");  RS/PS: 2048-bit;  ES: matching curve;  EdDSA: Ed25519
Header   := {alg} + opt(typ ∈ {JWT, jwt, at+jwt}) + opt(kid = issuer kid) + opt(private member x_*)
Payload  := Base + Opt* + Extra*
Base     := sub, role="user", iss, iat, exp          (iat past, exp far future)
Opt      := nbf = iat | jti : Str | aud : Str | aud : [Str, Str]
Extra    := x_<name> : Value, 0..4 members
Value    := Int | Float | Str | Bool | null | [Value*] | {x_<name>: Value*}      (depth ≤ 3)
Ser      := compact | JSON flattened | JSON general (one signature)
```

The generator is the issuer. It emits the payload **bytes** itself, so byte-level choices are signed exactly
as emitted: member order, whitespace, `\uXXXX` escaping and number spelling.

**Issuer-side mutation operators** (applied to the derivation *before* signing; each preserves `role="user"`):

| op | effect |
|---|---|
| `m_order` | shuffle members of one object (header, payload or nested) |
| `m_ws` | whitespace style ∈ {none, spaced, pretty} |
| `m_uesc` | write the characters of one string as `\uXXXX` (includes the `role` value) |
| `m_solidus` | write `/` as `\/` in strings |
| `m_numspell` | respell one integral number as `N.0` or `Ne0` |
| `m_addclaim` | add one private claim (Value grammar) |
| `m_addhdr` | add one private, non-critical header member |
| `m_deepen` | wrap one private claim value in an array or object |
| `m_aud` | add `aud` or switch it between string and one-element array |
| `m_typ` / `m_kid` | set or clear `typ` / `kid` |
| `m_ser` | change the serialization |
| `m_alg` | change `alg` (issuer re-signs with its key for that alg) |

**Design.** Mutation depth d ∈ {0,1,2,3,4}, with d=0 meaning pure generation. There are 320 tokens per depth,
1,600 in total. One master seed is used; the per-depth RNG is derived as `HMAC(master, "d"+d)`.

**Strata (tags fixed at generation).**
- `precision`: an integer with |n| > 2^53−1.
- `decimal_inexact`: a non-integral number not exactly representable in binary64.
- `nul`: a string that contains U+0000.
- `unicode`: an astral-plane or combining character.
- `num_respelled`: an integral value written with a fraction or exponent, whether it came from the pool or
  from `m_numspell`.
- `uesc`, `solidus`, `json_ser`, `aud`, `typ`, `kid`, `xhdr`: descriptive tags.
- All tags are computed from the final signed bytes, not from the operator trace.

**Primary stratum** = tokens with neither `precision` nor `decimal_inexact`. Those two strata break the
exact-number assumption and are reported on their own.

**Label self-check.** For every token the generator re-derives the signed bytes independently: it parses the
serialization, base64url-decodes the payload, verifies the signature with the issuer's public key, and parses
the JSON with duplicate-member rejection. Any mismatch aborts generation.

## 3. Oracle v4 and normalization ν (fixed now)

- **Signed(t)** = the reference parse of the signed payload bytes. Numbers are parsed as exact decimals.
- **belief(i, t)** = the claims the adapter exposes for an accepted t. Numbers are parsed as exact decimals from
  the adapter's JSON output.
- **ν.**
  - Numbers compare as exact rationals, so `1` = `1.0` = `1e0`.
  - Strings compare code point by code point, with no normalization.
  - Object member order is ignored.
  - Arrays are ordered.
  - `true`, `false` and `null` are distinct values, and `null` ≠ absent.
- **Declared equivalences.**
  - **E1.** `aud: "x"` ≡ `aud: ["x"]`, because RFC 7519 §4.1.3 allows either form.
  - **E2.** The order of `aud` array elements is ignored, because the claim is a set of recipients.
- **Label.** For an accepted honest token, **A_v4** holds iff some member (k, v) of belief(i, t) has no
  ν-equal counterpart in Signed(t). A coerced value and an added member both count. A *dropped* member does
  not make A: it is counted separately as `drop`. A rejection is C.
- Each A_v4 records its kind: `num` (numeric value changed), `type` (JSON type changed), `str` (string changed),
  `extra` (member not signed), or `other`. For nested values the kind is that of the first differing leaf.

## 4. Hypotheses

- **H-G0 (integrity, not a finding).** v3 claim-path A on honest tokens = 0, for all 32 primary implementations.
  A non-zero count means a harness defect.
- **H-G1 (v4 FP bound, confirmatory).** Primary stratum, 32 primary implementations, observation level:
  FPR_v4 ≤ 1.0%, and the upper bound of the token-clustered bootstrap 95% CI ≤ 2.0%. Either threshold exceeded
  → H-G1 falsified. Falsification is reported as the main result, not moved to a footnote.
- **H-G2 (comparison).** At token level, on the primary stratum, the flag "any primary implementation labels A_v4" fires on fewer honest
  tokens than B0, B1 and B2. The baselines are defined exactly as in `judge.py`, with the B2 profile learned on
  the scale30 V1 seed-1 data. The test is a paired exact McNemar test per baseline, Holm-corrected, α = 0.05.
- **H-G3 (test dimension; generic H5).** Acceptance vector = the set of primary implementations that accept a
  token. Both honest corpora are subsampled to n = 159 (the size of the scale30 honest set V1–V3), 1,000 times.
  H-G3 holds if the distinct-vector count of g2 exceeds that of scale30 in at least 95% of paired draws.
  This measures corpus diversity, not detector quality.
- **H-G4 (depth; exploratory, direction stated).** The token-level B0 honest-FP rate does not decrease with
  mutation depth. It is tested with a two-sided Cochran–Armitage trend test over d = 0..4 at α = 0.05.
  FPR_v4 is reported per depth.

**Descriptive only**
- the coercion catalogue: (implementation × kind × tag) counts for A_v4 and `drop`;
- the `precision` and `decimal_inexact` strata;
- the new-ecosystem set;
- the pilot `corpus_g`;
- the judge's `PROV` column, which uses the v1 resource path. Its instability is known (`EXP_scale30.md` §9),
  so it is excluded from all tests.

## 5. Interpretation rules (fixed now)

- **Where coercions come from.** An A_v4 caused by the adapter's own JSON encoding (for example a language
  runtime printing a double) cannot be told apart from the library's behaviour without inspecting the adapter.
  Each A_v4 cluster (implementation × kind) is inspected once. If the source is the adapter, it is reported as
  an adapter artefact, **still counted** in the pre-registered FPR, and listed separately.
- **Reclassification.** A coercion that manual review judges a genuine correctness defect is reported twice: as
  a false positive under these labels, and as a finding. Anything with possible security impact is handled under
  the project's disclosure rules before any public mention.
- **No detection claim.** This corpus has no positives, so TPR and FNR are **not** estimated here. Detection
  evidence remains that of the earlier studies. This study cannot add to it.

## 6. Threats to validity

- **Construct.** v4 treats every coercion as a violation. Some are harmless (see §5), so FPR_v4 is an upper
  bound on *harmful* false alarms. v3's zero is definitional.
- **Internal.** The same team built the grammar and the oracle. ν and E1–E2 are fixed here, before any g2
  outcome is seen. Adapter output encoding is a confound (see §5).
- **External.** Only safe-usage configurations are tested. The alg mix is uniform, so baseline FP is driven by
  alg support as well as by structure. A secondary breakdown restricted to HS256/RS256 is reported.
- **Statistical.** Observations cluster by token and by implementation. A token-clustered bootstrap is used
  (10,000 resamples, seed 1). The 1,000 subsamples of H-G3 are not independent tests.

## 7. Frozen artefacts

| artefact | value |
|---|---|
| master seed | 20260925 |
| dev seed (generator testing only; its corpus is never run on verifiers) | 0 |
| generator / analysis commit | the commit that adds this file |
| corpus sha256 | written to `corpus_g2/corpus_manifest.json` at generation, then logged in `LOG.md` |
| pre-freeze testing | generator run with the dev seed only (self-check passed, 1,600/1,600, deterministic payload bytes); `analyze_g2.py` smoke-tested on **synthetic stub results** for the dev corpus (a stub that echoes the signed claims, plus injected coercions). No real verifier output from g2 or the pilot was read before the freeze. |

## Deviations

- **D1 (2026-09-25, after freeze, before any g2 output was read).** `analyze_g2.py`: when a case's signed bytes
  are not valid JSON, it is now skipped for v4 and listed under `signed_unparseable`, where before the script
  crashed. The trigger was the pilot `corpus_g`, which has an RFC-forbidden BOM payload. This cannot affect g2,
  because every g2 payload passed the generator's JSON self-check.
