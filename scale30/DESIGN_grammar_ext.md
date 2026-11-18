# Grammar extension for deeper fuzzing — design (worked)

> Extends `DESIGN_generator.md` with new families along four axes. It does **not** touch the frozen
> scale30 corpus (`corpus/`). New tokens go in `corpus_g/`, judged with `judge.py --corpus corpus_g`.
> Every family states its ground truth (honest vs crafted) and what the oracle should say, so a flag is
> never circular.

## Why these four axes

The scale30 corpus varied (alg × key) for honest tokens (V1) and a small forged set (F1/F2). It barely
touched *how a token is serialized*, *how a claim is typed*, and *header-directed key selection*. Those are
exactly where implementations diverge without being wrong, so they are the honest test of the oracle's FP
claim; and header key-selection is where real forgeries live, so it is the honest test of detection.

## Truth model reminder

`truth.json` carries `(honestly_issued, legit_role="user", attack_role)`. Oracle v3 reads only `role`.

- **honest family** → `honestly_issued=True`. A rejection is **C** (never an alarm). An acceptance is OK.
  These families measure FP: any detector that flags them on honest tokens is a false positive.
- **crafted family** → `honestly_issued=False, attack_role="admin"`. Acceptance with `role="admin"` is a
  true **A**. Acceptance where the verifier still believes `role="user"` (ignored the unsigned part) is OK.

## Axis 1 — Structural / serialization (honest, family `S`)

Same issuer-signed `role=user` payload, re-expressed in RFC 7515-valid forms. The signature still covers the
real payload, so `honestly_issued=True`. A library that rejects a form it does not support → C.

| variant | construction | note |
|---|---|---|
| `compact` | three-part compact (control) | every lib should accept |
| `json_flat` | flattened JSON serialization | single-signature JSON form |
| `json_general` | general JSON, one signature entry | array-of-signatures form |
| `ws_json` | flat JSON with insignificant whitespace | JSON parsers must tolerate |
| `b64pad` | payload segment carries `=` padding | many libs reject; strict-b64url difference = C |
| `dup_member` **[ambiguous]** | payload JSON has a duplicated member name | tagged `parse_ambiguous`; reported separately, **excluded from the primary FP denominator** |
| `trailing_ws` | signing input has a trailing newline before signature | encoding strictness |

`dup_member` is the honest analogue of a real class of confusion, but its *meaning* is undefined, so it is
never counted as an FP or a TP — only described.

## Axis 2 — Claim-type coercion (honest, family `T`)

Issuer signs a well-formed token; the claim's *type* is the variable. These directly exercise the
`ν` normalization and Assumption N. The pilot already found four coercions in the wild, so these are named
as their own strata up front.

| variant | claim | coercion a lib may apply | oracle stance |
|---|---|---|---|
| `aud_string` | `aud:"api"` | some expose `["api"]` | belief differs by *type*, not authority → **not A**; tag `type_coerced` |
| `aud_array` | `aud:["api","web"]` | some reorder | order-insensitive ν → OK |
| `bigint` | `n: 2^60` | IEEE-754 rounding | **breaks Assumption N**; tag `precision`, exclude from claim-path FP denominator |
| `num_zeropad` | `ver: "01"` (string) vs `1` | — | control |
| `null_vs_absent` | `mid: null` | some drop null members | ν keeps null ≠ absent; report as C-like difference |
| `unicode_nfc` | `name` in NFC | — | control |
| `unicode_nfkc` | same grapheme in NFKC | libs must not normalize | if belief changes code points → tag `unicode`, not A |

Rule fixed in advance: a type/precision/encoding coercion of an issuer-signed value, with the **authority
claim (`role`) unchanged**, is **never** labelled A. It is reported in its tagged stratum. This is the
honest handling of the pilot finding.

## Axis 3 — Mutation-chain depth (crafted, family `M`)

Port of `random_fuzz.py` with larger `d_max`. A seeded RNG samples a typed operator chain under the DY
knowledge rule (attacker never holds `sk_I`). Every token records its `op_chain`. Target claim is
`role=admin`, so `honestly_issued=False, attack_role="admin"`.

- operators: `set_alg`, `set_role`, `swap_key(attacker|public-as-hmac|random)`, `reserialize(compact|flat|general)`,
  `inject_header(kid|cty|crit)`, `strip_sig`, `empty_sig`, `bitflip_sig`.
- depth 1..`d_max` (default 6); `n` chains per depth; seeds `1..S`.
- **Purpose:** show the oracle's FP rate stays flat and its A-detection stays correct as search deepens —
  i.e. more fuzzing does not manufacture false alarms. Any modern lib accepting `role=admin` = real A.

## Axis 4 — Header-injection forgeries (crafted, family `H`)

RFC 7515-valid header parameters that direct key selection. Attacker builds its own keypair and asks the
verifier to trust header-supplied key material. `honestly_issued=False, attack_role="admin"`.

| variant | header | true A iff |
|---|---|---|
| `embedded_jwk` | attacker `jwk` in header, self-signed | verifier trusts header key → accepts `role=admin` |
| `jku_url` | `jku` → attacker URL (kept unreachable) | verifier fetches/trusts it |
| `x5u_url` | `x5u` → attacker URL | same |
| `kid_confuse` | `kid` selecting an unintended key | key-directory confusion |
| `cty_nested` | `cty:JWT` wrapping a second forged token | double-decode confusion |
| `crit_unknown` | `crit:["exp"]`-style unknown must-understand | strictness probe (accept-with-belief still user → OK) |

Safe-usage configuration means a correct verifier ignores header-supplied keys and rejects, so the expected
outcome on hardened libs is 0 A. A single acceptance with `role=admin` is a genuine finding, handled under
the project's disclosure rules — the generator only produces the input.

## Reproducibility

- master seed fixed; family seed = `HMAC(master, family)`.
- keys generated once, stored in the corpus, hashed in the manifest.
- `iat` fixed, `exp` far future, `TZ=UTC`, `LC_ALL=C`.
- ambiguity/coercion tags live in `meta.tags`; the judge excludes tagged strata from the primary FP
  denominator and reports them on their own.
