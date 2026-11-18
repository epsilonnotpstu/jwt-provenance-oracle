# Design — provenance-labelled test-corpus generator

> This is a methodology document, and it is library-agnostic. The current implementation is
> `corpus/gen_corpus.py` (plus `operators.py` and `random_fuzz.py`). This document states the design those
> should satisfy, and the "gap" notes mark where they do not yet.

## 1. Goals and non-goals

**Goals**
- Produce tokens whose ground truth is known by construction, so no verifier is needed to label them.
  This avoids a circular oracle.
- Compose tokens from small typed operators, both in curated families and in seeded random chains.
- Emit a corpus that any language's adapter can consume, with the truth kept physically separate.
- Be fully reproducible from a manifest.

**Non-goals**
- Finding bugs by itself. The generator only produces inputs and labels. Classification is the oracle's job.
- Modelling application logic beyond the claims a verifier exposes.

## 2. Data model

```
Case  = { id, token, allowed_algs, key, meta }        → cases.json   (visible to adapters)
Truth = { honestly_issued, signed_claims, ... }       → truth.json   (visible only to the judge)
meta  = { family, alg, variant, seed, op_chain }      -- op_chain is the operator trace that built the token
key   = { kind, secret_hex | pem, jwk }               -- the verifier key, in several encodings
```

- `id` is hierarchical (`family/…/seed`) and stable across regenerations with the same seed.
- **Gap:** `truth.json` currently carries `legit_role` / `attack_role` instead of the full `signed_claims`
  (see `ORACLE_FORMAL_v2.md` §6).

## 3. Operator abstraction

Tokens are **terms** built from typed operators. Every operator is pure. Randomness comes only from an
explicit RNG argument.

| class | operator (signature) | notes |
|---|---|---|
| Constructors | `header(fields) → H` | arbitrary members, including unregistered ones |
| | `payload(claims) → P` | claim map → canonical or deliberately non-canonical JSON bytes |
| | `signing_input(H, P) → M` | `b64url(H) ‖ "." ‖ b64url(P)`; a variant form allows unencoded payloads |
| | `ser_compact(M, S) → t` | three-part compact form |
| | `ser_json_general(P, [(H_prot, H_unprot, S)…]) → t` | multi-signature JSON form |
| | `ser_json_flat(P, H_prot, H_unprot, S) → t` | single-signature JSON form |
| Cryptographic | `sign(k, alg, M) → S` | `k` must be in the caller's knowledge (§4) |
| | `pub(k) → k_pub` | derive public material |
| | `encode_key(k, fmt) → bytes` | e.g. PEM, DER or JWK encodings of the same key |
| | `keygen(alg, params, rng) → k` | attacker-side keys only |
| Mutators | `set/del_member(x, path, v)`, `re_encode(x, codec)`, `splice(t₁, t₂, part)`, `bitflip(S, i)` | structural edits |

**Typing.** Operators are typed over `{H, P, M, S, t, key}`. The composer rejects ill-typed chains before
anything is serialized, so random search never wastes effort on strings that fail to parse unless a
family targets malformed input on purpose.

**Composition.**
- *Curated families* are fixed operator chains that each express one attack or variant class.
- *Random chains* sample an operator sequence of length ≤ `d_max` from a seeded RNG, under the knowledge
  restrictions of §4.
- Every emitted token records its `op_chain`, so a flagged case can always be explained by replaying its construction.

## 4. Knowledge discipline (Dolev–Yao)

Two roles are modelled.

- **The issuer** may call `sign(sk_I, …)`. Only issuer-role chains produce honest tokens.
- **The attacker** holds `K`: public keys, previously issued tokens, and its own keys. Attacker chains may use
  `sign` only with keys in `K`. They may re-use any byte string from `K`, including issuer signatures and
  their signed inputs, but `sk_I` never appears.

The composer enforces this with a **capability check**: `sign`'s key argument must be derivable from the
current role's knowledge set. A chain that violates the check is rejected at construction time.

## 5. Provenance labels

Every intermediate value carries a label set `L ⊆ {issuer-signed(claims) | attacker}`. The rules:

- `sign(sk_I, M)` gives `M`'s parsed claims the label `issuer-signed`.
- Any value the attacker constructs is labelled `attacker`, **except** that embedding a byte-identical
  issuer-signed `(M, S)` pair keeps that pair's label.
- `Signed(t)` = the union of `issuer-signed` claim sets whose signature entry is present in `t` unchanged.
- `honestly_issued(t)` = the chain is issuer-role end-to-end.

**Two-source cross-check (a label control).** For every token, recompute `Signed(t)` from the definition in
`ORACLE_FORMAL_v2.md` §2 using a reference verifier that is independent of every verifier under test, with
`parse_ref`. If the propagated label and the recomputed value disagree, the generator aborts. Tokens where
`parse_ref` is ambiguous are tagged `meta.parse_ambiguous = true` and reported separately. Ambiguous means
duplicate members, precision-sensitive numbers, or payloads that are not objects.

## 6. Validation controls

Controls run before any analysis. If a control fails, that verifier or that corpus is excluded.

| control | construction | required outcome |
|---|---|---|
| **Positive (per verifier × supported alg)** | honest token, documented key, alg in the allow-list | accepted, and `belief` equals issuer claims after ν |
| **Negative: corrupted signature** | honest token with one signature bit flipped | rejected |
| **Negative: algorithm outside allow-list** | unsigned-algorithm token | rejected |
| **Belief fidelity** | honest token with Unicode, a 2^60 integer, and array/string audience claims | `belief` matches issuer claims; any difference is documented as the verifier's behaviour, never "fixed" in the adapter |
| **Label control** | whole corpus | propagated labels = reference recomputation (§5) |
| **End-to-end detection** | synthetic verifier with a documented injected defect (claim path + resource path) | oracle labels A |
| **Regression** | previous pipeline configuration | reproduces the previously reported baseline count |

The first three controls are gate G1–G4 in `PREREG.md` §3.

## 7. Reproducibility

- **Seeds.** One master seed per corpus. Each family's seed is `HMAC(master, family_name)`, so adding or
  removing a family never shifts another family's randomness. Every token stores its seed.
- **Keys.** Key generation is not reproducibly seedable across crypto backends (deviation D2 in `PREREG.md`).
  Generate keys once, store them in the corpus, and record their SHA-256 in `corpus_manifest.json`.
  Regenerating the corpus re-uses stored keys unless new keys are explicitly requested.
- **Time.** Fix `iat`, set `exp` far in the future and omit `nbf`, so results do not depend on the wall clock.
  Run with `TZ=UTC` and `LC_ALL=C`.
- **Pinned versions.** Commit each ecosystem's lockfile. Record the library version, crypto backend and
  toolchain version in every output line and in the adapter card.
- **Deterministic runner.** Cases run in file order, one verifier at a time, single-threaded, with a fixed
  warm-up policy. Output is one line per case, flushed after each case, so a killed run resumes from the last line.
- **Manifest.** `corpus_manifest.json` stores the SHA-256 of `cases.json` and `truth.json`, the generator's
  commit hash, the master seed and the key hashes. The judge refuses to run if the hashes do not match.
  **Gap:** today the manifest stores only the file hashes, and `judge.py` does not check them.

## 8. File layout

```
corpus_X/  cases.json  truth.json  corpus_manifest.json  gate.json
results_X/ <impl>.jsonl …  judged.csv
```
