# The Issuer-Provenance Oracle — formal statement, v2

> Supersedes nothing: `ORACLE_FORMAL.md` (v1) stays as the version cited by the submitted paper.
> §7 lists exactly what changed from v1 and why.

## 1. Setting

- **Claims.** A claim set is a finite partial map `Name ⇀ Value` over JSON values. We treat it as a set of
  pairs `(n, v)`.
- **Normalization.** `ν` maps a JSON value to a canonical form:
  - numbers become exact rationals, so `1` and `1.0` are equal but `2^60` and its nearest double are not;
  - strings are compared as code-point sequences, with **no** Unicode normalization;
  - arrays keep their order;
  - an absent claim is distinct from `null`.

  **Assumption N:** `ν` is injective on the values the issuer emits. Two different issued values never
  normalize to the same form.
- **Issuer** `I` holds a signing key `sk_I` and publishes the verification key `pk_I`. The set `Issued`
  contains exactly the tokens `I` produced.
- **Attacker (Dolev–Yao).** The attacker's knowledge `K` contains every public value (including `pk_I`
  and all tokens in `Issued`) plus the attacker's own keys. `K` is closed under the constructor and
  cryptographic operators, with perfect cryptography.
  **Assumption S:** `sk_I ∉ closure(K)`.
- **Reference parse.** `parse_ref` maps a payload byte string to a claim set, or ⊥ if the payload is not
  a single JSON object without duplicate member names. **Assumption R** is that the issuer's intended
  claims equal `parse_ref(payload)` for every token in `Issued`.

## 2. Provenance

For a token `t`, let `σ₁ … σ_k` be its signature entries. Entry `σ_j` covers the signing input `m_j`.

```
Signed(t) = ⋃ { ν(parse_ref(payload(m_j)))  :  Verify(pk_I, alg_j, m_j, σ_j) = true }
```

This is the set of claim pairs that some valid issuer signature on `t` covers. It is ∅ if no entry verifies.

- `honest(t) :⇔ t ∈ Issued`.
- If `t` is honest and has no unsigned members, then `Signed(t) = ν(claims_I(t))`.

**How the generator computes it.** It does not compute `Signed(t)` by running a verifier, which would be
circular. Instead it tracks provenance labels through construction (`DESIGN_generator.md` §5), and it
cross-checks the result with the definition above using an independent reference verifier.

## 3. Verifier model and classification rule

A verifier under configuration θ returns `V_θ(t) = (acc, B, e, τ)`:

- `acc` — whether it accepted;
- `B = ν(exposed claims)` if `acc`, otherwise ⊥;
- `e` — the error;
- `τ` — the verify time.

The error `e` is never an input to the oracle.

**Resource predicate** (v2 parameters from `PREREG_resource.md`):

```
Res(V, t) :⇔ τ(V, t) > max(κ · β_V(alg(t)), τ_min)   on each of r confirmation re-runs
```

Here `β_V(a)` is V's median time on honest tokens with algorithm `a`.

**Classification** (the first matching line wins):

```
O(V, t) = A    if Res(V, t)                            -- resource violation
          A    if acc ∧ B ⊄ Signed(t)                  -- belief not covered by the issuer's signature
          C    if ¬acc ∧ honest(t)                     -- capability / strictness difference
          OK   otherwise                               -- forged-and-rejected, or accepted with belief ⊆ Signed
```

Consequences:

- **Accepted forgery with signed-only belief is OK.** A forged container that the verifier accepts, but
  where it believes only issuer-signed claims, is labelled OK.
- **Honest token with unsigned belief is A.** If a verifier accepts an honest token but exposes a claim
  that is not in `Signed(t)`, that is labelled A. This is intended.

## 4. The ground-truth property the oracle targets

Let `B*` be the claims the verifier actually hands to the application. The adapter observes `B`.

**Assumption F (faithful observation):** `B = ν(B*)`. The adapter neither drops, adds, nor coerces claims.

```
Viol_claim(V, t) :⇔ acc ∧ ∃ (n, v) ∈ ν(B*) : (n, v) ∉ Signed(t)
```

## 5. Properties

**Theorem 1 — No rejection is a security alarm (soundness of C).**
For every V and t, if `¬acc` and `¬Res(V, t)`, then `O(V, t) ∈ {C, OK}`.

*Proof.* Both A lines need either `Res` or `acc`. ∎

*Corollary 1.1.* The oracle labels a token t A for some verifier only if (a) some verifier accepts t with a
belief outside `Signed(t)`, or (b) the resource predicate fires. Disagreement over *whether* to accept an
honest token therefore never produces an A. This is exactly the capability-difference FP source of
cross-implementation differential testing. (The differential detector flags t whenever
`∃ V₁, V₂ : acc(V₁, t) ≠ acc(V₂, t)`.)

**Theorem 2 — Precision of the claim path.**
Under Assumptions N, R and F: if `O(V, t) = A` via the claim line, then `Viol_claim(V, t)` holds.

*Proof.* By F, `B = ν(B*)`. The claim line fires on `acc ∧ B ⊄ Signed(t)`, which is `Viol_claim(V, t)`. ∎

*Reading.* On the claim path, any empirical FP is evidence that N, R or F fails, meaning a bug in the
harness or corpus. It is not imprecision in the rule. This is why `PREREG_provenance.md` treats
claim-path FP as an integrity check and not as a result.

**Theorem 3 — Completeness for claim violations (relative to observation).**
Under N, R and F: if `Viol_claim(V, t)` holds, then `O(V, t) = A`.

*Proof.* `Viol_claim` gives `acc` and a pair in `ν(B*) = B` outside `Signed(t)`. The claim line fires,
unless `Res` fired first, and that also yields A. ∎

*How completeness can fail in practice:*

- **F fails:** the adapter drops or coerces a claim → false negative.
- **R fails:** `parse_ref` disagrees with the verifier's parser on duplicate members or number precision.
  That can cause a false negative, or a false positive when a verifier parses differently from the reference.
- **The implementation projects `Signed` onto a subset of claims** (§6) → false negatives outside that subset.

**The resource path has no soundness theorem.** `Res` is a statistical decision. Its FP rate is bounded
empirically (`PREREG_resource.md`), and its recall is shown only against a synthetic positive control.

## 6. Gap between this definition and the current implementation

`oracle.py::judge_truth` (oracle v3) implements a **projection** of §3:

| case | formal rule (§3) | oracle v3 |
|---|---|---|
| honest, accepted | A if `B ⊄ Signed(t)`, else OK | always OK |
| forged, accepted | compares the full claim set | compares only the authority claim (`role`) against `legit_role` / `attack_role` |

So v3 is sound for A under the assumptions (Theorem 2 restricted to one claim). It is complete **only for
escalation of the authority claim**. Two things are invisible to v3:

- a forged, accepted token whose authority claim is unchanged but whose other claims (subject, audience,
  lifetime) are not covered by the issuer's signature;
- an honest token accepted with injected claims.

Any paper claim of "completeness for escalation" should say "of the authority claim" for results produced by v3.
**Oracle v4** would carry the full `Signed(t)` in `truth.json` and compare the whole `B`. It needs its own
pre-registration before it is used on new data.

## 7. Changes from v1

1. **Rule order.** v1 lists the resource line last, after branches that already return, so as written it
   can never fire. The code checks resource first. v2 fixes the rule to match.
2. **v1 Property 1 was stated too strongly.** v1 says: "if `honest(t)`, O never assigns A." The proof claims
   that acceptance implies `belief ⊆ Signed_I(t)`, but a verifier can accept an honest token and still
   expose an unsigned claim. v1 Property 1 holds only under the extra assumption that verifiers expose
   nothing beyond the signed payload on honest tokens. v2 replaces it with Theorem 1, which needs no
   assumption: *rejections* are never A. That is the property the FP argument actually needs.
3. **The assumptions N, R, F, S are now explicit.** Theorems 2 and 3 hold relative to them.
4. **The v1/v3 gap is documented (§6).**

## 8. Scope: violations outside A by design

- **Non-conformance that does not change belief.** An example is accepting a token that carries a
  must-understand header extension the verifier does not implement. The belief can still be ⊆ `Signed(t)`,
  so the result is OK. Covering this needs a separate conformance oracle.
- **Cross-context substitution.** `Signed(t)` is per-token and ignores context. A claim set that the issuer
  signed for a different audience, token type or purpose, re-used in a new context, satisfies
  `B ⊆ Signed(t)`. A context-indexed refinement `Signed(t, ctx)` is future work.
- **Key-handling defects with no claim escalation, and side channels.**
- **Unknown issuer.** `Signed(t)` requires issuer control. In-the-wild use would need to reconstruct `Signed`
  from observed public keys, and that is future work.
