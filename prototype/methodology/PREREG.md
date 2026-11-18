# Pre-registration: Issuer-Provenance Oracle for Low-False-Positive JOSE/JWT Library Testing

> Template. Placeholders (Library A, Implementation X, Language L1, Variant V1) are replaced by the
> concrete subject list **before** any corpus is run, and the filled document is frozen (git tag +
> SHA-256 of this file recorded in the lab log). Nothing below may be edited after the freeze except
> in the "Deviations" section, which is append-only.

- **Version / freeze date:** v1.0 — YYYY-MM-DD (fill at freeze)
- **Frozen commit:** `<git sha>`  **SHA-256 of this file:** `<hash>`
- **Authors:** (withheld for double-blind review)

---

## 1. Research questions

| ID | Question |
|---|---|
| RQ1 | Does an issuer-provenance oracle reduce capability-driven false positives relative to a naive differential oracle, without losing true positives? |
| RQ2 | Can reference-free remedies (majority voting, learned capability profiles, rule blacklists) reach a comparable false-positive rate, and what is their silencing cost? |
| RQ3 | Does the detector fire on controlled vulnerable targets (positive controls) and stay silent on their corrected counterparts? |
| RQ4 | Do conformance probes for MUST-reject requirements (which the provenance oracle cannot see by construction) behave as specified on correct and incorrect synthetic verifiers? |

## 2. Definitions

- **Issuer I**: the test harness, which holds all signing keys. For every token *t* it records the
  ground-truth set **Signed_I(t)** — the claims covered by I's signature (∅ for a forgery).
- **Validly issued token**: *t* ∈ **T_I**, i.e. signed by I under a configuration I intended.
- **Forged token**: any token not in **T_I**, produced by