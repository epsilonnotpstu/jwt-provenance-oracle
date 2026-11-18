# Preregistration — Reducing false positives in JOSE/JWT library testing with an issuer-provenance oracle

> Generic, library-agnostic version for the methodology section. It names no implementation, no
> vulnerability identifier and no attack procedure. The study-specific instance, with frozen hashes and
> thresholds, is `scale30/PREREG_provenance.md`.
>
> - **Version / freeze date:** v1.0 — [fill at freeze]
> - **Frozen commit:** [sha]  **SHA-256 of this file:** [hash]
> - After the freeze only the *Deviations* section may change, and it is append-only.

## 1. Background and research question

Differential testing compares how several independent implementations handle the same input and treats
disagreement as a possible defect. For signature-verification libraries, most disagreements are not defects.
Implementations legitimately differ in which algorithms, key sizes, header values and serializations they
support. A detector that flags every disagreement therefore reports these capability differences as false
positives.

An **issuer-provenance oracle** replaces "do the implementations agree?" with a different question: "does
the claim set this verifier accepted come from a valid signature by the legitimate issuer?" The test
harness controls the issuer, so this can be decided from how each test token was constructed. No verifier
is used as the reference.

**RQ.** On the same test corpus and the same set of verifiers, does the provenance oracle have a lower
false-positive rate than disagreement-based detectors, without losing detection of known defects?

## 2. Definitions

| term | meaning |
|---|---|
| verifier | one library under one fixed, documented, safe-usage configuration |
| token | one test input: a signed or crafted object plus the key and allowed-algorithm list given to the verifier |
| observation | one (verifier, token) pair, with outcome (accepted?, exposed claims, error, time) |
| honest token | a token produced by the controlled issuer with its real key, never modified afterwards |
| crafted token | a token produced under the attacker model: public material, previously issued tokens and the attacker's own keys only |
| Signed(t) | the set of claims covered by at least one valid issuer signature present in token t |
| belief(v, t) | the normalized claims verifier v exposes when it accepts t |
| label A | security violation: v accepts t and belief(v, t) is not contained in Signed(t), or a pre-specified resource bound is exceeded |
| label C | capability or strictness difference: v rejects an honest token |
| label OK | every other case |

**Normalization ν.** Fixed before any data is seen:
- numbers are compared as exact rationals;
- strings are compared code point by code point, with no Unicode normalization;
- member order inside objects is ignored.

Any extra equivalence rules, and the reason for each, are listed in the study-specific preregistration
before data collection.

## 3. Hypotheses

- **H1 (false positives).** On honest tokens, the token-level false-positive rate of the provenance oracle
  is lower than that of each disagreement-based baseline.
- **H2 (bounded false positives).** On a fresh corpus the harness has never seen, the observation-level
  false-positive rate of the provenance oracle stays below a pre-specified threshold, and so does the
  upper bound of its 95% confidence interval.
- **H3 (detection).** The provenance oracle labels A on every reproduced entry of an independently
  labelled positive panel.
- **H4 (integrity check, not a finding).** The claim path produces no A on honest tokens whose claims every
  verifier can represent exactly. A non-zero count means a defect in the harness, not in the oracle, and
  gets a root-cause report.
- **H5 (test dimension; exploratory, direction stated in advance).** A grammar-based generator with
  mutation produces more distinct cross-verifier behaviour patterns than the previous corpus, when both
  corpora are subsampled to the same size.
- **H6 (conformance probes; descriptive).** Some MUST-reject requirements leave belief unchanged, so the
  oracle cannot see them by construction. For each such requirement, issuer-signed probe tokens are run
  against one correct and one deliberately incorrect synthetic verifier, and the probe must separate the
  two. This covers the oracle's known blind spot. It is not a detection claim about real verifiers.

## 4. Baselines

- **B0 — any disagreement.** Flag a token if at least one verifier accepts it and at least one rejects it.
- **B1 — minority acceptance.** Flag a token if some verifiers accept it but fewer than half do.
- **B2 — capability profile.** Remove from the comparison each verifier's disagreements on
  (algorithm, key-variant) combinations its profile says it does not support, then apply B0 to what is left.
  The profiles are learned from a separate calibration corpus.

All detectors see identical observations.

## 5. Ground truth

| set | content | label source (independent of the oracle) |
|---|---|---|
| N (negatives) | every included verifier × every honest token | honest issuance by construction |
| P (positives) | a panel of (verifier, token family) pairs with a known defect | a published fix with a before/after version pair, or a synthetic verifier with a documented injected defect |
| U (unlabelled) | current verifiers × crafted tokens | none; reported descriptively |

The panel is fixed before data collection. Its list is committed as a cryptographic hash. The list itself
is revealed at write-up time, or after coordinated disclosure ends. An entry counts only if its defect
reproduces in the harness under a criterion written before the run. Entries that do not reproduce are
listed with reasons and are not counted as misses.

## 6. Metrics

- **FPR** = (number of A labels on N) / |N|
- **TPR** = (number of A labels on reproduced P) / |reproduced P|, reported per stratum (claim path, resource path)
- **FNR** = 1 − TPR
- Every proportion gets a Wilson 95% interval.
- Observations that share a token are not independent, so observation-level rates also get a
  token-clustered bootstrap interval (10,000 resamples).
- The baselines are defined per token only, so detectors are compared at token level.
- **Silencing.** For the baselines that suppress disagreements (B1, B2), report the number of crafted-token
  comparisons each one suppresses. A lower FPR bought by suppressing comparisons is a trade-off, not an
  improvement.
- **Test dimension (for H5).**
  - number of grammar productions and operators;
  - number of distinct acceptance vectors (which verifiers accept a token);
  - number of distinct (token family × outcome) cells.

## 7. Corpus generation

- **Generation.** Honest tokens are derived from a typed grammar over headers, claim sets, JSON
  serialization choices and token serializations. The issuer role alone signs them.
- **Mutation.** Crafted tokens come from applying typed mutation operators to generated tokens. The
  operators work at the encoding, structural, header and claim levels, and chains have depth up to a
  pre-specified maximum. A knowledge restriction applies: the attacker may sign only with keys it holds,
  and may reuse any public byte string.
- **Provenance labels.** Labels are propagated during construction and then re-derived independently with
  a reference verifier. If the two disagree, generation stops.
- **Ambiguity tags.** Tokens whose meaning is ambiguous are tagged at generation time and reported as their
  own stratum. Ambiguous means duplicate member names, numbers outside exactly representable ranges, or
  claims with more than one valid encoding.
- **Seeds and hashes.** Randomness comes from one master seed, with a separate derived seed for each family.
  The manifest records the hashes of all emitted files and all keys.

## 8. Analysis plan

1. **Regression check.** The previous configuration must reproduce the previously reported baseline count.
   If it does not, nothing is reported.
2. **Controls, per verifier.** An honest token must be accepted with correct claims. A corrupted signature
   must be rejected. An algorithm outside the allow-list must be rejected. Verifiers that fail the gate, or
   exceed a pre-specified key-loading failure rate, are excluded by the pre-registered rule and replaced
   from a reserve list.
3. **Freeze.** The analysis script is frozen by commit hash. Every metric in §6 is computed and reported,
   including results that contradict the hypotheses.
4. **Tests.**
   - H1 uses a paired exact McNemar test per baseline, with Holm correction across baselines, α = 0.05.
   - H2 and H3 are single pre-specified decisions.
   - H5 compares distinct-pattern counts over 1,000 equal-size subsamples.
5. **Reclassification.** An A on N that manual review confirms as a genuine violation is reported twice:
   as a false positive under the pre-registered labels, and separately as a finding. It is never moved
   into P after the fact.
6. **Deviations.** Any change after registration is appended with its date and reason. Earlier text is not
   edited.

## 9. Threats to validity

**Construct**
- The oracle observes what a library exposes, not what an application does with it.
- Claim-type coercion by a library can make belief differ from Signed(t) with no security consequence.
  Examples: large integers rounded to floating point, a single-value field turned into a one-element list,
  list order changed. These cases are handled by pre-declared ν rules and ambiguity tags, never by rules
  added after seeing the data.
- Label C covers interoperability defects as well as intended strictness. It means "not a security
  violation", not "correct".
- Violations that leave belief unchanged are out of scope for this oracle by design. Examples: ignoring a
  must-understand header, cross-context reuse of a validly signed token.

**Internal**
- Adapter configuration is a researcher degree of freedom. Adapters are frozen before the main run and
  follow each library's documented safe usage.
- Timing noise affects the resource path. Its parameters come from a separate earlier study and are not
  tuned on this corpus.
- Generator bugs are guarded against by the two-source label check and the controls.

**External**
- Verifiers are chosen by a written selection rule, not sampled at random from deployments.
- Only safe-usage configurations are tested.
- The positive panel is small and partly synthetic, so TPR generalizes weakly.

**Statistical conclusion**
- Observations are clustered by token and by verifier. Clustered intervals are reported next to naive ones.
- With a small panel, a perfect TPR is still compatible with much lower true recall. The Wilson lower bound
  is always reported with it.
- H5 is exploratory. A higher pattern count shows the corpus is more diverse, not that the detector is better.

## 10. Frozen artefacts (filled at registration)

- generator commit;
- master seed;
- analysis-script commit;
- adapter commits;
- lockfile hashes;
- panel hash;
- FPR threshold for H2;
- ν rules;
- maximum mutation depth.

## Deviations

(none yet)
