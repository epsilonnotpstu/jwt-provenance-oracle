# E-scale30 — Provenance বনাম naive/data-driven differential: ৩২ implementation × ৮ ভাষা (২৫ সেপ্ট ২০২৬)

**Pre-registration:** `scale30/PREREG.md` (commit `a8db4e0`, কোনো রানের আগে), deviation D1–D3 সেখানে লেখা।
**Pipeline:** `scale30/` — corpus → ৮ ভাষার adapter → `judge.py` → `analysis.py` (`results/analysis.json`)।
**Adapter:** `scale30/ADAPTERS.md`। **চলমান পর্যবেক্ষণ:** `scale30/LOG.md`।

## ০. সেটআপ
- **Corpus v3:** ২২০৪টা টোকেন — ১৫৯টা বৈধ (V1 alg×key ১০৫, V2 header ৩০, V3 claim ২৪; ৩টা key-seed) আর
  ২০৪৫টা জাল (F1 curated DY ৪৫, F2 seeded random ২০০০)। provenance label শুধু `truth.json`-এ; adapter দেখে না।
- **Implementation:** ৮টা ভাষায় ৩৪টা চালানো হয়েছে, সবগুলো gate পাস করেছে। PREREG keyload>৫% নিয়মে বাদ: go/jwx (১১.৩%),
  rust/josekit (১৫.১%) → reserve node/jwt-simple আর node/cloudflare-worker-jwt ঢুকেছে। **Primary = ৩২টা**:
  Python ৭, Node ৮, Go ৩, Java ৪, PHP ৩, Rust ২, Ruby ২, .NET ৩।
- **Regression:** নতুন pipeline-এ পুরনো ৪টা Python lib × E3-এর ২৪ family → B0 = ৯/২৪, একই ৯টা family, একই rejecter
  (EXP_corpus_v2.md-র সাথে হুবহু মিল)।
- **Detector:** B0 = যেকোনো অমিল; B1 = সংখ্যালঘু ACCEPT; B2 = V1-seed-1 থেকে বানানো (alg, key-variant)
  capability profile + B0; PROV = oracle v3 (claim + resource); PROV_claim = শুধু claim oracle (**post-hoc**)।

## ১. মূল ফল (৩২ impl, সব টোকেন)

| detector | বৈধ টোকেনে FP | হার | জাল টোকেনে flag |
|---|---|---|---|
| B0 NAIVE | 114/159 | 71.7% | 0 |
| B1 ACCEPT-MINORITY | 6/159 | 3.8% | 0 |
| B2 CAP-PROFILE | 38/159 | 23.9% | 0 |
| PROV (pre-registered) | 64/159 | 40.3% | 61 |
| PROV_claim (post-hoc) | 0/159 | 0.0% | 0 |

**জাল টোকেন:** ৩২টা current library-র **কোনোটাই ২০৪৫টা জাল টোকেনের একটাও গ্রহণ করেনি।** তাই জাল অংশে
B0/B1/B2-এর ০ flag হলো সঠিক আচরণ। PROV-এর ৬১টা flag সবই resource oracle-এর ("SLOW"); কোনো acceptor নেই (§৬)।

## ২. D1 — FP বনাম implementation সংখ্যা (১০০০টা ভাষা-quota subset, median [IQR])

| k | B0 | B1 | B2 | PROV | PROV_claim |
|---|---|---|---|---|---|
| 2 | 17.0% [7.5–24.5] | 0.0% [0.0–0.0] | 0.0% [0.0–7.5] | 7.5% [5.7–17.6] | 0% |
| 4 | 32.1% [24.5–40.3] | 1.9% [1.3–3.8] | 7.5% [1.3–11.3] | 18.2% [9.4–23.9] | 0% |
| 8 | 45.3% [41.5–54.7] | 3.8% [3.8–3.8] | 11.3% [8.8–22.6] | 26.4% [23.3–29.6] | 0% |
| 16 | 56.6% [49.1–56.6] | 3.8% [3.8–3.8] | 23.9% [16.4–23.9] | 30.8% [30.2–34.6] | 0% |
| 24 | 56.6% [56.6–71.7] | 3.8% [3.8–3.8] | 23.9% [23.9–23.9] | 33.3% [32.1–39.0] | 0% |
| 32 | 71.7% | 3.8% | 23.9% | 40.3% | 0% |

- B0 সংজ্ঞাগতভাবেই কখনো কমে না (PREREG §1), তাই এটা বর্ণনামূলক ফল, hypothesis নয়। ৮টা impl-এই প্রায় অর্ধেক বৈধ টোকেন flag হয়।
- **B0-এর হার সবচেয়ে কম-সক্ষম implementation-এর উপর নির্ভর করে:** reserve দুটো বাদ দিলে (৩০ impl) B0 = ৫৬.৬%।
  শুধু node/jwt-simple (HS*/RS256 ছাড়া কিছু সমর্থন করে না) একাই ~১৫ pp যোগ করে।

## ৩. Hypothesis

**H2 — cross-language জোড়া বৈধ টোকেনে within-language জোড়ার চেয়ে বেশি অমিল করে: সমর্থিত নয়।**
cross = 0.177, within = 0.158, পার্থক্য **1.9 pp**; language-label permutation (১০,০০০), এক-দিকে **p = 0.138**।
টোকেন-bootstrap CI [1.0, 2.9] pp শূন্য ছোঁয় না। কিন্তু সেই CI implementation-স্তরের নির্ভরশীলতা ধরে না;
pre-registered test permutation, আর সেটা তাৎপর্যপূর্ণ নয়। প্রভাব এমনিতেও ছোট।
→ capability-পার্থক্য ভাষার সীমানা ধরে চলে না। একই ভাষার library-রাও ততটাই অমিল করে।

**H3 — B2 (alg/key-size profile) held-out বৈধ টোকেনে টেকে না: সমর্থিত।**

| held-out গ্রুপ | B2 FP | 95% bootstrap CI |
|---|---|---|
| V1 seed ২–৩ (একই alg/size, নতুন key) | 2/70 = 2.9% | [0.0, 7.1] |
| V2 header variant | 24/30 = 80.0% | [66.7, 93.3] |
| V3 claim variant | 12/24 = 50.0% | [29.2, 70.8] |
| **সব held-out** | **38/124 = 30.6%** | **[22.6, 38.7]** |

profile-এ মোট ১৭৮টা rule। ব্যর্থতার উৎস (seed-1): V2 — kataras-jwt সব অ-মানক header reject করে; `cty:JWT` reject করে
jjwt, jose4j আর kataras; `typ:at+jwt` reject করে nimbus; private header reject করে joserfc। V3 — token-এ `aud` থাকলে কিন্তু
audience configure না থাকলে reject করে PyJWT, python-jose, jose4j, rust/jsonwebtoken। V1 held-out-এর ২টা FP = rust/jwt-simple-এর
high-S ES256K reject (§৬)। অর্থাৎ capability (alg, key-size)-এর function নয়: signature-এর randomness-এর উপরও নির্ভর করে।
- **Sensitivity:** `cty:JWT` দিয়ে plain claims পাঠানো RFC 7519 §5.2-এর সাথে সাংঘর্ষিক (nested JWT বোঝায়), তাই ওই variant
  সম্ভবত corpus-এর ত্রুটি। cty বাদ দিলে held-out B2 FP = 32/118 = **27.1%**। তাতেও H3-এর সিদ্ধান্ত বদলায় না।
- **সীমা:** পরীক্ষা হয়েছে মাত্র একটা profile ডিজাইনের। header/claim-সচেতন আরও সমৃদ্ধ profile এই FP কমাবে।
  দাবিটা তাই "যেকোনো profile ব্যর্থ" নয়। দাবিটা হলো: profile-কে প্রতিটা নতুন dimension আগে থেকে জানতে হয়,
  আর আমাদের পরীক্ষিত dimension-এর বাইরে গেলেই সে ভাঙে।

**H4 — PROV বাস্তব vulnerable implementation-এ TP হারায় না: এই pre-registration-এ পরীক্ষিত নয় (Deviation D3)।**
আগের প্রমাণ: EXP_phase_b1.md-তে PyJWT 0.2.3/0.4.3 আর Authlib 0.15.5 (confusion) → শ্রেণী-A, python-jose 3.3.0
(JWE bomb) → resource oracle শ্রেণী-A; EXP_crosslang.md-তে jsonwebtoken 8.5.1 → confusion, real TP।
এসব ভিন্ন corpus আর আগের pipeline-এর ফল। PREREG-এর নিজের মন্তব্য অনুযায়ী escalated-claim কেসে recall প্রায় সংজ্ঞাগত।

## ৪. D5 — triage cost (পুরো corpus, ২২০৪ টোকেন)

| detector | alert | প্রতি ১০০০ টোকেনে | (impl, error-class) cluster |
|---|---|---|---|
| B0 | 114 | 51.7 | 40 |
| B1 | 6 | 2.7 | 28 |
| B2 | 38 | 17.2 | 28 |
| PROV | 125 | 56.7 | 27 |
| PROV_claim | 0 | 0 | 0 |

এই corpus-এ কোনো সত্যিকারের bug নেই (§১)। তাই প্রতিটা alert-ই মানুষের জন্য অপচয়। একটা ব্যতিক্রম: B0-এর ১১৪টা alert-এর (B1-এর ৬টা এর মধ্যেই পড়ে) পেছনে বাস্তব interop পার্থক্য আছে। নিরাপত্তার নয়, কিন্তু দেখার মতো।

## ৫. D6 আর sensitivity
- gate-এ শেষ পর্যন্ত কেউ বাদ পড়েনি। ৩টা adapter bug gate-এ ধরা পড়েছে আর ঠিক করা হয়েছে (ADAPTERS.md)।
  keyload (বৈধ কেসে): ১০টা primary impl-এ ৩–৬টা (সর্বোচ্চ ৩.৮%), সবই library-র unsupported alg/curve।
- **বাদ পড়া দুটো সহ (৩৪ impl):** B0 71.7%, B1 3.8%, B2 23.9%, PROV 40.9%, PROV_claim 0%।
  **reserve ছাড়া (৩০ impl):** B0 56.6%, B1 3.8%, B2 23.9%, PROV 40.3%, PROV_claim 0%। B1/B2/PROV_claim-এর ফল
  set-নির্বাচনের উপর নির্ভর করে না; B0 করে।

## ৬. পথে পাওয়া finding
1. **Resource oracle রানটাইম-জুড়ে অস্থির (PROV-এর সব FP এখান থেকে)।** pre-registered baseline (প্রতি impl-এ
   HS256-min-এর median, ৩টা sample, ২০×, single-shot timing) দুইভাবে ভাঙে: (ক) structural — authlib/joserfc-এ ES384/ES512-এর
   স্বাভাবিক verify HS256-এর ১৮–২৬×; (খ) noise — Node-এ HS baseline কয়েক µs, GC/JIT jitter-এ rejected টোকেনও "SLOW" হয়।
   ICCIT/E3-এ এটা দেখা যায়নি কারণ সেখানে baseline ছিল ৪টা lib-এর সবচেয়ে ধীরটা, আর corpus ছোট ছিল।
   **পরিণাম:** resource উপাদানের জন্য alg-matched baseline আর repeated-measurement confirmation লাগবে। এটা
   future pre-registration-এর বিষয়; এই রানে threshold বদলানো হয়নি।
2. **rust/jwt-simple 0.13.1 বৈধ high-S ES256K signature প্রত্যাখ্যান করে।** seed-1-এর টোকেন low-S (গৃহীত), seed ২–৩ high-S
   ("Signature tag didn't verify")। **যাচাই করা:** RFC 8812 (§3.2, §5.4) low-S চায় না; কারণ হলো k256 0.14.0-এর
   `NORMALIZE_S = true`, যার ফলে ecdsa 0.17.0-এর `verify_prehashed` high-S বাতিল করে। স্বতন্ত্র repro আর issue draft আছে
   `scale30/ISSUE_DRAFT_jwt-simple_es256k_highS.md`-এ। একটা standard issuer-এর প্রায় অর্ধেক বৈধ ES256K টোকেন তাই প্রত্যাখ্যাত হয়।
   interop সমস্যা, নিরাপত্তার নয়।
3. **Alg-সমর্থন অসম:** ES256K মাত্র ৮/৩২ গ্রহণ করে, Ed448 ৯/৩২, EdDSA-Ed25519 ১৮/৩২, PS* ২৪/৩২। B1-এর সব FP ঠিক
   এই বিরল-alg টোকেনে (ES256K, Ed448), যেমনটা PLAN-এর worked example বলেছিল।

## ৭. দাবি ↔ প্রমাণ

| দাবি | প্রমাণ | অবস্থা |
|---|---|---|
| naive differential-এর বৈধ-টোকেন FP implementation বাড়লে দ্রুত বাড়ে (৮টাতেই ~৪৫%, ৩২টাতে ৭২%) | D1 | বর্ণনামূলক, সংজ্ঞাগতভাবে monotone |
| (alg, key-size) capability profile held-out header/claim variant-এ টেকে না | H3 (৩০.৬%, cty ছাড়া ২৭.১%) | সমর্থিত |
| header/claim category-সচেতন profile (B2+) নতুন variant-এ টেকে না | §১০: P1, P2 দুটোই সমর্থিত নয় | **মিশ্র** — B2+ FP অনেক কমায় (৬৬.৭% → ১৬.৭%) কিন্তু ৫%-এর নিচে নামে না; নতুন category-র বেশিরভাগ কোনো অমিল তৈরিই করে না |
| cross-language differential-এ capability-FP বেশি | H2 | **সমর্থিত নয়** — এই দাবি করা যাবে না |
| provenance বাস্তব TP হারায় না | H4 | এখানে পরীক্ষিত নয়; আগের প্রমাণ উদ্ধৃত |
| provenance oracle (resource সহ) কম FP দেয় | মূল ফল: PROV ৪০.৩% | **resource v1 দিয়ে দাবি করা যাবে না** — অস্থির; v2 (§৯) দিয়ে নতুন corpus-এ ০ FP, কিন্তু সেটা আলাদা pre-registration |
| claim oracle বৈধ টোকেনে FP দেয় না | PROV_claim ০% | soundness প্রমাণ থেকেই আসে, empirical finding নয়; post-hoc |
| ৩২টা current library-র কেউ এই corpus-এর জাল টোকেন গ্রহণ করে না | §১ | সমর্থিত (নতুন 0-day নেই) |

## ৮. Threats
- adapter config-এর সিদ্ধান্ত (pin[0], iss/aud বন্ধ, optional plug-in বাদ) ফল বদলায়। সব ADAPTERS.md-তে লেখা।
- keyload/verify সীমারেখা আংশিকভাবে API ডিজাইনের উপর নির্ভর করে (jwx/josekit বাদ পড়ার কারণ)। তাই sensitivity-তে দুটোকে সহ ফলও দেখানো হয়েছে।
- corpus-ত্রুটি: D2 (kid-JWK) ঠিক করা হয়েছে; cty variant সম্ভবত অ-RFC, তার sensitivity দেখানো হয়েছে।
- Python/Node বেশি (১৫/৩২)। D1-এ ভাষা-quota দিয়ে আংশিক সামাল দেওয়া হয়েছে।
- key-generation seedable নয়; corpus ফাইলগুলো নিজেরাই artifact (sha256 আছে `corpus_manifest.json`-এ)।

## ৯. Resource oracle v2 (আলাদা pre-registration: `scale30/PREREG_resource.md`, commit `d5b8516`, মাপার আগে)
নকশা: (alg, key-variant)-মিলানো baseline (V1 seed-1, ১৫ বার মেপে median) → single-shot screening (> ২০·B) →
candidate-কে ১৫ বার আবার মাপা → SLOW ⇔ median > ২০·B **এবং** median − B > ১ ms। মূল্যায়ন **নতুন corpus**-এ
(`scale30/corpus_r/`, নতুন key আর seed), একই ৩২টা impl আর একই adapter। ফল: `scale30/resource_v2_summary.json`।

| | v1 (single-shot, HS256 baseline) | v2 |
|---|---|---|
| বৈধ টোকেনে FP (১৫৯) | 53 (33.3%) | **0** |
| জাল টোকেনে flag (২০৪৫) | 29 | **0** |

- **R1 (বৈধে ০ FP): সমর্থিত। R2 (জালে ০ flag): সমর্থিত।** screening-এ ২২টা (impl, টোকেন) candidate ছিল, ১২টা impl-জুড়ে
  (বেশিরভাগ Node, Ruby, PHP)। ১৫ বার আবার মাপার পরে একটাও SLOW থাকেনি, মানে সবই ছিল single-shot noise।
  এর মানে দুই সমস্যার দুই সমাধান: alg-মিলানো baseline structural FP সরায় (v1-এর ৮২টা flag থেকে candidate নেমে ২২),
  আর confirmation noise সরায় (২২ → ০)।
- **v1-এর ব্যর্থতা নতুন corpus-এও পুনরুৎপাদিত** (৩৩.৩%): এটা আগের corpus-এর কোনো বিশেষত্ব ছিল না।
- **R3 (positive control): সমর্থিত।** controlled verifier (`x-cost` সংখ্যক SHA-256 iteration, cap নেই): x-cost ≥ ১০⁴ →
  ১৫/১৫ SLOW; x-cost নেই → ০/৫। x-cost = ১০³ → ০/৫ (কোনো পূর্বাভাস ছিল না)।
- **Detection limit:** ১ ms floor-এর কারণে ১ ms-এর কম অতিরিক্ত সময় সংজ্ঞাগতভাবেই অদৃশ্য (১০³ iteration এই সীমার নিচে পড়ে)।
  একই কারণে একটা ধীর-কিন্তু-বৈধ alg-এর ২০× পর্যন্ত slowdown-ও ধরা পড়ে না। FP-শূন্যতার দাম এই সংবেদনশীলতা।
- **সীমা:** control target আমাদের বানানো, বাস্তব library নয়। বাস্তব DoS bug-এ recall এখানে মাপা হয়নি।
  v2-এর নকশা v1-এর ব্যর্থতা দেখে বানানো। overfitting ঠেকাতে মূল্যায়ন নতুন corpus আর নতুন timing-এ করা হয়েছে,
  parameter আগে স্থির করা (T=২০, R=১৫, F=১ ms)। কিন্তু একই ৩২টা impl আর একই মেশিনে: অন্য হার্ডওয়্যারে যাচাই হয়নি।

## ১০. শক্ত baseline B2+ (আলাদা pre-registration: `scale30/PREREG_B2plus.md`, commit `3a18c63`, test corpus-এর আগে)
B2+ = ১৪টা header/claim category-র উপর প্রতি-impl blacklist (DDYF-ধরনের knowledge blacklist-এর সরল রূপ), training =
মূল corpus V1+V2+V3 seed-1 (মোট ১৯০টা rule)। test = নতুন `corpus_b` (৬৯টা বৈধ টোকেন, নতুন key)।
ফল: `scale30/b2plus_summary.json`।

| test গ্রুপ | B0 | B2 | **B2+** | PROV_claim |
|---|---|---|---|---|
| T-same (চেনা category-র নতুন মান), n=36 | 66.7% | 66.7% | **16.7%** [5.6, 30.6] | 0% |
| T-new (অচেনা category), n=33 | 9.1% | 9.1% | **9.1%** [0.0, 21.2] | 0% |

- **P1 (T-same-এ B2+ < ৫%): সমর্থিত নয়।** ৬টা FP-এর সবই `typ: "JOSE"` থেকে। rust/jwt-simple training-এ `typ: at+jwt`
  গ্রহণ করেছিল, কিন্তু "JOSE" প্রত্যাখ্যান করে ("Not a JWT token")। অর্থাৎ আচরণ category-র উপর নয়, নির্দিষ্ট **মানের** উপর নির্ভর করে।
- **P2 (T-new-এ B2+ ≥ ৫% আর CI-নিম্নসীমা > ০): সমর্থিত নয়** (CI-নিম্নসীমা ০)। ৬টা নতুন category-র ৫টা (nbf, float exp,
  ৬ KB payload, nested claim, jti) ৩২টা library-র কোনো অমিলই তৈরি করেনি। একমাত্র FP-উৎস self-embedded `jwk`:
  joserfc header-এর ৫১২ byte সীমা ছাড়ায়, rust/jwt-simple `jwk`-কে string হিসেবে parse করতে চায় ("invalid type: map"),
  আর kataras-jwt কোনো অ-মানক header মানে না।
- **P3 (blacklist-এর দাম):** জাল টোকেনে (impl, টোকেন) জোড়ার **০.৯২%** B2+-এ চুপ হয়ে যায় (৫৯৯/৬৫,৪৪০)। B2-তে এটা ছিল ০.০০৫% (৩টা)।
  প্রায় ২০০× বেশি অন্ধত্ব: এই জোড়াগুলোয় ভবিষ্যতের কোনো সত্যিকারের ভুল-গ্রহণ ধরা পড়বে না।
- **সৎ সারাংশ:** শক্ত profile FP অনেক কমায়, আর "নতুন category-তে blacklist ভাঙে" যুক্তিটা এই ডাটায় দুর্বল, কারণ নতুন
  category-র বেশিরভাগ অমিলই তৈরি করে না। টিকে থাকা দাবিটা সংকীর্ণ: capability-পার্থক্য **মান- আর আকার-নির্দিষ্ট**
  (typ-এর মান, header-এর byte-সীমা, header-এর JSON টাইপ)। তাই category-স্তরের blacklist-কে নির্দিষ্ট মানও আগে থেকে জানতে হয়।
  ১৯০টা rule নিয়েও B2+ মোট ৯/৬৯ (১৩%) বৈধ টোকেন flag করে, আর বাড়তি rule-এর দাম জাল টোকেনে বেশি অন্ধত্ব।
  provenance-এর সুবিধাটা তাই "কম FP, কোনো profile রক্ষণাবেক্ষণ ছাড়া, কোনো তুলনা চুপ না করে" (PROV_claim: ০ FP, ০ চুপ)।
- **পাশে পাওয়া interop finding:** rust/jwt-simple 0.13.1 RFC 7515-এর `jwk` header (JSON object) parse করতে পারে না,
  আর `typ: "JOSE"` প্রত্যাখ্যান করে। নিরাপত্তার নয়। ES256K issue-এর সাথে একই রিপোর্টে যোগ করা যায় (যাচাই: শুধু এই রানের error message)।
