# PREREG — scale30 মূল্যায়নের pre-registration (২৫ সেপ্ট ২০২৬)

> এই ফাইল **কোনো scale30 রান চালানোর আগে** commit করা হয়েছে। পরে কিছু বদলালে নিচে
> "Deviations" অংশে তারিখ আর কারণসহ লিখতে হবে। আগের লেখা মুছে দেওয়া যাবে না।
> পটভূমি: `PLAN_scale30.md`।

## 1. প্রশ্ন ও scope
- **প্রশ্ন:** implementation-এর সংখ্যা আর ভাষার বৈচিত্র্য বাড়লে naive/data-driven
  differential detector-দের false positive কেমন আচরণ করে, আর provenance oracle (oracle v3,
  `oracle.judge_truth`) বাস্তব vulnerable implementation-এ TP হারায় কি না।
- **scope = authenticity/উৎস।** বাইরে: `crit` semantics, সময়-বৈধতা (exp/nbf), JWE (শুধু
  real-TP panel-এর resource কেস বাদে)। সব corpus টোকেনে `exp=4102444800`, `iat` থাকবে,
  `nbf` থাকবে না।
- **আগে থেকেই জানা, তাই দাবি নয়:** (ক) any-disagreement detector (B0)-এর FP(k) k-এর সাথে
  কখনো কমে না (superset monotonicity); (খ) বৈধ টোকেনে PROV-এর FP = ০ আসে
  soundness-of-C থেকে (`ORACLE_FORMAL.md`)। এ দুটো sanity check হিসেবে রিপোর্ট হবে, finding নয়।

## 2. Implementation নির্বাচন (install করার আগেই স্থির)
নিয়ম: (১) registry-তে সক্রিয়, গত ২৪ মাসে release; (২) স্বাধীন JOSE implementation
(wrapper/fork বাদ); (৩) high-level verify API আছে, যেটা alg allow-list + key নেয়;
(৪) install-এর দিনে যে সর্বশেষ stable version পাওয়া যায় সেটা, পিন করে `ADAPTERS.md`-এ লেখা।

প্রার্থী (৩২): Python — PyJWT, python-jose, Authlib, jwcrypto, joserfc, jwskate, cryptojwt ·
Node — panva/jose, jsonwebtoken, fast-jwt, jsrsasign, njwt, node-jose (reserve: jwt-simple,
@tsndr/cloudflare-worker-jwt) · Go — golang-jwt/v5, lestrrat-go/jwx, go-jose/v4, kataras/jwt ·
Java — nimbus-jose-jwt, jjwt, auth0 java-jwt, jose4j · PHP — firebase/php-jwt, lcobucci/jwt,
web-token/jwt-framework · Rust — jsonwebtoken, josekit, jwt-simple · Ruby — ruby-jwt, json-jwt ·
.NET — Microsoft.IdentityModel.JsonWebTokens, jose-jwt, JWT (jwt-dotnet)।

Reserve শুধু তখন ঢুকবে যখন কোনো প্রার্থী gate-এ বাদ পড়ে। প্রার্থী যে ক্রমে বাদ পড়ে,
reserve সেই ক্রমেই ঢুকবে।

## 3. Adapter নিয়ম
- config = library README-র নিরাপদ স্বাভাবিক ব্যবহার: alg পিন করা (`allowed_algs`),
  key টাইপ করা। misuse config আলাদা panel-এ যাবে (মূল গণনায় নয়)।
- adapter শুধু `corpus/cases.json` পড়ে। `corpus/truth.json` কখনো পড়ে না।
- output প্রতি কেসে একটা JSONL লাইন: `impl, version, lang, backend, case, accepted, claims,
  error, stage∈{keyload,verify,claims}, ns`।
- **Gate** (যেকোনোটা ব্যর্থ হলে adapter বাদ, আর কারণ `ADAPTERS.md`-এ লেখা):
  G1 বৈধ HS256(32B)/RS256(2048)/ES256 ACCEPT (lib যে alg সমর্থন করে না বলে লেখা আছে, সেটা বাদে);
  G2 এক-bit উল্টানো signature REJECT; G3 ACCEPT হলে `claims.role=="user"`;
  G4 `alg:none` (allow-list-এ নেই) REJECT।
- `stage=keyload` ব্যর্থতা হলো **adapter artifact**। এটা capability difference-এ গোনা হবে না।
  কোনো adapter-এ বৈধ কেসের >৫% keyload ব্যর্থ হলে সেটা ঠিক না হওয়া পর্যন্ত বাদ।
- JVM/.NET: corpus দুবার চালিয়ে দ্বিতীয় রান রাখা হবে। resource baseline প্রতি adapter-এ
  আলাদা: বৈধ HS256-min কেসের median ns।

## 4. Corpus v3 (`corpus/gen_corpus.py`, seed স্থির)
- key-seed: ১, ২, ৩ (প্রতিটায় আলাদা issuer key)।
- **V1** alg × key: HS{256,384,512}×{16B, min, 64B}; RS{256,384,512}×{1024,2048,3072,4096};
  PS{256,384}×{1024,2048,4096}, PS512×{2048,4096}; ES256, ES384, ES512, ES256K; EdDSA(Ed25519), EdDSA(Ed448)।
- **V2** header variant (RS256-2048 আর HS256-min-এর উপর): kid, typ-নেই, typ=at+jwt,
  অতিরিক্ত private header, cty=JWT।
- **V3** claim variant (RS256-2048 আর HS256-min-এর উপর): unicode, বড় integer (2^60), aud array, aud string।
- **F1** curated forged family (verifier key = issuer key; allow-list = কেসে লেখা):
  alg:none ×৪ রূপ, RSA-pubkey→HMAC confusion ×৩ key-encoding (PEM, DER, JWK-json),
  attacker HMAC key, attacker RSA key, signature strip, empty signature, embedded `jwk`,
  `kid` path traversal, `jku`, ECDSA r=s=0।
- **F2** `random_fuzz.attack_token`, seed 1, N=2000।
- **Sealed** family: `sealed/`-এ আলাদা run। এগুলো কোনো aggregate সংখ্যায় ঢুকবে না।

## 5. Detector (সবগুলো একই results-এর উপর)
একটা টোকেন t, implementation-সেট S (gate-পাস করা, `keyload` বাদ দিয়ে):
- **B0 NAIVE:** S-এ ACCEPT/REJECT দুটোই থাকলে flag।
- **B1 ACCEPT-MINORITY:** 0 < #ACCEPT < |S|/2 হলে flag।
- **B2 CAP-PROFILE:** প্রতিটা impl i-এর profile P_i = V1 **seed-1**-এর যে (alg, key-variant)
  বৈধ টোকেন i reject করেছে। t-এর (alg, key-variant) কোনো P_i-তে থাকলে i-কে বাদ দিয়ে বাকি
  S-এ B0 চালানো হয়। (alg, key-variant) টোকেন header আর key থেকেই দেখা যায়, তাই truth leak হয় না।
  V2/V3 বা forged টোকেনের key-variant ধরা হবে তার base (alg, key-variant)।
- **PROV:** কোনো i-এর `judge_truth` = A হলে flag।

## 6. Hypothesis ও metric
- **D1 (বর্ণনামূলক):** B0/B1/B2/PROV-এর বৈধ-টোকেন FP rate বনাম k ∈ {2,4,8,16,24,all}।
  প্রতি k-তে ১০০০টা subset, ভাষা-quota সহ (সম্ভব হলে প্রতি ভাষা থেকে সমান)।
  রিপোর্ট: median + IQR।
- **H2:** বৈধ টোকেনে cross-language জোড়ার disagreement rate within-language জোড়ার চেয়ে
  **বেশি**। test: language label permutation (১০,০০০ বার, group-size একই রেখে), এক-দিকে,
  α=0.05। effect size = গড় পার্থক্য (percentage point), সাথে bootstrap CI।
- **H3:** B2 held-out বৈধ টোকেনে (V1 seed ২–৩, V2, V3; আলাদা আলাদা রিপোর্ট) FP rate ≥ ৫%,
  আর bootstrap 95% CI-র নিম্নসীমা > ০। held-out FP < ৫% হলে **H3 ভুল প্রমাণিত**, আর সেটাই লেখা হবে।
- **H4:** real-TP panel-এর প্রতিটা আগে-থেকে-জানা (impl, attack family) জোড়া যা বাস্তবে
  পুনরুৎপাদিত হয়, সেগুলোর প্রতিটা PROV flag করে। কোনো জোড়া মিস হলে H4 ভুল প্রমাণিত।
  B0/B1-এর recall-ও রিপোর্ট হবে। recall-এর সাথে Wilson 95% CI। **সীমাবদ্ধতা:** যে জোড়ায়
  escalated claim সরাসরি গৃহীত হয়, সেখানে PROV-এর recall প্রায় সংজ্ঞাগত। H4-এর তথ্যমূল্য
  মূলত resource (JWE bomb) আর claim-belief কেসে।
  panel (আগে থেকে জানা): PyJWT 0.4.3 + Authlib 0.15.5 (confusion), python-jose 3.3.0
  (JWE bomb), jsonwebtoken 8.5.1 (confusion), misuse config: golang-jwt keyfunc, nimbus
  MACVerifier, njwt unpinned। প্রার্থী: CVE-2022-21449 (JDK 17.0.2 + nimbus/jjwt)।
  পুনরুৎপাদিত না হলে বাদ, আর কারণসহ লেখা।
- **D5:** প্রতি ১০০০ টোকেনে alert সংখ্যা; (impl, error-class) cluster সংখ্যা।
- **D6:** gate-এ বাদ পড়ার সংখ্যা, keyload artifact rate।

## 7. Regression ও থামার নিয়ম
- নতুন pipeline-এ পুরনো ৪টা Python lib আর E3-এর ২৪টা বৈধ family চালালে ৯/২৪ B0 FP আসতে হবে।
  না এলে কোনো ফলাফল রিপোর্ট হবে না।
- gate-পাস করা ভাষা < ৬ হলে "৮ ভাষা" দাবি করা যাবে না।
- নতুন সন্দেহজনক ACCEPT পাওয়া গেলে: `sealed/`-এ রাখা হবে, হাতে যাচাই করা হবে, তারপর
  disclosure। এটা মূল্যায়নের metric-এ ঢুকবে না।

## Deviations
- **D1 (২৫ সেপ্ট, কোনো রানের আগে):** F2 `random_fuzz.attack_token` সরাসরি নয়, একই ৫টা kind আর
  একই সম্ভাবনায় port করা (`gen_corpus.gen_f2`)। কারণ: মূল ফাংশন ২০% কেসে `crit` header যোগ
  করে (§1-এ scope-এর বাইরে), আর `exp` দেয় না (§1 অনুযায়ী আবশ্যক)। crit শাখা বাদ, exp যোগ।
- **D2 (২৫ সেপ্ট, শুধু Python-এর ৭টা impl চালানোর পরে, বাকি ভাষাগুলো চালানোর আগে):** V2/kid কেসে issuer-এর
  JWK-তে একই `kid` যোগ। কারণ: header-এ kid দেওয়া issuer নিজের JWKS-এ সেই kid প্রকাশ করে;
  আগের corpus-এ তা ছিল না, ফলে cryptojwt (KeyJar kid-matching) বৈধ টোকেন reject করছিল, যেটা
  corpus-এর ত্রুটি, library-র নয়। এই পরিবর্তন B0/B2-এর FP **কমায়** (H3-এর বিপক্ষে)।
  আগের সংখ্যা: Python-7-এ B2 held-out FP = 24/54 (V2+V3); পরের সংখ্যা EXP_scale30.md-তে।
  corpus পুনরায় তৈরি (key seedable নয়, তাই সব key নতুন), আর regression check আবার চালানো হয়েছে।
- **D3 (২৫ সেপ্ট, primary analysis-এর পরে):** H4-এর real-TP panel scale30 pipeline-এ **আবার চালানো হয়নি**।
  এর বদলে আগে মাপা ও রিপোর্ট করা ফল উদ্ধৃত করা হচ্ছে: `EXP_phase_b1.md` (PyJWT 0.2.3/0.4.3, Authlib 0.15.5 →
  confusion, শ্রেণী-A; python-jose 3.3.0 → JWE bomb, resource oracle শ্রেণী-A) আর `EXP_crosslang.md`
  (jsonwebtoken 8.5.1 → confusion, real TP)। পরিণাম: H4 এই pre-registration-এর অধীনে **পরীক্ষিত নয়**।
  এর মানে আগের corpus আর আগের oracle-সংস্করণে পাওয়া ফল। CVE-2022-21449 প্রার্থী যাচাই হয়নি।
  EXP_scale30.md-তে H4 "not tested (prior evidence cited)" হিসেবে রিপোর্ট হবে।
