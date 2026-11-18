# The Issuer-Provenance Oracle — a formal statement

> paper §5.2-এর formal সংস্করণ। লক্ষ্য: provenance oracle-কে একটা *general principle*
> হিসেবে দাঁড় করানো — নির্দিষ্ট library/alg/error-string-নিরপেক্ষ — এবং তার দুটো
> মূল ধর্ম (soundness of C, completeness for escalation) স্পষ্ট করা।

## Setting

- একজন সৎ **issuer** `I`-এর key material: গোপন `sk_I` (RSA/EC private key বা HMAC
  secret) এবং প্রকাশ্য `pk_I`।
- একজন **Dolev-Yao attacker** `A`, যার knowledge `K_A` = সব প্রকাশ্য মান (`pk_I` সহ)
  + `A`-এর নিজের key। সীমা: `sk_I ∉ closure(K_A)` — অর্থাৎ perfect-crypto ধরে নিয়ে
  `A` কখনো `I`-এর গোপন key বের করতে পারে না।
- একটি **verifier** (library under test) `V`, config `θ` (allowed algorithms, key)।
  আউটপুট: `V_θ(t) = (accept?, belief)` যেখানে `belief` = গৃহীত হলে যে claim-গুলো
  `V` application-কে দেখায় (নইলে `⊥`)।

## Ground-truth provenance

প্রতিটি টোকেন `t`-এর জন্য আমরা issuer হিসেবে জানি:

- `honest(t) ∈ {⊤, ⊥}` — `I` কি `sk_I` দিয়ে `t` (বা তার signed অংশ) তৈরি করেছে?
- `Signed_I(t)` — `t`-এর যে claim-গুলোর উপর `I`-এর signature বৈধভাবে যাচাই হয়
  (honest token-এ = issuer-এর intended claim; forgery-তে সাধারণত `∅`, তবে
  format-confusion-এ একটি বৈধ-signed benign core থাকতে পারে)।
- `authz(t)` — honest হলে `I` যে authority (যেমন `role`) সাইন করেছিল।
- `attack(t)` — attacker যে escalated authority চায় (forgery-তে)।

এই তথ্য **পাওয়া যায় কারণ আমরাই issuer** (library-testing setting; §4)। এটাই
oracle-কে সম্ভব করে, এবং এটাই in-the-wild scanning-এর সাথে পার্থক্য।

## The oracle

resource-signal (verify-time `≫` baseline) আলাদা path; নিচে claim-path:

```
O(V_θ, t) =
  if  ¬accept          →  if honest(t)  then  C      # বৈধ টোকেন প্রত্যাখ্যাত
                           else                OK     # forgery সঠিকভাবে বাতিল
  if   accept          →  let b = belief(V_θ(t)) in
        if  b ⊆ Signed_I(t)              →  OK        # শুধু issuer-signed মানই বিশ্বাস
        else                            →  A          # issuer সাইন করেনি এমন claim গৃহীত
  if   verify-time ≫ baseline           →  A          # resource exhaustion
```

`b ⊆ Signed_I(t)` = verifier যা believe করল তার প্রতিটি claim issuer বৈধভাবে
সাইন করেছিল। এর অন্যথা (escalated `role`, বা unsigned overlay থেকে আসা মান) = `A`।

**গুরুত্বপূর্ণ:** `O` কখনো error-string বা per-alg allow-list দেখে না, অন্য
implementation-এর সাথে তুলনাও করে না। রেফারেন্স একটাই — `I`-এর ground-truth
`Signed_I(t)`।

## দুটি ধর্ম (paper-এর দাবির ভিত্তি)

**ধর্ম ১ — C-এর soundness (capability difference কখনো false alarm নয়):**
> যদি `honest(t)` হয়, তবে যত library-ই `t` reject করুক না কেন, `O` তাদের কখনো `A`
> দেয় না — সর্বোচ্চ `C`।

*কেন:* honest হলে reject-branch সরাসরি `C` দেয়; accept-branch-এ `belief ⊆
Signed_I(t)` (issuer নিজেই সব সাইন করেছে) → `OK`। কোনো branch `A` নয়। ∎

এই ধর্মই cross-implementation differential-এর মূল false-positive উৎস (একটি বৈধ
টোকেন কেউ support করে না) সম্পূর্ণ নির্মূল করে — নির্মাণ-দ্বারা, তদন্ত-দ্বারা নয়।
§7.1-এর `9/24 → 0` এই ধর্মেরই পরিমাপ।

**ধর্ম ২ — escalation-এর completeness:**
> যদি `V` কোনো claim `c ∈ belief` এমন গ্রহণ করে যা `c ∉ Signed_I(t)` (issuer সাইন
> করেনি), তবে `O` অবশ্যই `A` দেয়।

*কেন:* accept-branch-এ `belief ⊄ Signed_I(t)` → সরাসরি `A`। ∎

এই ধর্ম নিশ্চিত করে যে FP কমাতে গিয়ে আমরা কোনো প্রকৃত escalation মিস করি না
(§7.1-এ same true-positive; §7.2-এ real-CVE reproduce)।

## Differential oracle-এর সাথে সম্পর্ক

Cross-implementation differential `D(t)` flag করে যদি `∃ V₁,V₂: accept(V₁,t) ≠
accept(V₂,t)`। honest `t`-এ যদি library-দের capability ভিন্ন হয় তবে `D` flag করে
কিন্তু `O` করে না (ধর্ম ১)। অর্থাৎ:

> `FP(D) \ FP(O) ⊇ { honest t : libraries disagree by capability }`

TLS-এ DDYF এই সেট ছোট রাখে **config-alignment** দিয়ে (সব PUT একই feature-set-এ)।
JOSE/JWT-তে সেটা অসম্ভব: capability = *missing feature* (config নয়) — একটি library-কে
config বদলে EdDSA verify করানো যায় না। তাই এখানে `O`-এর provenance-anchor অপরিহার্য,
`D`-এর alignment যথেষ্ট নয়। এটাই paper-এর কেন্দ্রীয় domain-argument।

## সীমা (formal-ও সৎ)

- `Signed_I(t)` জানতে issuer-control লাগে → in-the-wild-এ `O` সরাসরি চলে না
  (approximation ভবিষ্যৎ কাজ: known-JWKS observation থেকে `Signed_I` আংশিক পুনর্গঠন)।
- `belief(V_θ(t))` library-র exposed claim থেকে নেওয়া; যদি application signature-এর
  বাইরে গিয়ে টোকেন re-parse করে (format confusion), তবে সেই application-স্তর আলাদা
  target হিসেবে মডেল করতে হয় (§7.3-এর FMT-CONFUSED/FMT-SAFE)।
