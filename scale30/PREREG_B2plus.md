# PREREG-B2+ — header/claim-সচেতন capability profile কি held-out variant-এ টেকে? (২৫ সেপ্ট ২০২৬)

> এই ফাইল **B2+-এর কোনো মূল্যায়ন-ডাটা (corpus_b) তৈরি বা মাপার আগে** commit করা। পরিবর্তন হলে Deviations-এ লিখতে হবে।
> পটভূমি: EXP_scale30.md §৩ H3। সেখানে B2 (শুধু alg, key-size) held-out-এ ৩০.৬% FP দিয়েছিল, আর সীমা হিসেবে লেখা ছিল:
> "পরীক্ষা হয়েছে মাত্র একটা profile ডিজাইনের"। reviewer-এর প্রত্যাশিত আপত্তি: "header/claim-সচেতন profile বানালেই হতো"।
> এই পরীক্ষা সেই শক্ত প্রতিপক্ষকে মাপে।

## 1. B2+ — সংজ্ঞা (DDYF-ধরনের knowledge blacklist-এর সবচেয়ে সরল সৎ রূপ)
প্রতিটা টোকেনের **category** শুধু টোকেন আর key থেকে গণনা হয়, truth থেকে নয়। default মানগুলো বন্ধনীতে:
- C1 (alg, key-variant) — V1-এর মতো; default নেই (সবসময় non-default গণ্য)
- C2 typ: absent / "JWT" (default) / অন্য
- C3 kid আছে (default: নেই)
- C4 অ-নিবন্ধিত header param আছে (নিবন্ধিত = alg, typ, cty, kid, jku, jwk, x5u, x5c, x5t, x5t#S256, crit)
- C5 cty আছে
- C6 নিবন্ধিত-কিন্তু-বিরল header আছে (jwk, jku, x5u, x5c, x5t, x5t#S256)
- C7 aud আছে
- C8 payload-এ non-ASCII
- C9 payload-এ integer > 2^53
- C10 nbf আছে
- C11 exp integer নয়
- C12 payload > 4 KB
- C13 payload-এ nested object claim আছে
- C14 payload-এ jti আছে

**Profile P_i:** training-এর প্রতিটা বৈধ টোকেন t, যেটা impl i verify-stage-এ reject করেছে → P_i-তে যোগ হয় t-এর সব
non-default category (V1 টোকেনে শুধু C1; V2/V3 টোকেনে তার variant-এর category, যেমন V2/kid → C3)।
**Detector B2+(t):** i বাদ যাবে যদি t-এর non-default category-র কোনোটা P_i-তে থাকে (C1 সবসময় non-default গণ্য)।
বাকি impl-এ B0 চালানো হবে। keyload বাদ, primary ৩২টা impl, adapter অপরিবর্তিত।

**Training:** `scale30/corpus` (মূল), V1+V2+V3 **seed-1**, আর scale30-এর মাপা ফল (results/main)।

## 2. Test corpus (`corpus_b/`, নতুন key ও seed; এই PREREG-এর পরে তৈরি)
সব বৈধ টোকেন, base = RS256-2048 আর HS256-min, ৩টা seed:
- **T-same** (training-এ দেখা category-র নতুন instance): kid = "k-2026-rotation"; private header `x-region: "eu"`;
  typ = "JOSE"; aud = "https://api.example.org"; unicode = "Grüße 日本語"; bigint = 2^62।
- **T-new** (training-এ কখনো দেখা যায়নি এমন category): nbf = iat (অতীতে); exp = 4102444800.5; payload ~৬ KB
  (একটা লম্বা `note` claim); self-embedded `jwk` header (শুধু RS256 base: issuer-এর নিজের public key); nested object
  claim `ctx: {"tenant": "acme", "tier": 2}`; jti = "5f0c…" (fixed)।

## 3. Hypothesis ও metric
- **P1:** T-same-এ B2+-এর FP < ৫%। (পূর্বাভাস: সমর্থিত। ব্যর্থ হলে সেটাও রিপোর্ট হবে।)
- **P2:** T-new-এ B2+-এর FP ≥ ৫%, আর bootstrap 95% CI-র নিম্নসীমা > ০। ব্যর্থ হলে (< ৫%) H3-এর যুক্তি দুর্বল হবে,
  কারণ তখন শুধু সরল profile-ই ব্যর্থ হয়। সেটা EXP-এ স্পষ্ট লেখা হবে।
- **P3 (বর্ণনামূলক):** blacklist-এর দাম, মানে জাল টোকেনে (scale30 মূল corpus-এর F1+F2) কত শতাংশ (impl, টোকেন) জোড়া
  exclusion-এর কারণে তুলনা থেকে "চুপ" হয়ে যায়। B2 বনাম B2+ তুলনা। একটা চুপ জোড়ায় ভবিষ্যতের কোনো সত্যিকারের
  ভুল-গ্রহণ ধরা পড়বে না।
- **Sanity:** T-same/T-new-এ PROV_claim-এর FP = ০ (soundness থেকে আশা করা)।
- CI: টোকেন ধরে bootstrap (১০,০০০)।

## 4. যা দাবি করা যাবে না
- P2 সমর্থিত হলেও "কোনো profile কখনো কাজ করে না" দাবি করা যাবে না। দাবি সীমিত: category আগে থেকে না জানলে
  blacklist ভাঙে, আর যত বেশি category যোগ হয়, তত বেশি তুলনা চুপ হয় (P3)।

## Deviations
(এখনো নেই)
