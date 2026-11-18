# PREREG-R — resource oracle v2-এর pre-registration (২৫ সেপ্ট ২০২৬)

> এই ফাইল **resource-v2-এর কোনো timing মাপার আগে** commit করা। পরিবর্তন হলে নিচের Deviations-এ লিখতে হবে।
> পটভূমি: `EXP_scale30.md` §৬.১। সেখানে pre-registered PROV-এর ৪০.৩% FP-এর সবটাই এসেছে resource oracle v1 থেকে।

## 1. কেন নতুন নকশা, আর overfitting-এর ঝুঁকি
v1 (oracle.py `judge_truth`, scale30 PREREG §3) দুইভাবে ভেঙেছিল:
(ক) **alg-নিরপেক্ষ baseline:** ES384/ES512-এর স্বাভাবিক verify HS256-এর ১৮–২৬× বেশি সময় নেয়;
(খ) **single-shot timing:** Node/JIT/GC jitter-এ rejected টোকেনও "SLOW" হয়।
v2-এর নকশা ঠিক এই পর্যবেক্ষণ থেকে এসেছে, মানে post-hoc অনুপ্রেরণা। একই ডাটায় আবার মাপলে overfitting হবে।
**তাই v2 মূল্যায়ন হবে নতুন corpus-এ** (`corpus_r/`: নতুন key আর নতুন seed, একই generator)। v2-এর
সব parameter নিচে স্থির করা, নতুন corpus-এ মাপার আগেই।

## 2. Resource oracle v2 — সংজ্ঞা
প্রতি impl i আর টোকেন t-এর জন্য:
- **Baseline B(i, a, v):** `corpus_r` V1 **seed-1**-এর বৈধ টোকেন, (alg a, key-variant v) অনুযায়ী। প্রতিটা টোকেন
  **R_b = 15** বার verify করে তার median। keyload-এ ব্যর্থ হলে সেই (a, v) baseline-এ থাকবে না।
- **Fallback:** টোকেনের (meta.alg, meta.variant)-এর baseline না থাকলে (যেমন `alg:none`-এর রূপভেদ, JSON টোকেন,
  unsupported alg) → B_max(i) = i-এর সব baseline-এর সর্বোচ্চ। এটা রক্ষণশীল পছন্দ।
- **Screening:** মূল রানের single-shot সময় ns(i, t) > **T · B**, যেখানে **T = 20** (v1-এর মতোই)। এমন (i, t) candidate।
- **Confirmation:** প্রতিটা candidate (i, t) **R_c = 15** বার আবার মাপা। **SLOW** ⇔ median > T · B **এবং**
  median − B > **F = 1 ms**। F-এর কারণ: µs-স্কেলের পার্থক্য DoS হিসেবে অর্থহীন, আর jitter-এর স্কেলের মধ্যেই পড়ে।
- **RES_v2(t)** = কোনো primary impl-এ SLOW। **PROV_v2(t)** = claim oracle-এ A (অপরিবর্তিত) **অথবা** RES_v2(t)।
- impl-সেট = scale30 PREREG-এর primary ৩২টা (একই নির্বাচন-নিয়ম, একই adapter; কোনো adapter বদলানো হবে না)।

## 3. Positive control (resource oracle যেন সংজ্ঞাগতভাবে অন্ধ না হয়)
threshold যথেষ্ট বড় হলে যেকোনো detector ০% FP পাবে। তাই oracle আসল slowdown ধরে কি না, সেটাও মাপতে হবে।
- **Control target** (`control/cost-hs256`, শুধু এই পরীক্ষার জন্য বানানো Python function): HS256 যাচাই করে, কিন্তু আগে
  header-এর `x-cost` মানের সমান সংখ্যক SHA-256 iteration চালায়। কোনো cap নেই। এটা একটা controlled "উপাদান-অপচয়কারী"
  verifier, বাস্তব library নয় (Phase A-র VULN-target-এর মতো)।
- **Control corpus:** issuer-এর HS256 key দিয়ে সাইন করা, `x-cost` ∈ {absent, 10³, 10⁴, 10⁵, 10⁶}, প্রতিটা ৫টা টোকেন।
- control target-এর baseline = একই নিয়মে V1 HS256 টোকেন থেকে (x-cost ছাড়া)।

## 4. Hypothesis
- **R1:** `corpus_r`-এর বৈধ টোকেনে PROV_v2-এর FP = ০, সব primary impl-জুড়ে। ≥১ হলে R1 ভুল প্রমাণিত; কোন impl আর কোন টোকেন, সেটা রিপোর্ট হবে।
- **R2:** `corpus_r`-এর জাল টোকেনে RES_v2-এর flag = ০। কোনো current library slow নয় বলে আশা। ≥১ হলে হাতে তদন্ত করা হবে,
  সত্যিকারের slowdown হলে সেটা আলাদা lead, noise হলে R2 ভুল প্রমাণিত।
- **R3 (positive control):** x-cost ≥ 10⁴ → ২০/২০ টোকেন SLOW; x-cost absent → ০/৫। 10³-এর জন্য কোনো পূর্বাভাস নেই (শুধু রিপোর্ট)।
  x-cost ≥ 10⁴-এ কোনোটা মিস হলে R3 ভুল প্রমাণিত।
- **তুলনা (বর্ণনামূলক):** একই `corpus_r` রানে v1 (single-shot, HS256-min baseline, ২০×) কত FP দেয়।

## 5. যা দাবি করা যাবে না
- R1/R2 সত্য হলেও দাবি হবে শুধু "এই ৩২টা current library আর এই corpus-এ v2 কোনো মিথ্যা alarm দেয় না, আর controlled
  slowdown ধরে"। বাস্তব DoS bug-এ recall-এর দাবি করা যাবে না। control target বাস্তব library নয়।

## Deviations
(এখনো নেই)
