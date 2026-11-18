# PREREG-L — নতুন ecosystem-এ out-of-sample replication (২৫ সেপ্ট ২০২৬)

> নতুন adapter-গুলো **কোনো corpus-এ চালানোর আগে** এই ফাইল commit করা। পরিবর্তন হলে Deviations-এ লিখতে হবে।

## 1. প্রশ্ন
scale30-এর সিদ্ধান্তগুলো ৩২টা implementation-এর উপর দাঁড়িয়ে। সেগুলো কি **আগে দেখা হয়নি এমন implementation**-এ
টেকে, যাদের ভাষা, runtime আর crypto stack আলাদা? এটা সংখ্যা বাড়ানো নয়, একটা held-out replication। নতুন impl-গুলো
আলাদা set হিসেবে মূল্যায়িত হবে, আর মূল ৩২টার সংখ্যা বদলাবে না।

## 2. নতুন implementation (নির্বাচন-নিয়ম scale30 PREREG §2-এর মতোই; wrapper বাদ)
- C: **libjwt**, **cjose** (source থেকে build, system OpenSSL + jansson)
- Erlang/BEAM: **erlang-jose** (potatosalad), Elixir থেকে ডাকা। Joken এর wrapper, তাই আলাদা গণ্য নয়।
- Swift: **JWTKit** (Vapor), **Swift-JWT** (Kitura)
- Dart: **dart_jsonwebtoken**, **jose** (Dart)
কোনো library build বা install না হলে সেটা বাদ, আর কারণ লেখা হবে। কোনো reserve নেই।
adapter contract, gate (G1–G4) আর keyload>৫% নিয়ম scale30 PREREG §3-এর মতোই।

## 3. Hypothesis (মূল corpus `scale30/corpus`-এ, নতুন impl-set আলাদাভাবে)
- **L1:** নতুন কোনো impl মূল corpus-এর ২০৪৫টা জাল টোকেনের একটাও গ্রহণ করে না।
  ≥১ হলে L1 ভুল প্রমাণিত। তখন টোকেনটা `sealed/`-এ যাবে, হাতে যাচাই হবে, আর disclosure-এর প্রশ্ন আসবে।
- **L2 (H3 replication):** শুধু নতুন impl-set নিয়ে B2 profile (V1 seed-1) বানালে held-out বৈধ টোকেনে (V1 seed ২–৩, V2, V3)
  B2-এর FP ≥ ৫%, আর bootstrap 95% CI-র নিম্নসীমা > ০।
- **L3 (sanity):** নতুন impl-set-এ PROV_claim-এর বৈধ-টোকেন FP = ০।
- **বর্ণনামূলক:** নতুন set-এ B0/B1 FP; ৩২ + নতুন মিলিয়ে B0/B1/B2; আর নতুন কোনো rejection-কারণ যা ৩২টায় ছিল না।
  (নতুন set ছোট, তাই D1 curve বা H2 আবার মাপা হবে না।)

## Deviations
(এখনো নেই)
