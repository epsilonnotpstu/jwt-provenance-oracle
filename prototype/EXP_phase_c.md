# Phase C — Grammar coverage (২২ সেপ্টেম্বর ২০২৬)

লক্ষ্য: operator-বর্ণমালা কি JWTeemo-র ৫টা attack-class-ই প্রকাশ করতে পারে?
(WORKSHEET-এর completeness পরীক্ষা: "বর্ণমালা দিয়ে পরিচিত শব্দ লেখা যায় কি?")
code: `grammar_coverage.py`; নতুন operator: `operators.py` (Phase C অংশ);
নতুন target: `controlled_targets.py` (`verify_FORMAT_CONFUSED`, `verify_FORMAT_SAFE`)।

## নতুন operator
- `fn_json_flat(h, p, sig)` — RFC 7515 Flattened JSON serialization।
- `fn_json_with_extra(h, p, sig, field, value)` — **Format Confusion**: signature আসল
  payload-এর উপর অক্ষত, জাল claim একটা unsigned বাড়তি field-এ।
- `fn_pbes2_header(p2c, ...)` — **Billion Hashes**-এর কাঁচামাল (বিশাল iteration count)।

## ফল

| attack class | operator জোড়া | grammar-এ প্রকাশযোগ্য? | detector coverage |
|---|---|---|---|
| Algorithm confusion | `fn_hmac_sign(si, fn_pubkey_pem(...))` | ✅ | শ্রেণী-A ✅ (VULN-target) |
| alg:none (sig exclusion) | `fn_compact(fn_header('none'), p, b'')` | ✅ | শ্রেণী-A ✅ (VULN-target) |
| JWT Format confusion | `fn_json_with_extra(h, p, sig, 'fakeiss', {...})` | ✅ | শ্রেণী-A ✅ (FMT-CONFUSED), FMT-SAFE=OK |
| Billion Hashes (PBES2) | `fn_pbes2_header(p2c=10_000_000)` | ✅ (construction) | modern jwcrypto p2c cap → defended |
| Sign/Encrypt confusion | pubkey → JWE, verifier=JWS | ✅ (construction) | JWE path Phase B1-এ |

**সব ৫টা class grammar-এ প্রকাশযোগ্য।** detector-testable ৩টায় (alg:none, alg-confusion,
format confusion) ground-truth oracle সঠিক শ্রেণী দেয়।

## Format confusion — কেন এটা আমাদের thesis-এর সাথে বিশেষভাবে মানানসই
Format confusion **প্রকৃতিগতভাবে একটা provenance mismatch**: signature যে payload-এর উপর
(role=user), সিদ্ধান্ত সেখান থেকে নয় (unsigned `fakeiss`.role=admin)। আমাদের
provenance oracle ঠিক এই "কে সাইন করেছিল vs verifier কী believe করল" পার্থক্যই মাপে —
তাই FMT-CONFUSED (unsigned admin বিশ্বাস) = শ্রেণী-A, আর FMT-SAFE (শুধু signed user পড়ে)
= OK, যদিও দুটোই একই crafted টোকেন গ্রহণ করেছে। naive differential এই দুটোকে আলাদা
করতে পারত না (দুটোই ACCEPT); provenance পারে।

এই পর্যায়ে oracle-ও একটু নিখুঁত হলো: "crafted টোকেন গৃহীত হলেই A" নয় — verifier যদি
শুধু issuer-এর বৈধ-সাইন-করা মান (legit_role) বিশ্বাস করে তবে OK; escalated/unsigned মান
বিশ্বাস করলে তবেই A।

## সৎ সীমা
- Billion Hashes ও Sign/Encrypt confusion এখানে **construction coverage** — অর্থাৎ operator
  দিয়ে টোকেন বানানো যায়; live true-positive demo আধুনিক library-তে হয় না (jwcrypto p2c
  cap করে; JWE decompression Phase B1-এ python-jose 3.3.0-তে দেখানো হয়েছে)।
- Format confusion দুই-স্তরের (crypto-lib + app) বাগ; ৪টা real Python library compact-only
  বলে এটা controlled target-এ দেখানো — real-world-এ এটা app-integration স্তরের সমস্যা
  (JWTeemo Kubernetes case)।
- এগুলো grammar-completeness ও detector-coverage — real-library 0-day নয়।

---

## Phase C-2 — Random mutation-chain fuzzing campaign (২২ সেপ্টে)

code: `random_fuzz.py` (seeded, reproducible)। কেন: এতদিন mutation হাতে-বাছা ছিল —
"এটা সত্যিকারের fuzzer, নাকি hand-crafted test?" — এই আপত্তির জবাব। fuzzer এখন N বার
এলোমেলোভাবে operator জোড়া দিয়ে টোকেন বানায় (DY-সীমার ভেতরে: attacker শুধু নিজের
secret + issuer-এর public key), ৪ real library + controlled target-এ চালায়, provenance
oracle দিয়ে শ্রেণী দেয়। random header extra (kid/crit)-ও ছোঁয়।

### ফল (একাধিক seed, স্থিতিশীল)
| seed | N | hardened lib-এ FP | real-lib genuine bug | VULN-target TP |
|---|---|---|---|---|
| 1337 | 2000 | **0** | 0 | 590 |
| 7 | 1500 | **0** | 0 | 486 |
| 42 | 1500 | **0** | 0 | 459 |
| 2026 | 1500 | **0** | 0 | 476 |

coverage: ৫টা attack-class (alg_none, confusion, wrong_key, wrong_rsa, format_confusion)
+ ৬টা honest family (HS256/384/512, RS256, ES256, EdDSA) — সব random chain-এ ছোঁয়া।

### সৎ interpretation
- **মূল দাবি:** হাজার হাজার এলোমেলো iteration জুড়ে provenance oracle-এর false positive **০** —
  অর্থাৎ 0% FP শুধু হাতে-বাছা corpus-এর ফল নয়, random campaign-এও টেকে।
- আধুনিক ৪ library random forgery-তে **০ genuine bug** (hardened; consistent) — তাই detection-
  শক্তি controlled VULN-target-এ মাপা (প্রতি run-এ শত শত TP)।
- **সীমা:** uniform random, coverage-guided নয় (puffin-এর মতো নয়); বড় guided campaign ভবিষ্যৎ কাজ।
