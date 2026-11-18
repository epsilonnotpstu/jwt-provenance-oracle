# E3 (v2) — Naive differential বনাম Ground-truth oracle (non-circular)

Corpus: 28 টোকেন (24 বৈধ, 4 জাল)। baseline=0.107ms। ৪ Python library (+ ফল ২-এ VULN/SAFE target)।

## ফল ১ — বৈধ input-এ false positive (মূল দাবি)

24টা বৈধ (honestly-issued) টোকেন; একটা সঠিক detector কোনোটাই flag করবে না।

| Detector | False positive | FP-rate |
|---|---|---|
| NAIVE (library-অমিল = bug) | 9/24 | 37.5% |
| GT-ORACLE (provenance-চালিত) | 0/24 | 0.0% |

NAIVE-এর false positive (সব বৈধ টোকেনে library-আচরণের empirical পার্থক্য):

- `valid/HS256/short`
- `valid/HS384/short`
- `valid/HS512/short`
- `valid/PS256/2048`
- `valid/PS256/1024`
- `valid/PS384/2048`
- `valid/PS384/1024`
- `valid/PS512/2048`
- `valid/EdDSA`

## ফল ২ — true positive-এর জন্য known-vulnerable target লাগে

আধুনিক ৪ library আমাদের 4টা জাল টোকেনের ভুল-গ্রহণ করেছে: **0টা** — অর্থাৎ এই library-তে আমাদের mutation-সেটে সত্যিকারের bug নেই (hardened; recurring truth)। তাই detection-শক্তি মাপতে controlled VULN-target দরকার।

| Detector | VULN-target-এর 2 জাল-গ্রহণ ধরল | Recall |
|---|---|---|
| NAIVE | 2/2 | 100% |
| GT-ORACLE | 2/2 | 100% |

## সৎ interpretation

- **মূল ফলাফল (ফল ১):** ground-truth oracle বৈধ input-এ naive differential-এর 9টা capability-driven false positive সম্পূর্ণ সরায় (38% → 0%), true-positive না হারিয়ে (ফল ২)।
- circularity ভাঙা: FP কেসগুলো probe থেকে empirically পাওয়া, oracle বসায়নি; oracle শুধু general নিয়ম ("টোকেন বৈধভাবে issued?") ব্যবহার করে, নির্দিষ্ট alg/error-string নয়।
- এটা এই ৪ library + এই mutation-সেটের internal mechanism-comparison। JWTeemo-র ৩৫.১%-এর সাথে **সরাসরি সংখ্যাগত তুলনা নয়** (ভিন্ন corpus, ভাষা-পরিসর, baseline)।
