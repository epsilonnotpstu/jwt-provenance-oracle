# পরীক্ষা লগ — Blind vs DY-guided false-positive

## v2 (২২ সেপ্টেম্বর ২০২৬) — non-circular পুনর্নকশা  ← বর্তমান

code: `corpus_experiment.py` → output `EXP_corpus_v2.md`, `corpus_v2_rows.csv`
Library version pinned: `requirements.txt` (pyjwt 2.14.0, python-jose 3.5.0,
authlib 1.8.0, jwcrypto 1.6.1, cryptography 50.0.1), Python 3.12।

### v1-এর তিনটা ফুটো কীভাবে বন্ধ হলো
1. **Circularity** — আগে corpus-এর FP-ফাঁদ ও oracle-এর C-নিয়ম একই হাতে বানানো ছিল।
   এখন: (ক) capability-difference কেসগুলো `probe_algsupport.py`-তে **empirically**
   পাওয়া (২৪টা alg×key-variant চালিয়ে যেখানে library বাস্তবে অমিল করে); আমরা বসাইনি।
   (খ) oracle (v3) আর error-string keyword দেখে না — শুধু general provenance নিয়ম
   ("টোকেন কি issuer বৈধভাবে সাইন করেছিল?") ব্যবহার করে, যা নির্দিষ্ট কেস চেনে না।
2. **হাতে-বাছা ২টা diff** → এখন সব JWS পরিবার (HS/RS/PS/ES/EdDSA) × key-variant।
3. **Degenerate সংখ্যা** → এখন FP আর TP আলাদা মাপা, TP-এর জন্য known-vulnerable
   target ব্যবহার (আধুনিক library hardened বলে তাদের মধ্যে bug নেই)।

### ফলাফল
**ফল ১ — বৈধ input-এ false positive (২৪টা honestly-issued টোকেন):**

| Detector | FP | FP-rate |
|---|---|---|
| NAIVE (library-অমিল = bug) | 9/24 | 37.5% |
| GT-ORACLE (provenance-চালিত) | 0/24 | 0.0% |

NAIVE-এর ৯টা FP: jwcrypto short-HMAC ×3 (HS256/384/512), python-jose PS* ×5
(PS256/384/512), python-jose EdDSA ×1 — সবই বৈধ টোকেন প্রত্যাখ্যান = capability/
strictness difference, নিরাপত্তা নয়।

**ফল ২ — true positive (forged, ৪ library + VULN/SAFE target):**
- আধুনিক ৪ library: forged-সেটে **০টা** ভুল-গ্রহণ (hardened)।
- controlled VULN-target জাল টোকেন গ্রহণ করে ২টা (alg:none, algorithm-confusion);
  দুই detector-ই ২/২ ধরে → FP কমানোর জন্য detection হারায়নি।

### সৎ দাবি (এবং যা এখনো দাবি করা যাবে না)
- ✅ **দাবি:** একই টোকেন-স্রোতে ground-truth oracle naive differential-এর
  capability-driven false positive সম্পূর্ণ (৩৭.৫%→০%) সরায়, true-positive না হারিয়ে।
  circularity নেই (FP কেস empirical, oracle general)।
- ⚠️ **যা নয়:** "JWTeemo-র ৩৫.১% beat করলাম" — ভিন্ন corpus/ভাষা-পরিসর/baseline।
  ৩৭.৫% সংখ্যাটা এই ৪-library corpus-এর artifact (jwcrypto+python-jose-এর strictness),
  general FP-rate নয়। controlled VULN-target-এর TP = detector sanity-check,
  "real vulnerability discovery" নয়।
- এখনো external validity দুর্বল: সত্যিকারের পুরনো-দুর্বল library version-এ TP দরকার (Phase B1)।

---

## v1 (১৮ সেপ্টেম্বর ২০২৬) — circular, বাতিল
পুরনো run: BLIND 66.7% FP / DY-GUIDED 0.0%। সংখ্যা design-এর ফল ছিল (corpus-ফাঁদ ও
oracle একই হাতে বানানো), পৃথিবী সম্পর্কে কিছু বলত না। v2 এটাকে প্রতিস্থাপন করেছে।
পূর্ণ কারণ উপরে "v1-এর তিনটা ফুটো"।
