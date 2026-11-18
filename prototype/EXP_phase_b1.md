# Phase B1 — real library version-এ external validity

detector (ground-truth oracle) documented-দুর্বল পুরনো library version-এ real
vulnerability reproduce করে, আধুনিক fixed version-এ চুপ থাকে। Python 3.12 (আধুনিক)
ও 3.9 (খুব পুরনো library-র জন্য) venv-এ pinned version।

## ১. Algorithm confusion (RS256→HS256) — claim-mismatch oracle

attacker শুধু issuer-এর PUBLIC key জানে; সেটাকে HMAC secret বানিয়ে HS256-এ
role=admin সাইন করে। verifier RSA public key ধরে, ভুলে HS256-ও গ্রহণযোগ্য।

| Library version | forged admin গৃহীত? | detector | প্রত্যাশা |
|---|---|---|---|
| PyJWT 0.2.3 | 🚨 হ্যাঁ (TP) | শ্রেণী-A ধরল | দুর্বল ✅ |
| PyJWT 0.4.3 | 🚨 হ্যাঁ (TP) | শ্রেণী-A ধরল | দুর্বল ✅ |
| PyJWT 1.4.2 | না (REJECT) | চুপ | fixed ✅ |
| PyJWT 1.5.0 | না (REJECT) | চুপ | fixed ✅ |
| PyJWT 1.7.1 | না (REJECT) | চুপ | fixed ✅ |
| PyJWT 2.14.0 (cur) | না (REJECT) | চুপ | fixed ✅ |
| Authlib 0.15.5 | 🚨 হ্যাঁ (TP) | শ্রেণী-A ধরল | দুর্বল ✅ |
| python-jose 2.0.2 | না (REJECT) | চুপ | fixed ✅ |
| python-jose 3.3.0 | না (REJECT) | চুপ | fixed ✅ |

## ২. JWE decompression bomb (CVE-2024-33664) — resource oracle

ছোট JWE টোকেন (zip=DEF) decrypt-এ বিশাল প্রসারণ → DoS। claim ঠিক থাকলেও
সম্পদ শেষ হয়; resource oracle ধরে।

| Library version | ছোট→বড় প্রসারণ? | detector | প্রত্যাশা |
|---|---|---|---|
| python-jose 3.3.0 | 🚨 হ্যাঁ (bomb) | শ্রেণী-A ধরল | দুর্বল ✅ |
| python-jose 3.5.0 (cur) | না (সীমিত) | চুপ | fixed ✅ |

## সৎ interpretation

- controlled VULN-target-এর বাইরে **৩টা distinct real true-positive** — ২টা
  library (PyJWT 0.x, Authlib 0.15.5) algorithm confusion, ১টা (python-jose 3.3.0)
  JWE bomb — এবং প্রতিটার আধুনিক fixed counterpart চুপ থাকে (মিথ্যা alarm নেই)।
- দুই oracle-path-ই বাস্তব bug-এ কাজ করে: claim-mismatch (confusion) ও resource (bomb)।
- এগুলো *পরিচিত ঐতিহাসিক দুর্বলতা* (নতুন 0-day নয়) — উদ্দেশ্য detector-এর external
  validity, নতুন CVE দাবি নয়। CVE-2024-33664 (jose JWE bomb) documented; PyJWT/Authlib
  algorithm-confusion = Tim McLean 2015-এর শ্রেণী (নির্দিষ্ট CVE নম্বর UNVERIFIED)।
- confusion আক্রমণে caller-ও দায়ী (allow-list না দেওয়া) — কিন্তু আধুনিক version
  একই call-এ asymmetric key HMAC-এ ঢুকতে না দিয়ে defense-in-depth যোগ করেছে;
  পুরনো version করেনি। detector সেই পার্থক্যই ধরে।
