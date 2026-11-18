# Phase B-ext — Cross-language external validity (Node.js) — ২২ সেপ্টেম্বর ২০২৬

লক্ষ্য: provenance/algorithm-confusion detector শুধু Python-এ নয়, অন্য ভাষার
library-তেও real bug ধরে — এবং ২০২৬-এর জীবন্ত CVE-এর মূল সূত্র reproduce করে।
code: `_oldlibs/node/` (`confusion_jsonwebtoken.js`, `cve_2026_22817_hono.js`);
setup: `setup_crosslang.sh`; runner: `run_crosslang.sh`। Node v22, npm 12।

## ১. `jsonwebtoken` (Node) — algorithm confusion (RS256→HS256)

DY-সীমা: attacker শুধু issuer-এর RSA public key জানে; সেটাকে HMAC secret বানিয়ে
HS256-এ role=admin সাইন করে। verifier public key ধরে।

| version | no-algorithms | RS256+HS256 allowed | RS256-only | ফল |
|---|---|---|---|---|
| **8.5.1** (পুরনো) | REJECT (invalid algorithm) | **🚨 ACCEPT role=admin** | REJECT | **real TP** |
| **9.0.2** (fixed) | REJECT | REJECT ("must be a symmetric key when using HS256") | REJECT | নিরাপদ |

→ পূর্ণ end-to-end forgery: jsonwebtoken 8.5.1 misconfigured verifier-এ (RS256+HS256
allow) forged admin token গৃহীত। 9.0.2 asymmetric key-কে HMAC-এ ঢুকতে না দিয়ে
defense-in-depth যোগ করেছে — ঠিক Python-এর PyJWT 2.x / Authlib 1.x-এর মতো।
**Cross-language পুষ্টি:** capability/defense-difference ও provenance-signal ভাষা-নিরপেক্ষ।

## ২. Hono (Node) — CVE-2026-22817 (verifyWithJwks alg fallback)

Root cause (source-এ যাচাইকৃত): Hono 4.11.3 `verifyWithJwks` —
`alg: matchingKey.alg || header.alg` — JWK-তে `alg` না থাকলে **unverified header-এর
alg**-এ fallback করে (attacker-controlled)। fix: 4.11.4।

Setup: JWKS-এ RSA public JWK (kid=k1, `alg` field বাদ; intended RS256)। attacker
HS256 header বসিয়ে বিভিন্ন public-derived material দিয়ে HMAC করে।

| version | attacker-এর HS256 নির্বাচন গৃহীত? | Hono guard | ফল |
|---|---|---|---|
| **4.11.3** (vulnerable) | **হ্যাঁ** — HMAC verification-এ এগোয় (Web Crypto তখন RSA-JWK→HMAC import আটকায়) | নেই | **CVE আচরণ নিশ্চিত** |
| **4.11.4** (fixed) | না — `JwtSymmetricAlgorithmNotAllowed` আগেই থামায় | আছে | নিরাপদ |

### সৎ সীমা (overclaim নয়)
- **পূর্ণ forgery হয়নি:** RSA public JWK-কে HMAC key হিসেবে import করতে Web Crypto
  অস্বীকার করে ("Invalid JWK kty") — তাই এই configuration-এ token forge সম্পূর্ণ হয় না।
  এটা advisory-র "in certain configurations, allow forged tokens" caveat-এর সাথে সঙ্গতিপূর্ণ।
- **যা reproduce হয়েছে:** vulnerable algorithm-**selection** — 4.11.3 attacker-এর header-alg
  বিশ্বাস করে symmetric verification-পথে যায় (guard নেই), 4.11.4 categorically থামায়।
  এই আচরণগত পার্থক্যই CVE-র মূল ও তার fix, এবং এটাই আমাদের detector-এর signal
  ("verifier issuer-এর নির্ধারিত নয় এমন algorithm-এ verify করছে")।
- pure RSA→HMAC forgery-র জন্য এমন JWK-config লাগে যা attacker-এর alg-এ import-যোগ্য;
  RSA JWKS-এ Web Crypto সেটা আটকায়। ভিন্ন key-type-এ পূর্ণ exploit ভবিষ্যৎ কাজ।

## সারসংক্ষেপ
- ভিন্ন ভাষায় (Node) **১টা পূর্ণ real TP** (jsonwebtoken 8.5.1) + **১টা ২০২৬-CVE root-cause
  reproduce** (Hono 4.11.3→4.11.4)। Python Phase B1-এর সাথে মিলে external validity
  এখন cross-language।
- সব ক্ষেত্রে fixed version-এর defense = asymmetric key-কে symmetric algorithm-এ ব্যবহারে
  অস্বীকার — একই প্যাটার্ন Python (PyJWT/Authlib) ও Node (jsonwebtoken/Hono) উভয়ে।
