# Cross-language algorithm-confusion survey (Scale-up) — ২২ সেপ্টেম্বর ২০২৬

লক্ষ্য (paper-এর "scale" লিভার): ৫ ভাষা × ১১টি current library জুড়ে algorithm
confusion (RS256→HS256) — কে safe-by-API, কে শুধু safe-if-used-correctly, কে
পুরনো version-এ পূর্ণ দুর্বল। এবং fix/defense-pattern ভাষা-নিরপেক্ষ কিনা।
code: `multilang/` (`setup_multilang.sh`, `run_multilang.sh`) + `crosslang/`।

DY-সীমা সর্বত্র এক: attacker শুধু issuer-এর RSA **public** key জানে, সেটাকে HMAC
secret বানিয়ে HS256-এ role=admin সাইন করে।

## ফলাফল (current version, safe/normal usage)

| ভাষা | library (version) | confusion (normal use) | মন্তব্য |
|---|---|---|---|
| Python | PyJWT 2.14.0 | ❌ REJECT | asymmetric key HMAC-এ অস্বীকার |
| Python | python-jose 3.5.0 | ❌ REJECT | " |
| Python | Authlib 1.8.0 | ❌ REJECT | " |
| Python | jwcrypto 1.6.1 | ❌ REJECT | typed JWK |
| Python | joserfc 1.7.5 | ❌ REJECT | InvalidKeyTypeError |
| Python | python-jwt 4.1.0 | ❌ REJECT | jwcrypto-ভিত্তিক |
| Node | panva/jose 5.10.0 | ❌ REJECT | strict, typed key |
| Node | jsonwebtoken 9.0.2 | ❌ REJECT | "must be a symmetric key" |
| PHP | firebase/php-jwt 6.10.0 | ❌ REJECT¹ | alg per-Key pinned |
| Go | golang-jwt/v5 5.2.1 | ⚠️ **ACCEPT under misuse** | keyFunc→PEM bytes হলে full forgery |
| Java | nimbus-jose-jwt 9.40 | ⚠️ **ACCEPT under misuse** | MACVerifier(pubBytes) হলে full forgery |

¹ php-jwt: RS256-config-এ REJECT; শুধু চরম misconfig `Key(pub,'HS256')`-এ ACCEPT
(app স্পষ্টভাবে pubkey-কে HMAC key ঘোষণা করলে) — কার্যত safe-by-design।

## historical (version before/after — `crosslang/`)

| library | vulnerable | fixed |
|---|---|---|
| jsonwebtoken (Node) | 8.5.1 → full forgery | 9.0.2 → REJECT |
| Hono JWKS (Node) CVE-2026-22817 | 4.11.3 → attacker alg-selection | 4.11.4 → guard |
| PyJWT / Authlib / python-jose (Python) | পুরনো → forgery (Phase B1) | current → REJECT |

## সৎ synthesis (দাবি ও অ-দাবি)

- **ভাষা-নিরপেক্ষ defense pattern (paper §7.2 দাবি সমর্থিত):** ৫ ভাষার high-level,
  algorithm-pinning API সবই একই ভাবে confusion আটকায় — asymmetric key-কে symmetric
  algorithm-এ ব্যবহার করতে অস্বীকার করে। provenance-signal তাই ভাষা-স্বাধীন।
- **যেখানে exposure এখনো জীবন্ত (২০২৬):** low-level/typed-key API যেগুলো caller-কে
  key ও method নিজে মেলাতে দেয় — **golang-jwt (Go)** ও **nimbus (Java)** — সেখানে
  একটা বাস্তব, নথিভুক্ত misuse প্যাটার্নে (key bytes verifier-কে দেওয়া) **current
  version-এও পূর্ণ forgery** সম্ভব। এটা caller-দায়, কিন্তু আমাদের সমীক্ষা দেখায়
  exposure এখন এই দুই ঘরানায় কেন্দ্রীভূত, high-level API-তে নয় — একটা systematization insight।
- **নতুন 0-day পাইনি (সৎ negative):** কোনো mainstream current library safe/normal
  usage-এ forgery গ্রহণ করেনি। তাই এই সমীক্ষা নতুন CVE দাবি করে না; বরং (ক) fix-pattern-এর
  ভাষা-নিরপেক্ষতা ও (খ) অবশিষ্ট exposure-এর অবস্থান নথিভুক্ত করে।
- **Coverage:** ৫ ভাষা (Python, Node, Go, Java, PHP), ১১ current library + ৩ historical।

## সীমা
- confusion (+ alg:none) কেন্দ্রিক; প্রতিটি ভাষায় পূর্ণ ৫-class provenance-oracle harness
  বানানো হয়নি (Python-এ আছে)। এটা targeted cross-language survey, পূর্ণ multi-language fuzzer নয়।
- Go/Java-র "misuse" বাস্তব ও নথিভুক্ত, তবু caller-নির্ভর — library-র default-safe API আলাদা।
