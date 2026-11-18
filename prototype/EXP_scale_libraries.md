# Scale-up library survey (~17 independent implementations, 5 languages) — ২৩ সেপ্টে ২০২৬

JWTeemo-স্টাইল scale bug-hunt: algorithm confusion (RS256→HS256, pubkey-as-HMAC) +
alg:none, DY-legal (attacker শুধু issuer-এর public key জানে)। শুধু **স্বাধীন
implementation** গণনা করা হয়েছে — wrapper/fork বাদ (pyjwt3, python-jwt→jwcrypto,
express-jwt→jsonwebtoken, flask-jwt-extended→PyJWT ইত্যাদি)। scripts: `bughunt/`।

## ফলাফল

| ভাষা | library (version) | confusion (normal use) | শ্রেণি |
|---|---|---|---|
| Python | PyJWT 2.14.0 | reject | safe-by-default |
| Python | python-jose 3.5.0 | reject | safe-by-default |
| Python | Authlib 1.8.0 | reject | safe-by-default |
| Python | jwcrypto 1.6.1 | reject | safe-by-default |
| Python | joserfc 1.7.5 | reject | safe-by-default |
| Python | jwskate 0.12.2 | reject | safe-by-default |
| Python | cryptojwt 1.11.0 (IDPy/pyoidc) | reject (SignerAlgError) | safe-by-default |
| Node | panva/jose 5.x | reject | safe-by-default |
| Node | jsonwebtoken 9.0.2 | reject | safe-by-default (8.5.1 hist-vuln) |
| Node | jwt-simple 0.5.6 | reject | safe (historically vuln, now fixed) |
| Node | fast-jwt 6.3.3 | reject | safe-by-default |
| Node | jsrsasign 11.1.5 | reject (RSA≠HMAC key error) | safe-by-default |
| Node | @tsndr/cloudflare-worker-jwt | reject | safe-by-default |
| Node | **njwt 2.0.1** | **ACCEPT if algorithm not pinned** | **unsafe-by-default** |
| Node | jws 4.0.1 (low-level) | accept under header-alg misuse | pin-required |
| Go | golang-jwt/v5 5.2.1 | accept under keyfunc misuse | pin-required |
| Java | nimbus-jose-jwt 9.40 | accept under MACVerifier misuse | pin-required |
| PHP | firebase/php-jwt 6.10.0 | reject (alg pinned per Key) | safe-by-default |

## মূল finding (আগের চেয়ে ধারালো ও সৎ)
তিন-স্তরের ergonomics পরিষ্কার হলো:
1. **safe-by-default** (১৩টি): normal usage-এ confusion অসম্ভব — asymmetric key-কে
   symmetric alg-এ ব্যবহার করতে অস্বীকার/allow-list পিন করা।
2. **unsafe-by-default** (njwt 2.0.1): default algorithm HS256; RSA verifier যদি
   `verify(token, pubkey)`-এ algorithm না দেয় (স্বাভাবিক ভুল), তবে confusion সফল।
   README-documented default behaviour — **known footgun, নতুন 0-day নয়**।
3. **pin-required low-level** (jws, golang-jwt, nimbus): caller-কেই algorithm/key-type
   মেলাতে হয়; না করলে confusion।

## সৎ verdict
- **নতুন 0-day নেই** কোনো library-র নিজস্ব সঠিক/documented usage-এ।
- কিন্তু **exposure-এর ergonomics ranking** একটা প্রকৃত অবদান: ২০২৬-এও confusion-ঝুঁকি
  টিকে আছে unsafe-by-default (njwt) ও pin-required (jws/golang-jwt/nimbus) API-তে,
  safe-by-default API-তে নয়। njwt-এর default-unsafe হওয়া সবচেয়ে খারাপ ergonomics।
- njwt-এর আচরণ documented → নতুন CVE দাবি করা হচ্ছে না। কেউ চাইলে maintainer-কে
  ergonomics-উন্নতির suggestion দিতে পারে, কিন্তু এটা "আবিষ্কার" নয়।
