# ADAPTERS — scale30 adapter card (PREREG §3)

সব adapter একই contract মানে: `corpus/cases.json` পড়ে, প্রতি কেসে একটা JSONL লাইন লেখে
(`impl, version, lang, backend, case, accepted, claims, error, stage, ns`)। `truth.json` কেউ পড়ে না।
Gate: `corpus/gate.json` (G1–G4) → `check_gate.py`। Install: ২৫ সেপ্ট ২০২৬, সর্বশেষ stable (PREREG §2 নিয়ম ৪)।

## সাধারণ নীতি (সব adapter-এ একই)
- **Config = README-র নিরাপদ স্বাভাবিক ব্যবহার:** allow-list পিন করা; library একটামাত্র alg নিলে
  `allowed_algs[0]` পিন করা (নিচে "pin[0]" লেখা)। issuer/audience কোথাও configure করা নেই।
- **keyload/verify সীমারেখা:** keyload = key material-কে library-র high-level API যে container নেয়
  তাতে রূপান্তর (JCA-ভিত্তিক lib-এ generic `SecretKeySpec`/`X509EncodedKeySpec`)। library-র নিজস্ব policy
  check (key size ইত্যাদি) সাধারণত verify-তে পড়ে। **সীমাবদ্ধতা:** যেসব library-তে container নিজেই
  alg-নির্দিষ্ট verifier (josekit, rust/jwt-simple, kataras) বা যার parser validation করে (jwx), সেখানে
  policy keyload-এ পড়ে। তাই keyload>5% নিয়ম আংশিকভাবে API ডিজাইনের উপর নির্ভরশীল। এই পছন্দগুলো
  প্রতিটা library-র ফল দেখার আগে ঠিক করা হয়েছিল। jwx-এর JWK-parser পছন্দ অবশ্য Java-র নীতি লেখার আগের।
- **Optional plug-in যোগ করা হয়নি:** nimbus-এ Tink (EdDSA), ruby-jwt-এ `jwt-eddsa`, jwx-এ `jwx_es256k`
  build tag। default install-এর আচরণই মাপা হয়েছে।
- **Library-র unsupported alg:** adapter-এ সেই alg-এর API না থাকলে verify-stage reject ("no algorithm
  for X")। key import-এ ব্যর্থ হলে keyload (যেমন Go x509-এ secp256k1/Ed448)।
- **Warm-up:** Python/Node/Go/PHP/Rust/Ruby-তে প্রথম কেস দুবার মাপা; Java/.NET-এ পুরো corpus দুবার,
  দ্বিতীয় রান লেখা।

## Card

| impl | version | API (সংক্ষেপে) | key container | honest-reject | keyload | অবস্থা |
|---|---|---|---|---|---|---|
| python/pyjwt | 2.15.0 | `jwt.decode(t,k,algorithms)` | bytes / PEM | 12 | 0 | ok |
| python/python-jose | 3.5.0 | `jwt.decode(t,k,algorithms)` | bytes / PEM | 45 | 0 | ok |
| python/authlib | 1.8.0 | `JsonWebToken(algs).decode` + `validate()` | bytes / PEM | 0 | 0 | ok |
| python/jwcrypto | 1.6.1 | `JWT(key,jwt,algs)` | JWK | 9 | 0 | ok |
| python/joserfc | 1.7.5 | `jwt.decode(t,k,algorithms)` + `JWTClaimsRegistry` | JWK | 6 | 0 | ok |
| python/jwskate | 0.12.2 | `SignedJwt.verify_signature(k,algs)` + expiry | JWK | 3 | 0 | ok |
| python/cryptojwt | 1.11.0 | `JWT(key_jar,allowed_sign_algs).unpack` | KeyJar(iss) | 0 | 3 | ok (ES256K import) |
| node/jose | 6.2.12 | `jwtVerify(t,k,{algorithms})` | KeyObject | 21 | 0 | ok |
| node/jsonwebtoken | 9.0.3 | `verify(t,k,{algorithms})` | Buffer / PEM | 9 | 0 | ok |
| node/fast-jwt | 6.3.3 | `createVerifier({key,algorithms})` | Buffer / PEM | 3 | 0 | ok |
| node/jsrsasign | 11.1.5 | `JWS.verifyJWT(t,k,{alg})` | hex / KEYUTIL | 3 | 6 | ok (EdDSA import) |
| node/njwt | 2.0.1 | `verify(t,k,alg)` pin[0] | Buffer / PEM | 33 | 0 | ok |
| node/node-jose | 2.2.0 | `JWS.createVerify(k,{algorithms})` | JWK | 12 | 6 | ok (EdDSA import) |
| node/jwt-simple | 0.5.6 | `decode(t,k,false,alg)` pin[0] | Buffer / PEM | 66 | 0 | **reserve ১**; G1 ES256 exempt (README: HS*/RS256 only) |
| node/cloudflare-worker-jwt | 3.2.3 | `verify(t,jwk,{algorithm,throwError})` pin[0] | JWK | 33 | 0 | **reserve ২** |
| go/golang-jwt | v5.3.1 | `Parse(t,keyfunc,WithValidMethods)` | typed key | 0 | 6 | ok |
| go/jwx | v3.3.0 | `jwt.Parse(WithKey(alg,k)...)` | `jwk.ParseKey` | 3 | 18 | **বাদ** (keyload 11.3%: RSA-1024, ES256K) |
| go/go-jose | v4.1.5 | `ParseSigned(t,algs)` + `Claims` + `Validate` | JWK | 9 | 6 | ok |
| go/kataras-jwt | v0.3.0 | `Verify(alg,k,t)` pin[0] | typed key | 27 | 3 | ok; সব অ-মানক header reject (কারণ UNVERIFIED) |
| java/nimbus-jose-jwt | 10.10 | `DefaultJWTProcessor` + `JWSVerificationKeySelector` | JWKSet | 24 | 0 | ok; `typ:at+jwt` default-এ reject |
| java/jjwt | 0.13.0 | `parser().verifyWith(k).parseSignedClaims` (allow-list API নেই) | JCA | 33 | 0 | ok |
| java/java-jwt | 4.6.1 | `JWT.require(Algorithm.X(k)).verify` pin[0] | JCA | 33 | 0 | ok |
| java/jose4j | 0.9.7 | `JwtConsumerBuilder` + `AlgorithmConstraints(PERMIT)` | JCA | 45 | 0 | ok |
| php/php-jwt | v7.2.0 | `JWT::decode(t,new Key(k,alg))` pin[0] | string / PEM / b64 Ed | 48 | 0 | ok |
| php/lcobucci-jwt | 5.6.0 | `Validator->assert(SignedWith, LooseValidAt)` pin[0] | `InMemory` | 48 | 0 | ok |
| php/jwt-framework | 4.2.3 | `JWSVerifier(AlgorithmManager).verifyWithKey` + checkers | JWK | 15 | 0 | ok |
| rust/jsonwebtoken | 11.1.0 | `decode(t,&k,&Validation{algorithms})`, aws_lc_rs | DecodingKey | 33 | 3 | ok |
| rust/josekit | 0.10.3 | `decode_with_verifier` + `JwtPayloadValidator` pin[0] | alg verifier (PS*: JWK) | 0 | 24 | **বাদ** (keyload 15.1%: HMAC<32B, RSA-1024) |
| rust/jwt-simple | 0.13.1 | `<ALG>PublicKey::verify_token` pin[0] | alg key | 2 | 6 | ok; high-S ES256K reject (LOG #৭) |
| ruby/ruby-jwt | 3.3.0 | `JWT.decode(t,k,true,{algorithm})` | String / `PKey` | 6 | 0 | ok |
| ruby/json-jwt | 1.17.2 | `JSON::JWT.decode(t,k,algs)` | String / `PKey` | 6 | 0 | ok |
| dotnet/IdentityModel | 8.23.0 | `JsonWebTokenHandler.ValidateTokenAsync` (ValidAlgorithms; iss/aud off) | JsonWebKey | 18 | 0 | ok |
| dotnet/jose-jwt | 5.3.0 | `Jose.JWT.Decode(t,k,alg)` pin[0] | byte[] / RSA / ECDsa | 3 | 6 | ok (OKP container নেই) |
| dotnet/JWT | 11.1.0 (assembly 11.0.0.0) | `JwtBuilder...MustVerifySignature().Decode` pin[0] | byte[] / RSA / ECDsa | 27 | 6 | ok (OKP container নেই) |

honest-reject আর keyload = ১৫৯টা বৈধ কেসের মধ্যে।

## Gate-এ ধরা পড়া adapter bug (ঠিক করে আবার gate চালানো)
- python/cryptojwt: `unpack()` dict ফেরত দেয়, `.to_dict()` ছিল।
- php/jwt-framework: v4-এর claim checker-এ PSR clock আবশ্যক।
- rust/josekit PS*: `verifier_from_pem` শুধু RSASSA-PSS OID-এর PEM নেয় → JWK (format artifact)।

## Toolchain (sudo ছাড়া)
`scale30/env.sh` দেখুন। PHP = conda-forge 8.5.9 (system PHP-তে `ext-sodium` নেই; lcobucci 5.x-এর দরকার)।
Rust: BoringSSL (jwt-simple) আর OpenSSL (josekit) একই binary-তে link হয় না → দুটো binary (`adapters/rust/run.sh`)।

## নতুন ecosystem (PREREG_newlangs) — আলাদা set, মূল ৩২-এর সংখ্যায় নয়
Install: ২৫ সেপ্ট ২০২৬, সর্বশেষ stable। adapter corpus-এ চালানোর আগে freeze (commit)। রান: `unshare -rn`, `TZ=UTC LC_ALL=C`।
Fidelity check (corpus-এর বাইরের নিজস্ব টোকেন: unicode, 2^60, aud array/string, null) — সব মিলেছে।
honest-reject/keyload মূল রানের পরে পূরণ হবে।

| impl | version | API (সংক্ষেপে) | key container | honest-reject | keyload | অবস্থা |
|---|---|---|---|---|---|---|
| dart/dart_jsonwebtoken | 3.4.1 | `JWT.verify(t,k)` (allow-list API নেই; alg header থেকে, key-টাইপ cast; default `typ=="JWT"` আবশ্যক) | SecretKey(b64) / PEM | — | — | gate PASS |
| dart/jose | 0.3.5+2 | `JsonWebToken.decodeAndVerify(t,store,allowedArguments)` + `claims.validate()` | JWK (JsonWebKeyStore; kid-matching) | — | — | gate PASS; EdDSA সমর্থন নেই (README) |
| c/libjwt | 3.6.1 (tag v3.6.1, f4edfe5) | `jwt_checker_setkey(alg,JWK)` + `jwt_checker_verify` pin[0]; claim checker callback থেকে (parse-এর পরে, verify-এর আগে), verify==0 হলে belief | JWK (`jwks_create`) | — | — | gate PASS |
| c/cjose | 0.8.1 (cisco/cjose, 6fdb5fe) | `cjose_jws_import` + `cjose_jws_verify` (JWS-স্তর; allow-list আর exp যাচাই নেই) | JWK (`cjose_jwk_import`) | — | — | gate PASS |
| erlang/erlang-jose | 1.11.12 (Hex) | `JOSE.JWT.verify_strict(jwk,algs,t)` (Elixir 1.20.4 / OTP 29 থেকে); claim (exp) যাচাই নেই — Joken wrapper-এর কাজ | JWK (`JOSE.JWK.from_map`) | — | — | gate PASS; JSON codec = default OTP `json` |
| swift/jwt-kit | 5.7.1 (Vapor) | `JWTKeyCollection.add(…)` (alg key-এর সাথে বাঁধা → pin[0]) + `verify(t, as: Payload)`; payload-এর `verify(using:)`-এ exp | HMACKey / PEM (`Insecure.RSA.PublicKey`, `ES*PublicKey`, `EdDSA.PublicKey`) | — | — | gate PASS; RSA < 2048 container-এই throw (keyload); ES256K API নেই |
| swift/swift-jwt | 4.0.2 (Kitura) | — | — | — | — | **বাদ (build হয় না)**: dependency BlueRSA OpenSSL 1.x macro (`EVP_PKEY_size`, `EVP_CIPHER_iv_length`) ব্যবহার করে, Swift-এ OpenSSL 3.x-এ import হয় না। PREREG_newlangs §2 অনুযায়ী বাদ; পুরনো OpenSSL দিয়ে জোর করে build = default install নয় |

C source: `adapters/c/fetch.sh` release tag + commit hash-এ পিন করে; build `run.sh --build` (OpenSSL 3.6.4, jansson 2.15.1;
repo path-এ space থাকায় libjwt-এর build ভাঙে, তাই `~/.local/opt/scale30-c` symlink দিয়ে build)।
**নির্বাচন-নোট:** আগে ক্লোন করা source release ছিল না (libjwt master 94e3cdf; cjose `1.0.0 (unreleased)` HEAD) — PREREG §2 নিয়ম ৪
অনুযায়ী release tag-এ বদলানো। cjose-এর দুটো সক্রিয় ধারা: cisco/cjose (মূল, সর্বশেষ release 0.8.1, ১৪ সেপ্ট ২০২৬) আর
OpenIDC/cjose (fork, v0.6.2.8) — নিয়ম ২ (fork বাদ) অনুযায়ী cisco/cjose। এই সিদ্ধান্ত কোনো corpus রানের আগে।

BEAM: micromamba env `beam` (conda-forge erlang OTP 29 + elixir 1.20.4, sudo ছাড়া); `run.sh --build` = mix deps.get + escript।
Gate-এ ধরা পড়া adapter bug: OTP `json` JSON null-কে `:null` atom দেয়, Elixir `JSON.encode!` তা string "null" লিখত →
`:null`→`nil` রূপান্তর (fidelity test-এ ধরা, corpus রানের আগে)।

Swift: swiftly দিয়ে Swift 6.4.0 (Ubuntu 24.04 toolchain; Manjaro অফিসিয়ালি সমর্থিত নয়)। build tool-গুলো শুধু `libncurses.so.6` চায়,
Manjaro-তে আছে `libncursesw.so.6` → toolchain-এর RUNPATH dir (`usr/lib/swift/linux`)-এ symlink। Swift-JWT 4.0.2-এর tag commit
১৪ নভে ২০২৪ (২৪ মাসের নিয়মে টেকে), কিন্তু build হয় না — উপরে কারণ।
