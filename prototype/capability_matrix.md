# Capability matrix (বৈধ টোকেন, honest issuer)

✅ = ACCEPT, ❌ = REJECT। প্রতিটা ❌ বৈধ টোকেনে — তাই সংজ্ঞা অনুযায়ী শ্রেণী-C (বা strictness), নিরাপত্তা নয়।

| alg | variant | PyJWT | python-jose | Authlib | jwcrypto | differential? |
|---|---|---|---|---|---|---|
| HS256 | short | ✅ | ✅ | ✅ | ❌ | **হ্যাঁ** |
| HS256 | min | ✅ | ✅ | ✅ | ✅ |  |
| HS256 | long | ✅ | ✅ | ✅ | ✅ |  |
| HS384 | short | ✅ | ✅ | ✅ | ❌ | **হ্যাঁ** |
| HS384 | min | ✅ | ✅ | ✅ | ✅ |  |
| HS384 | long | ✅ | ✅ | ✅ | ✅ |  |
| HS512 | short | ✅ | ✅ | ✅ | ❌ | **হ্যাঁ** |
| HS512 | min | ✅ | ✅ | ✅ | ✅ |  |
| HS512 | long | ✅ | ✅ | ✅ | ✅ |  |
| RS256 | 2048 | ✅ | ✅ | ✅ | ✅ |  |
| RS256 | 1024 | ✅ | ✅ | ✅ | ✅ |  |
| RS384 | 2048 | ✅ | ✅ | ✅ | ✅ |  |
| RS384 | 1024 | ✅ | ✅ | ✅ | ✅ |  |
| RS512 | 2048 | ✅ | ✅ | ✅ | ✅ |  |
| RS512 | 1024 | ✅ | ✅ | ✅ | ✅ |  |
| PS256 | 2048 | ✅ | ❌ | ✅ | ✅ | **হ্যাঁ** |
| PS256 | 1024 | ✅ | ❌ | ✅ | ✅ | **হ্যাঁ** |
| PS384 | 2048 | ✅ | ❌ | ✅ | ✅ | **হ্যাঁ** |
| PS384 | 1024 | ✅ | ❌ | ✅ | ✅ | **হ্যাঁ** |
| PS512 | 2048 | ✅ | ❌ | ✅ | ✅ | **হ্যাঁ** |
| ES256 | - | ✅ | ✅ | ✅ | ✅ |  |
| ES384 | - | ✅ | ✅ | ✅ | ✅ |  |
| ES512 | - | ✅ | ✅ | ✅ | ✅ |  |
| EdDSA | - | ✅ | ❌ | ✅ | ✅ | **হ্যাঁ** |

**9/24 case-এ library-দের মধ্যে অমিল** — naive differential fuzzer এগুলোকে bug বলবে।

## REJECT-এর কারণ

- HS256/short — jwcrypto: `InvalidJWSSignature: Verification failed for all signatures["Failed: [InvalidJWSSignature(`
- HS384/short — jwcrypto: `InvalidJWSSignature: Verification failed for all signatures["Failed: [InvalidJWSSignature(`
- HS512/short — jwcrypto: `InvalidJWSSignature: Verification failed for all signatures["Failed: [InvalidJWSSignature(`
- PS256/2048 — python-jose: `JWKError: Unable to find an algorithm for key`
- PS256/1024 — python-jose: `JWKError: Unable to find an algorithm for key`
- PS384/2048 — python-jose: `JWKError: Unable to find an algorithm for key`
- PS384/1024 — python-jose: `JWKError: Unable to find an algorithm for key`
- PS512/2048 — python-jose: `JWKError: Unable to find an algorithm for key`
- EdDSA/- — python-jose: `JWKError: Unable to find an algorithm for key`
