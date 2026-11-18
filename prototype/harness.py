"""
ঘর #৬ — Harness (সম্পূর্ণ, ৪টা library)
=========================================
প্রতিটা JWT library-কে একটা অভিন্ন সুইচবোর্ডে নামায়:
    টোকেন (str) + key + allowed algs  →  VerifyResult(accepted, claims, error)

কেন অভিন্ন? — differential testing-এর জন্য fuzzer একই টোকেন সব library-কে
দিয়ে উত্তর তুলনা করবে। উত্তরের আকার এক না হলে তুলনা অসম্ভব।
"""

from dataclasses import dataclass, field
import time


@dataclass
class VerifyResult:
    library: str                        # কোন library দিল
    accepted: bool                      # মেনে নিল?
    claims: dict = field(default_factory=dict)   # ACCEPT হলে যে payload পেল
    error: str = ""                     # REJECT হলে কেন
    seconds: float = 0.0                # কত সময় লাগল (DoS oracle-এর জন্য)

    # কেন seconds? — DoS আক্রমণে library exception ছোঁড়ে না, REJECT-ও করে না,
    #   শুধু আটকে থাকে। ACCEPT/REJECT দিয়ে সেটা ধরা পড়ে না — সময় দিয়ে পড়ে।
    #   (ঘর #৫-এর "দুই রকম oracle": claim-mismatch + resource-threshold)


def _timed(fn):
    """একটা verify-চেষ্টা চালিয়ে সময় মেপে VerifyResult বানানোর মোড়ক।"""
    def wrapper(token, key, algorithms):
        t0 = time.perf_counter()
        try:
            claims = fn(token, key, algorithms)
            dt = time.perf_counter() - t0
            return dict(accepted=True, claims=claims, error="", seconds=dt)
        except Exception as e:
            dt = time.perf_counter() - t0
            # accepted=False, claims={} — কারণ বাতিল হলে কোনো claim পায়নি
            return dict(accepted=False, claims={}, error=f"{type(e).__name__}: {e}", seconds=dt)
    return wrapper


# ─────────────────────────────────────────────────────────────
# প্রতিটা library-র জন্য একটা করে ছোট adapter
# প্রতিটা শুধু "verify করো, claims ফেরত দাও, নইলে exception উঠুক" —
# মোড়ক (_timed) exception-কে অভিন্ন REJECT-এ অনুবাদ করে।
# ─────────────────────────────────────────────────────────────

@_timed
def _pyjwt(token, key, algorithms):
    import jwt as pyjwt
    return pyjwt.decode(token, key, algorithms=algorithms)

@_timed
def _jose(token, key, algorithms):
    from jose import jwt as jose_jwt
    return jose_jwt.decode(token, key, algorithms=algorithms)

@_timed
def _authlib(token, key, algorithms):
    from authlib.jose import JsonWebToken
    # ── ঠিক করা (২২ সেপ্টে): আগে `authlib.jose.jwt.decode(token, key)` ছিল,
    #   যেটা allow-list মানে না (সব alg গ্রহণ করে)। ফলে Authlib বনাম অন্যদের
    #   "অমিল" harness-এর তৈরি হতো, library-র নয়। এখন অন্যদের মতো একই allow-list।
    claims = JsonWebToken(algorithms).decode(token, key)
    claims.validate()                          # exp ইত্যাদি যাচাই এখানে
    return dict(claims)

@_timed
def _jwcrypto(token, key, algorithms):
    from jwcrypto import jwt as jwc_jwt, jwk
    import json
    # ── ঠিক করা: key-কে "একই অর্থে" নেওয়া ──
    #   PEM (asymmetric public/private) হলে from_pem — অন্য library যেভাবে পায়।
    #   নইলে raw symmetric secret হিসেবে oct JWK।
    #   আগের bug: সব key-কে জোর করে oct বানানো হতো → asymmetric key-ও
    #   symmetric হয়ে যেত → Algorithm Confusion-এ false-positive ACCEPT।
    k = _to_jwk(key)
    tok = jwc_jwt.JWT(key=k, jwt=token, algs=algorithms)
    return json.loads(tok.claims)


def _to_jwk(key):
    """key-material → jwcrypto JWK, key-এর আসল ধরন বজায় রেখে।"""
    from jwcrypto import jwk
    if isinstance(key, str):
        key = key.encode()
    if isinstance(key, (bytes, bytearray)) and b"-----BEGIN" in bytes(key):
        return jwk.JWK.from_pem(bytes(key))          # asymmetric — যেমনটা হওয়া উচিত
    return jwk.JWK(kty="oct", k=_b64url(bytes(key)))  # genuine symmetric secret


def _b64url(b: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


# ─────────────────────────────────────────────────────────────
# একটাই প্রবেশদ্বার: সব library-কে একই টোকেন দিয়ে উত্তর সংগ্রহ
# ─────────────────────────────────────────────────────────────

LIBRARIES = {
    "PyJWT": _pyjwt,
    "python-jose": _jose,
    "Authlib": _authlib,
    "jwcrypto": _jwcrypto,
}

def warm_up():
    """সব library আগে থেকে import করা।
    কেন: adapter-এর ভেতরের import প্রথম call-এর সময়ে ঢুকে যেত (~৫ms vs ~০.১ms),
    ফলে প্রথম call-কে baseline ধরলে DoS threshold ~৫০× ফুলে যেত (resource oracle অন্ধ)।
    """
    import warnings
    warnings.filterwarnings("ignore", message=".*authlib.jose module is deprecated.*")
    import jwt, jose.jwt, authlib.jose, jwcrypto.jwt, jwcrypto.jwk  # noqa: F401


warm_up()


def verify_all(token: str, key, algorithms) -> list:
    """একটা টোকেন সব library-কে দিয়ে VerifyResult-এর তালিকা ফেরত দাও।"""
    out = []
    for name, fn in LIBRARIES.items():
        r = fn(token, key, algorithms)
        out.append(VerifyResult(library=name, **r))
    return out


def measure_baseline(token: str, key, algorithms, runs: int = 15) -> float:
    """বৈধ টোকেনে কয়েকবার চালিয়ে সবচেয়ে ধীর library-র median সময় (সেকেন্ড)।
    কেন median, প্রথম call নয়: প্রথম call-এ lazy import/backend-load ঢুকে যায়,
    তাতে DoS threshold ফুলে যায়। একটা warm-up run আগে বাদ দেওয়া হয়।
    """
    import statistics
    verify_all(token, key, algorithms)                      # warm-up, বাদ
    per_lib = {}
    for _ in range(runs):
        for r in verify_all(token, key, algorithms):
            per_lib.setdefault(r.library, []).append(r.seconds)
    return max(statistics.median(v) for v in per_lib.values())
