"""
ঘর #২ + #৩ — Operators (JWT-র "ইট")
=====================================
প্রতিটা function একটা ছোট ধাপ: হয় JWT-র একটা অংশ বানায়, নয় crypto হিসাব করে।
নিয়ম: এগুলো আক্রমণ নয়। fuzzer এগুলো জোড়া লাগিয়ে আক্রমণ বানাবে।

DY নিরাপত্তা-সীমা:
  - attacker Issuer-এর PUBLIC key পায় (প্রকাশ্য)
  - attacker Issuer-এর private key / HMAC secret পায় না
"""

import json
import base64
import hmac
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


# ─────────────────────────────────────────────────────────────
# সহায়ক: base64url encode/decode (JWT-র সর্বত্র লাগে)
# ─────────────────────────────────────────────────────────────
def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")

def b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


# ─────────────────────────────────────────────────────────────
# Atom (arity ০) — সম্ভাব্য মান
# ─────────────────────────────────────────────────────────────
def fn_alg_hs256(): return "HS256"
def fn_alg_rs256(): return "RS256"
def fn_alg_none():  return "none"

def fn_role_user():  return "user"
def fn_role_admin(): return "admin"


# ─────────────────────────────────────────────────────────────
# Constructor — JWT-র অংশ বানানো
# ─────────────────────────────────────────────────────────────
def fn_header(alg: str) -> dict:
    return {"alg": alg, "typ": "JWT"}

def fn_payload(role: str, iss: str = "real-issuer") -> dict:
    return {"role": role, "iss": iss}

def fn_signing_input(header: dict, payload: dict) -> bytes:
    """b64url(header) + '.' + b64url(payload) — signature এটার উপরই হয়।"""
    h = b64url(json.dumps(header, separators=(",", ":")).encode())
    p = b64url(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}".encode()

def fn_compact(header: dict, payload: dict, signature: bytes) -> str:
    """তিন অংশ জোড়া দিয়ে compact JWT string।"""
    si = fn_signing_input(header, payload).decode()
    return f"{si}.{b64url(signature)}"


# ─────────────────────────────────────────────────────────────
# Crypto Operation
# ─────────────────────────────────────────────────────────────
def fn_hmac_sign(signing_input: bytes, key: bytes) -> bytes:
    """HMAC-SHA256। ⚠️ key হিসেবে যেকোনো bytes নেয় — এটাই দুর্বলতা।"""
    return hmac.new(key, signing_input, hashlib.sha256).digest()

def fn_rsa_sign(signing_input: bytes, privkey) -> bytes:
    return privkey.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())

def fn_pubkey_pem(privkey) -> bytes:
    """private key → public key-র PEM bytes। ⚠️ এটাই Algorithm Confusion-এর সেতু।"""
    return privkey.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


# ─────────────────────────────────────────────────────────────
# Phase C — বাড়তি operator (JWTeemo-র ৫ attack-class সম্পূর্ণ করতে)
# ─────────────────────────────────────────────────────────────

def fn_json_flat(header: dict, payload: dict, signature: bytes) -> str:
    """RFC 7515 Flattened JSON serialization।
    কেন: compact ছাড়াও JWS-এর বৈধ রূপ — Format Confusion-এর দরজা এখানেই।"""
    si = fn_signing_input(header, payload)
    protected_b64, payload_b64 = si.decode().split(".")
    return json.dumps({
        "protected": protected_b64,
        "payload": payload_b64,
        "signature": b64url(signature),
    }, separators=(",", ":"))


def fn_json_with_extra(header: dict, payload: dict, signature: bytes,
                       field_name: str, field_value) -> str:
    """Format Confusion-এর প্রাণভোমরা: বৈধ signature আসল payload-এর উপর অক্ষত,
    কিন্তু JSON object-এ একটা বাড়তি field বসানো যেখানে জাল claim থাকে।

    মূল ভুল (JWTeemo Fig 5c / Kubernetes case): crypto lib `payload` field-এর উপর
    signature যাচাই করে (সিল মেলে ✅), কিন্তু app টোকেন ভেঙে/ভুল field থেকে claim পড়ে
    → জাল মান পায়। "signature যেখানে, সিদ্ধান্ত সেখান থেকে নয়" — এটাই বাগ।"""
    si = fn_signing_input(header, payload)
    protected_b64, payload_b64 = si.decode().split(".")
    obj = {
        "protected": protected_b64,
        "payload": payload_b64,
        "signature": b64url(signature),
        field_name: field_value,          # ⚠️ signature-এর বাইরে, তাই unsigned
    }
    return json.dumps(obj, separators=(",", ":"))


def fn_pbes2_header(p2c: int, p2s: bytes = b"saltsaltsalt", alg: str = "PBES2-HS256+A128KW",
                    enc: str = "A128GCM") -> dict:
    """Billion Hashes-এর কাঁচামাল: PBES2 header বিশাল iteration count (p2c)-সহ।
    কেন: verifier key derive করতে p2c বার PBKDF2 চালায় → বড় p2c = CPU DoS।
    (attack নয়, শুধু ইট — resource oracle এই টোকেন verify-সময় দেখে ধরবে।)"""
    return {"alg": alg, "enc": enc, "p2c": p2c, "p2s": b64url(p2s)}


# ─────────────────────────────────────────────────────────────
# Phase C-3 — header-injection operators (jwk / jku / x5u / kid / nested)
# এগুলো RFC 7515-বৈধ header parameter। DY-সীমা: attacker নিজের keypair বানায়;
# verifier যদি header-এর key/URL বিশ্বাস করে, তবেই total auth-bypass।
# ─────────────────────────────────────────────────────────────
def fn_pubjwk(pubkey) -> dict:
    """RSA public key → JWK dict (header-এ embed করার জন্য)।"""
    nums = pubkey.public_numbers()
    def be(n): return b64url(n.to_bytes((n.bit_length() + 7) // 8, "big"))
    return {"kty": "RSA", "n": be(nums.n), "e": be(nums.e)}

def fn_header_jwk(alg: str, jwk: dict) -> dict:
    """embedded `jwk` header — verifier এটা বিশ্বাস করলে attacker-এর নিজের key-তে যাচাই হয়।"""
    return {"alg": alg, "typ": "JWT", "jwk": jwk}

def fn_header_jku(alg: str, url: str, kid: str = "k1") -> dict:
    """`jku` header — attacker-নিয়ন্ত্রিত JWKS URL (SSRF + key confusion)।"""
    return {"alg": alg, "typ": "JWT", "jku": url, "kid": kid}

def fn_header_x5u(alg: str, url: str) -> dict:
    """`x5u` header — attacker-নিয়ন্ত্রিত X.509 cert URL।"""
    return {"alg": alg, "typ": "JWT", "x5u": url}

def fn_header_kid(alg: str, kid: str) -> dict:
    """`kid` injection — path traversal / SQLi / command payload kid-এ।"""
    return {"alg": alg, "typ": "JWT", "kid": kid}
