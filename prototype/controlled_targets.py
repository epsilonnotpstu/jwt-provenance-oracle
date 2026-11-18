"""
Controlled Targets — ground-truth-সহ verifier।
================================================
কেন: detector সত্যিকারের আক্রমণ ধরে কিনা প্রমাণ করতে একটা *জানা-দুর্বল* target লাগে,
     আর FP মাপতে একটা *জানা-নিরাপদ* target লাগে। আধুনিক library সব patched বলে
     এদের ground-truth নিয়ন্ত্রিতভাবে বানানো হলো।

এগুলো harness-এর VerifyResult আকারেই উত্তর দেয়, যাতে fuzzer/oracle একইভাবে চালাতে পারে।
"""
import hmac, hashlib, base64, json, time
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from harness import VerifyResult


def _split(token):
    h, p, s = token.split(".")
    header = json.loads(base64.urlsafe_b64decode(h + "=="))
    payload = json.loads(base64.urlsafe_b64decode(p + "=="))
    signing_input = f"{h}.{p}".encode()
    sig = base64.urlsafe_b64decode(s + "==") if s else b""
    return header, payload, signing_input, sig


def verify_VULN(token, key, algorithms=None):
    """
    ইচ্ছাকৃতভাবে দুর্বল: header-এর alg অন্ধভাবে বিশ্বাস করে, এক key দিয়েই
    HMAC আর RSA দুটো পথ চালায় → classic Algorithm Confusion + alg:none দুটোতেই দুর্বল।
    (এটাই ঐতিহাসিক ভুল প্যাটার্ন — ground-truth 'vulnerable'।)
    """
    t0 = time.perf_counter()
    try:
        header, payload, si, sig = _split(token)
        alg = header.get("alg")
        if alg == "none":
            ok = True                                  # 🚨 signature ছাড়াই মেনে নেয়
        elif alg.startswith("HS"):
            expected = hmac.new(_as_bytes(key), si, hashlib.sha256).digest()
            ok = hmac.compare_digest(expected, sig)    # 🚨 key যদি public PEM হয়, তবু চলে
        elif alg.startswith("RS"):
            pub = load_pem_public_key(_as_bytes(key))
            pub.verify(sig, si, padding.PKCS1v15(), hashes.SHA256()); ok = True
        else:
            ok = False
        dt = time.perf_counter() - t0
        if ok:
            return VerifyResult("VULN-target", True, payload, "", dt)
        return VerifyResult("VULN-target", False, {}, "bad signature", dt)
    except Exception as e:
        return VerifyResult("VULN-target", False, {}, f"{type(e).__name__}: {e}", time.perf_counter()-t0)


def verify_SAFE(token, key, algorithms=None):
    """
    নিরাপদ reference: শুধু allow-listed alg, alg:none বাতিল, public key দিয়ে
    HMAC করতে অস্বীকার। ground-truth 'safe'।
    """
    t0 = time.perf_counter()
    allow = set(algorithms or ["HS256"])
    try:
        header, payload, si, sig = _split(token)
        alg = header.get("alg")
        if alg not in allow or alg == "none":
            return VerifyResult("SAFE-target", False, {}, "algorithm not allowed", time.perf_counter()-t0)
        kb = _as_bytes(key)
        if alg.startswith("HS"):
            if b"-----BEGIN" in kb:                     # public key কে HMAC secret বানানো রুখে দেয়
                return VerifyResult("SAFE-target", False, {}, "asymmetric key rejected for HMAC", time.perf_counter()-t0)
            expected = hmac.new(kb, si, hashlib.sha256).digest()
            ok = hmac.compare_digest(expected, sig)
        elif alg.startswith("RS"):
            load_pem_public_key(kb).verify(sig, si, padding.PKCS1v15(), hashes.SHA256()); ok = True
        else:
            ok = False
        dt = time.perf_counter() - t0
        return VerifyResult("SAFE-target", ok, payload if ok else {}, "" if ok else "bad signature", dt)
    except Exception as e:
        return VerifyResult("SAFE-target", False, {}, f"{type(e).__name__}: {e}", time.perf_counter()-t0)


def _as_bytes(k):
    return k if isinstance(k, (bytes, bytearray)) else k.encode()


# ─────────────────────────────────────────────────────────────
# Phase C — Format Confusion controlled target
# ─────────────────────────────────────────────────────────────
def verify_FORMAT_CONFUSED(token, key, algorithms=None):
    """দুই-স্তরের ভুল app: crypto layer JSON-এর `payload` field-এর signature যাচাই করে
    (সিল মেলে), কিন্তু app claim পড়ে বাড়তি (unsigned) field থেকে — এটাই Format Confusion।
    ground-truth 'vulnerable to format confusion'।
    input: fn_json_with_extra(...)-এ বানানো JSON string।"""
    t0 = time.perf_counter()
    try:
        obj = json.loads(token)
        protected = obj["protected"]; payload_b64 = obj["payload"]
        si = f"{protected}.{payload_b64}".encode()
        sig = base64.urlsafe_b64decode(obj["signature"] + "==")
        # crypto layer: HS256 signature over payload যাচাই (সঠিক)
        expected = hmac.new(_as_bytes(key), si, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, sig):
            return VerifyResult("FMT-CONFUSED", False, {}, "bad signature", time.perf_counter()-t0)
        signed_claims = json.loads(base64.urlsafe_b64decode(payload_b64 + "=="))
        # 🚨 app-স্তরের ভুল: বাড়তি field থাকলে সেখান থেকে claim overlay করে
        if "fakeiss" in obj:
            signed_claims = {**signed_claims, **obj["fakeiss"]}   # unsigned মান বিশ্বাস
        return VerifyResult("FMT-CONFUSED", True, signed_claims, "", time.perf_counter()-t0)
    except Exception as e:
        return VerifyResult("FMT-CONFUSED", False, {}, f"{type(e).__name__}: {e}", time.perf_counter()-t0)


def verify_FORMAT_SAFE(token, key, algorithms=None):
    """নিরাপদ reference: শুধু signed `payload` থেকেই claim পড়ে, বাড়তি field উপেক্ষা করে।"""
    t0 = time.perf_counter()
    try:
        obj = json.loads(token)
        si = f"{obj['protected']}.{obj['payload']}".encode()
        sig = base64.urlsafe_b64decode(obj["signature"] + "==")
        expected = hmac.new(_as_bytes(key), si, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, sig):
            return VerifyResult("FMT-SAFE", False, {}, "bad signature", time.perf_counter()-t0)
        claims = json.loads(base64.urlsafe_b64decode(obj["payload"] + "=="))  # শুধু signed অংশ
        return VerifyResult("FMT-SAFE", True, claims, "", time.perf_counter()-t0)
    except Exception as e:
        return VerifyResult("FMT-SAFE", False, {}, f"{type(e).__name__}: {e}", time.perf_counter()-t0)
