"""scale30 Python adapter — ৭টা library, PREREG §3 contract।
ব্যবহার: .venv/bin/python run.py <cases.json> <outdir> [impl ...]
প্রতি impl-এ দুটো ধাপ: load(case) → key (stage=keyload), verify(token, key, algs) → claims
(stage=verify)। config = README-র নিরাপদ স্বাভাবিক ব্যবহার: allow-list পিন, key টাইপ করা।
truth.json এখানে কখনো পড়া হয় না।"""
import json, sys, time, warnings
from importlib.metadata import version
from pathlib import Path
warnings.filterwarnings("ignore")


def secret(c): return bytes.fromhex(c["key"]["secret_hex"])
def pem(c): return c["key"]["pem"]


# ── PyJWT: jwt.decode(token, key, algorithms=[...]) ──
def pyjwt_load(c):
    return secret(c) if c["key"]["kind"] == "hmac" else pem(c)
def pyjwt_verify(tok, k, algs):
    import jwt
    return jwt.decode(tok, k, algorithms=algs)


# ── python-jose: jose.jwt.decode(token, key, algorithms=[...]) ──
def jose_load(c):
    return secret(c) if c["key"]["kind"] == "hmac" else pem(c)
def jose_verify(tok, k, algs):
    from jose import jwt
    return jwt.decode(tok, k, algorithms=algs)


# ── Authlib: JsonWebToken(algs).decode(token, key); claims.validate() ──
def authlib_load(c):
    return secret(c) if c["key"]["kind"] == "hmac" else pem(c).encode()
def authlib_verify(tok, k, algs):
    from authlib.jose import JsonWebToken
    cl = JsonWebToken(algs).decode(tok, k)
    cl.validate()
    return dict(cl)


# ── jwcrypto: JWT(key=JWK, jwt=token, algs=[...]) — exp যাচাই default-এ ──
def jwcrypto_load(c):
    from jwcrypto import jwk
    return jwk.JWK(**c["key"]["jwk"])
def jwcrypto_verify(tok, k, algs):
    from jwcrypto import jwt
    return json.loads(jwt.JWT(key=k, jwt=tok, algs=algs).claims)


# ── joserfc: jwt.decode(token, key, algorithms=[...]) + JWTClaimsRegistry().validate ──
def joserfc_load(c):
    from joserfc import jwk
    return jwk.import_key(c["key"]["jwk"])
def joserfc_verify(tok, k, algs):
    from joserfc import jwt
    t = jwt.decode(tok, k, algorithms=algs)
    jwt.JWTClaimsRegistry().validate(t.claims)
    return dict(t.claims)


# ── jwskate: SignedJwt(token).verify_signature(jwk, algs=[...]) + expiry ──
def jwskate_load(c):
    from jwskate import Jwk
    return Jwk(c["key"]["jwk"])
def jwskate_verify(tok, k, algs):
    from jwskate import SignedJwt
    sj = SignedJwt(tok)
    if not sj.verify_signature(k, algs=algs):
        raise ValueError("verify_signature returned False")
    if sj.is_expired():
        raise ValueError("expired")
    return dict(sj.claims)


# ── cryptojwt: JWT(key_jar, allowed_sign_algs).unpack(token) — high-level, iss দিয়ে key খোঁজে ──
def cryptojwt_load(c):
    from cryptojwt.jwk.jwk import key_from_jwk_dict
    from cryptojwt.key_jar import KeyJar
    kj = KeyJar()
    kj.add_keys("real-issuer", [key_from_jwk_dict(c["key"]["jwk"])])
    return kj
def cryptojwt_verify(tok, kj, algs):
    from cryptojwt.jwt import JWT
    return dict(JWT(key_jar=kj, allowed_sign_algs=algs).unpack(tok))


IMPLS = {  # name → (pip dist, backend, load, verify)
    "pyjwt": ("pyjwt", "cryptography", pyjwt_load, pyjwt_verify),
    "python-jose": ("python-jose", "cryptography", jose_load, jose_verify),
    "authlib": ("authlib", "cryptography", authlib_load, authlib_verify),
    "jwcrypto": ("jwcrypto", "cryptography", jwcrypto_load, jwcrypto_verify),
    "joserfc": ("joserfc", "cryptography", joserfc_load, joserfc_verify),
    "jwskate": ("jwskate", "cryptography", jwskate_load, jwskate_verify),
    "cryptojwt": ("cryptojwt", "cryptography", cryptojwt_load, cryptojwt_verify),
}


def err(e): return f"{type(e).__name__}: {e}"[:200]


def run_one(name, cases, out):
    dist, backend, load, verify = IMPLS[name]
    base = dict(impl=f"python/{name}", version=version(dist), lang="python", backend=backend)
    with open(out, "w") as f:
        for i, c in enumerate(cases):
            r = dict(base, case=c["id"], accepted=False, claims={}, error="", stage="", ns=0)
            try:
                k = load(c)
            except Exception as e:
                r.update(stage="keyload", error=err(e))
            else:
                t0 = time.perf_counter_ns()
                try:
                    cl = verify(c["token"], k, c["allowed_algs"])
                    r["ns"] = time.perf_counter_ns() - t0
                    if isinstance(cl, dict):
                        r.update(accepted=True, claims=cl, stage="verify")
                    else:
                        r.update(stage="claims", error=f"non-dict claims: {type(cl).__name__}")
                except Exception as e:
                    r.update(ns=time.perf_counter_ns() - t0, stage="verify", error=err(e))
            if i == 0 and r["ns"]:            # প্রথম call-এ lazy import — timing বাদ দিয়ে আবার মাপা
                t0 = time.perf_counter_ns()
                try: verify(c["token"], k, c["allowed_algs"])
                except Exception: pass
                r["ns"] = time.perf_counter_ns() - t0
            # G3 D1: ensure_ascii=True so an accepted lone-surrogate claim is written as \ud800 instead of crashing
            f.write(json.dumps(r, ensure_ascii=True, default=str) + "\n")


def main():
    cases = json.loads(Path(sys.argv[1]).read_text())["cases"]
    outdir = Path(sys.argv[2]); outdir.mkdir(parents=True, exist_ok=True)
    for name in (sys.argv[3:] or IMPLS):
        run_one(name, cases, outdir / f"python__{name}.jsonl")
        print("done", name, file=sys.stderr)


if __name__ == "__main__":
    main()
