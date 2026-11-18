"""
Grammar-extended HONEST corpus (DESIGN_grammar_ext.md, Axes 1-2 only)
=====================================================================
S = structural / serialization (honest), T = claim-type coercion (honest).

Every case here is honestly_issued=True: the issuer signs a real role=user payload, and the *only* thing
that varies is how the token is serialized (S) or how a claim is typed (T). These are exactly the
dimensions where correct libraries legitimately diverge, so this corpus is the honest stress test of the
provenance oracle's central claim: 0 claim-path false positives. A verifier that *rejects* one of these is
a capability/strictness difference (class C), never a security finding.

Deliberately NOT generated here: crafted / forged families (Axis 3 mutation-chains, Axis 4 header-injection).
Those duplicate the frozen corpus (corpus/ F1+F2, 2045 forgeries), operators.py (fn_header_jwk/jku/x5u/kid),
and random_fuzz.py (seeded mutation chains); and the scale30 run already found 0/2045 forgeries accepted, so
a larger forged set has ~0 expected yield. See DESIGN_grammar_ext.md and the note in EXP_grammar_ext.md.

Never touches the frozen corpus (corpus/). Writes to corpus_g/:
  cases.json           - adapter reads only this (id, token, allowed_algs, key, meta)
  truth.json           - id -> TokenTruth (adapter never reads it: blinding)
  signed.json          - id -> exact UTF-8(surrogateescape) bytes the issuer signature covers.
                         Used by the claim-fidelity check; adapters never read it either.
  corpus_manifest.json - counts + sha256

usage: python gen_corpus_g.py [outdir]
"""
import hashlib, json, sys, unicodedata
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa, ec

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "corpus"))
sys.path.insert(0, str(HERE.parents[1]))
import gen_corpus as g  # noqa: E402  (claims, signer, key_hmac, key_pub, compact, IAT, EXP)
import operators as op   # noqa: E402

OUT = HERE
KID = "issuer-key-1"

# fixed issuer keys (this corpus is its own reproducibility artifact; sha256 in the manifest, like corpus/)
_HS = bytes.fromhex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
_RSA = rsa.generate_private_key(65537, 2048)
_EC = ec.generate_private_key(ec.SECP256R1())
HKEY = g.key_hmac(_HS)
_rk = g.key_pub(_RSA.public_key())
RKEY = {**_rk, "jwk": {**_rk["jwk"], "kid": KID}}
EKEY = g.key_pub(_EC.public_key())

# base -> (alg, B2 variant string, private key, verifier key dict)
BASES = {"HS256": ("HS256", "min", _HS, HKEY),
         "RS256": ("RS256", "2048", _RSA, RKEY),
         "ES256": ("ES256", "P-256", _EC, EKEY)}


def jb(x):
    return json.dumps(x, separators=(",", ":"), ensure_ascii=False).encode()


class Corpus:
    def __init__(self):
        self.cases, self.truth, self.signed = [], {}, {}

    def add(self, cid, token, base, family, tags=(), signed=None):
        assert cid not in self.truth, cid
        alg, var, _, key = BASES[base]
        self.cases.append(dict(id=cid, token=token, allowed_algs=[alg], key=key,
                               meta=dict(alg=alg, variant=var, family=family, seed=1, tags=list(tags))))
        self.truth[cid] = dict(honestly_issued=True, legit_role="user", attack_role="")
        self.signed[cid] = (signed if signed is not None else jb(g.claims("user"))).decode("utf-8", "surrogateescape")


def sign(base, header_bytes, payload_bytes):
    """issuer signs raw header/payload bytes, so byte-level variants are exactly what was signed."""
    alg, _, priv, _ = BASES[base]
    hb, pb = op.b64url(header_bytes), op.b64url(payload_bytes)
    sb = op.b64url(g.signer(alg, priv)(f"{hb}.{pb}".encode()))
    return hb, pb, sb


# ===== Axis 1: structural / serialization (honest) =====
def fam_S(C):
    for base in BASES:
        alg = BASES[base][0]
        user = jb(g.claims("user"))
        hdr = jb({"alg": alg, "typ": "JWT"})
        hb, pb, sb = sign(base, hdr, user)

        def add(v, tok, tags=(), signed=user):
            C.add(f"S/{base}/{v}", tok, base, "S", tags=tags, signed=signed)

        # -- compact control + RFC 7515 JSON serializations (same signature, re-serialized) --
        add("compact", f"{hb}.{pb}.{sb}")
        add("json_flat", json.dumps({"protected": hb, "payload": pb, "signature": sb}), ["json_ser"])
        add("json_general",
            json.dumps({"payload": pb, "signatures": [{"protected": hb, "signature": sb}]}), ["json_ser"])
        add("ws_json", json.dumps({"protected": hb, "payload": pb, "signature": sb}, indent=2), ["json_ser"])

        # -- encoding strictness (issuer still signed the real payload) --
        pad = pb + "=" * (-len(pb) % 4)
        if pad != pb:
            add("b64pad", f"{hb}.{pad}.{sb}", ["encoding"])
        add("trailing_nl", f"{hb}.{pb}.{sb}\n", ["encoding"])

        # -- header bytes valid-but-noncanonical JSON (signed as-is) --
        for v, hb2 in (("hdr_ws", ('{ "alg" : "%s" , "typ" : "JWT" }' % alg).encode()),
                       ("hdr_order", ('{"typ":"JWT","alg":"%s"}' % alg).encode())):
            h2, p2, s2 = sign(base, hb2, user)
            add(v, f"{h2}.{p2}.{s2}")

        # -- payload byte forms with identical JSON meaning / RFC-forbidden BOM --
        esc = ('{"sub":"alice","\\u0072ole":"user","iss":"real-issuer","iat":%d,"exp":%d}'
               % (g.IAT, g.EXP)).encode()               # r == 'r' -> "role"
        h2, p2, s2 = sign(base, hdr, esc)
        add("pl_escaped_key", f"{h2}.{p2}.{s2}", signed=esc)
        bom = b"\xef\xbb\xbf" + user                     # RFC 8259: MUST NOT emit; parsers vary
        h2, p2, s2 = sign(base, hdr, bom)
        add("pl_bom", f"{h2}.{p2}.{s2}", ["encoding"], signed=bom)

        # -- duplicate member name: MEANING is undefined -> reported on its own, never FP/TP (design) --
        dup = ('{"sub":"alice","role":"user","role":"user","iss":"real-issuer","iat":%d,"exp":%d}'
               % (g.IAT, g.EXP)).encode()
        h2, p2, s2 = sign(base, hdr, dup)
        add("dup_member", f"{h2}.{p2}.{s2}", ["parse_ambiguous"], signed=dup)

        # -- unknown must-understand header: RFC 7515 4.1.11 says REJECT. issuer-signed, so acceptance is a
        #    strictness observation, not a provenance violation. tagged, excluded from primary FP denom. --
        h2, p2, s2 = sign(base, jb({"alg": alg, "typ": "JWT", "crit": ["x-must"], "x-must": 1}), user)
        add("crit_unknown", f"{h2}.{p2}.{s2}", ["must_reject"])


# ===== Axis 2: claim-type coercion (honest) =====
def fam_T(C):
    cafe = "café"
    variants = {
        "aud_string": (g.claims("user", aud="api"), ["type_coerced"]),
        "aud_array": (g.claims("user", aud=["api", "web"]), []),
        "bigint": (g.claims("user", n=2 ** 60), ["precision"]),
        "bigint_53p1": (g.claims("user", n=2 ** 53 + 1), ["precision"]),
        "exp_float": (g.claims("user", exp=g.EXP + 0.5), ["precision"]),
        "str_num": (g.claims("user", ver="01"), []),
        "null_member": (g.claims("user", mid=None), ["null_vs_absent"]),
        "float_claim": (g.claims("user", score=0.1), ["precision"]),
        "nested_obj": (g.claims("user", ctx={"tenant": "acme", "lvl": [1, 2]}), []),
        "empty_obj_arr": (g.claims("user", o={}, a=[]), []),
        "bool_claim": (g.claims("user", email_verified=True), []),
        "unicode_nfc": (g.claims("user", name=unicodedata.normalize("NFC", cafe)), []),
        "unicode_nfd": (g.claims("user", name=unicodedata.normalize("NFD", cafe)), ["unicode"]),
        "unicode_astral": (g.claims("user", name="\U0001f642 ok"), ["unicode"]),
        "long_claim": (g.claims("user", note="x" * 4096), []),
        "many_claims": ({**g.claims("user"), **{f"c{i}": i for i in range(200)}}, []),
    }
    for base in ("HS256", "RS256"):
        alg = BASES[base][0]
        hdr = jb({"alg": alg, "typ": "JWT"})
        for name, (payload, tags) in variants.items():
            pb = jb(payload)
            h, p, s = sign(base, hdr, pb)
            C.add(f"T/{base}/{name}", f"{h}.{p}.{s}", base, "T", tags=tags, signed=pb)


def main():
    global OUT
    if len(sys.argv) > 1:
        OUT = Path(sys.argv[1]).resolve(); OUT.mkdir(parents=True, exist_ok=True)
    C = Corpus()
    fam_S(C)
    fam_T(C)
    (OUT / "cases.json").write_text(json.dumps({"version": "g1", "cases": C.cases}, indent=0, ensure_ascii=False))
    (OUT / "truth.json").write_text(json.dumps(C.truth, indent=0))
    (OUT / "signed.json").write_text(json.dumps(C.signed, indent=0, ensure_ascii=False))
    from collections import Counter
    fam = Counter(c["meta"]["family"] for c in C.cases)
    man = {"n_cases": len(C.cases), "families": dict(fam),
           "sha256": {f: hashlib.sha256((OUT / f).read_bytes()).hexdigest()
                      for f in ("cases.json", "truth.json", "signed.json")}}
    (OUT / "corpus_manifest.json").write_text(json.dumps(man, indent=1))
    print(json.dumps(man, indent=1))


if __name__ == "__main__":
    main()
