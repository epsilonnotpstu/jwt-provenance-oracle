"""PREREG_B2plus §2 — test corpus (corpus_b): সব বৈধ টোকেন, T-same আর T-new variant।
base = RS256-2048 আর HS256-min, ৩টা seed, নতুন key। ব্যবহার: gen_corpus_b.py <outdir>"""
import json, os, sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gen_corpus as G  # noqa: E402

T_SAME = {  # training-এ দেখা category-র নতুন instance
    "kid": ({"typ": "JWT", "kid": "k-2026-rotation"}, {}),
    "private_hdr": ({"typ": "JWT", "x-region": "eu"}, {}),
    "typ_other": ({"typ": "JOSE"}, {}),
    "aud": ({"typ": "JWT"}, {"aud": "https://api.example.org"}),
    "unicode": ({"typ": "JWT"}, {"name": "Grüße 日本語"}),
    "bigint": ({"typ": "JWT"}, {"n": 2 ** 62}),
}
T_NEW = {  # training-এ কখনো দেখা যায়নি এমন category
    "nbf": ({"typ": "JWT"}, {"nbf": G.IAT}),
    "exp_float": ({"typ": "JWT"}, {"exp": G.EXP + 0.5}),
    "big_payload": ({"typ": "JWT"}, {"note": "x" * 6000}),
    "nested": ({"typ": "JWT"}, {"ctx": {"tenant": "acme", "tier": 2}}),
    "jti": ({"typ": "JWT"}, {"jti": "5f0c2b7e-9d41-4c55-8a3e-0e4f1d2c7b90"}),
}


def main():
    out = Path(sys.argv[1]).resolve(); out.mkdir(parents=True, exist_ok=True)
    C = G.Corpus()
    for s in (1, 2, 3):
        rk = rsa.generate_private_key(65537, 2048); hs = os.urandom(32)
        bases = {"RS256/2048": ("RS256", "2048", rk, G.key_pub(rk.public_key())),
                 "HS256/min": ("HS256", "min", hs, G.key_hmac(hs))}
        for fam, table in (("TS", T_SAME), ("TN", T_NEW)):
            for bname, (alg, var, k, kp) in bases.items():
                for vname, (hdr, extra) in table.items():
                    kpv = {**kp, "jwk": {**kp["jwk"], "kid": hdr["kid"]}} if "kid" in hdr else kp
                    C.add(f"{fam}/{bname}/{vname}/s{s}",
                          G.compact({"alg": alg, **hdr}, G.claims("user", **extra), G.signer(alg, k)),
                          [alg], kpv, alg, var, fam, s, True)
        # self-embedded jwk (শুধু RS256): issuer নিজের public key header-এ দেয়
        C.add(f"TN/RS256/2048/self_jwk/s{s}",
              G.compact({"alg": "RS256", "typ": "JWT", "jwk": bases["RS256/2048"][3]["jwk"]}, G.claims("user"),
                        G.signer("RS256", rk)), ["RS256"], bases["RS256/2048"][3], "RS256", "2048", "TN", s, True)
    (out / "cases.json").write_text(json.dumps({"version": "b", "cases": C.cases}, ensure_ascii=False))
    (out / "truth.json").write_text(json.dumps(C.truth))
    print(len(C.cases), "cases")


if __name__ == "__main__":
    main()
