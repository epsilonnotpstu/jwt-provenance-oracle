"""
Phase A2 — Capability matrix (empirical)
=========================================
প্রশ্ন: কোন library কোন বৈধ (honest-issuer-সাইন-করা) টোকেন গ্রহণ করে?
        প্রতিটা REJECT এখানে সংজ্ঞা অনুযায়ী *নিরাপত্তা নয়* — এটাই শ্রেণী-C-এর
        বাস্তব, পদ্ধতিগত নমুনা (হাতে-বাছা PS256/HS512 নয়)।

নকশা:
  - ১৩টা JWS alg × key-variant (HMAC-এ ছোট/বড় key; RSA-তে 2048/1024 bit)।
  - signer = `cryptography` দিয়ে সরাসরি (operators-এর মতো), পরীক্ষাধীন ৪ library-র
    কোনোটা নয় — যাতে signer-library-র নিজস্ব quirks ফলাফলে না ঢোকে।
  - verifier-কে ঠিক সেই alg-টাই allow-list-এ দেওয়া হয় (ন্যায্য সুযোগ)।
  - ফল: capability_matrix.csv + capability_matrix.md

⚠️ সীমা: শুধু JWS। JWE (RSA-OAEP, PBES2, dir…) এখনো নেই। key "ধরন" ৪ library-কে
   একই PEM/bytes আকারে দেওয়া হয় — কোনো library JWK-dict চাইলে সেটা harness-এর
   সীমা, library-র নয় (error বার্তা দেখে আলাদা করতে হবে)।
"""
import csv, json, hmac, hashlib, warnings
warnings.filterwarnings("ignore")
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, padding
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from operators import b64url
from harness import verify_all

HASH = {"256": hashes.SHA256(), "384": hashes.SHA384(), "512": hashes.SHA512()}
HLIB = {"256": hashlib.sha256, "384": hashlib.sha384, "512": hashlib.sha512}
CURVE = {"ES256": (ec.SECP256R1(), 32), "ES384": (ec.SECP384R1(), 48), "ES512": (ec.SECP521R1(), 66)}


def _pem(pub):
    return pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def make_case(alg, variant):
    """(signing_key, verify_key, sign_fn) — honest issuer-এর দৃষ্টিকোণ থেকে।"""
    bits = alg[-3:]
    if alg.startswith("HS"):
        n = {"short": 16, "min": int(bits) // 8, "long": 64}[variant]
        secret = (b"k" * n)
        return secret, lambda si: hmac.new(secret, si, HLIB[bits]).digest()
    if alg.startswith(("RS", "PS")):
        priv = rsa.generate_private_key(65537, {"2048": 2048, "1024": 1024}[variant])
        pad = (padding.PKCS1v15() if alg.startswith("RS")
               else padding.PSS(mgf=padding.MGF1(HASH[bits]), salt_length=int(bits) // 8))
        return _pem(priv.public_key()), lambda si: priv.sign(si, pad, HASH[bits])
    if alg.startswith("ES"):
        curve, size = CURVE[alg]
        priv = ec.generate_private_key(curve)
        def sign(si):
            r, s = decode_dss_signature(priv.sign(si, ec.ECDSA(HASH[bits])))
            return r.to_bytes(size, "big") + s.to_bytes(size, "big")     # JOSE raw r||s
        return _pem(priv.public_key()), sign
    if alg == "EdDSA":
        priv = ed25519.Ed25519PrivateKey.generate()
        return _pem(priv.public_key()), lambda si: priv.sign(si)
    raise ValueError(alg)


CASES = ([(a, v) for a in ("HS256", "HS384", "HS512") for v in ("short", "min", "long")]
         + [(a, v) for a in ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512") for v in ("2048", "1024")
            if not (a == "PS512" and v == "1024")]   # PSS salt(64B)+SHA512 1024-bit key-এ অসম্ভব
         + [(a, "-") for a in ("ES256", "ES384", "ES512", "EdDSA")])


def token_for(alg, sign):
    h = b64url(json.dumps({"alg": alg, "typ": "JWT"}, separators=(",", ":")).encode())
    p = b64url(json.dumps({"role": "user", "iss": "real-issuer"}, separators=(",", ":")).encode())
    si = f"{h}.{p}".encode()
    return f"{h}.{p}.{b64url(sign(si))}"


def main():
    rows = []
    for alg, variant in CASES:
        vkey, sign = make_case(alg, variant)
        tok = token_for(alg, sign)
        for r in verify_all(tok, vkey, [alg]):
            rows.append(dict(alg=alg, variant=variant, library=r.library,
                             verdict="ACCEPT" if r.accepted else "REJECT",
                             error=r.error.replace("\n", " ")[:120]))

    with open("capability_matrix.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader(); w.writerows(rows)

    libs = list(dict.fromkeys(r["library"] for r in rows))
    lines = ["| alg | variant | " + " | ".join(libs) + " | differential? |",
             "|---|---|" + "---|" * len(libs) + "---|"]
    notes = []
    for alg, variant in CASES:
        rr = [r for r in rows if r["alg"] == alg and r["variant"] == variant]
        cells = ["✅" if r["verdict"] == "ACCEPT" else "❌" for r in rr]
        diff = len({r["verdict"] for r in rr}) > 1
        lines.append(f"| {alg} | {variant} | " + " | ".join(cells) + f" | {'**হ্যাঁ**' if diff else ''} |")
        notes += [f"- {alg}/{variant} — {r['library']}: `{r['error'][:90]}`" for r in rr if r["verdict"] == "REJECT"]

    n_cases = len(CASES)
    n_diff = sum(1 for a, v in CASES if len({r["verdict"] for r in rows if r["alg"] == a and r["variant"] == v}) > 1)
    md = ["# Capability matrix (বৈধ টোকেন, honest issuer)", "",
          "✅ = ACCEPT, ❌ = REJECT। প্রতিটা ❌ বৈধ টোকেনে — তাই সংজ্ঞা অনুযায়ী শ্রেণী-C (বা strictness), নিরাপত্তা নয়।", "",
          *lines, "", f"**{n_diff}/{n_cases} case-এ library-দের মধ্যে অমিল** — naive differential fuzzer এগুলোকে bug বলবে।", "",
          "## REJECT-এর কারণ", "", *notes, ""]
    open("capability_matrix.md", "w", encoding="utf-8").write("\n".join(md))
    print("\n".join(md))


if __name__ == "__main__":
    main()
