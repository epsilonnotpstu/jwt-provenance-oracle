"""
Phase C-2 — Random mutation-chain fuzzing campaign (seeded, reproducible)
==========================================================================
কেন: এতদিন mutation হাতে-বাছা ছিল — reviewer বলবে "এটা fuzzer নয়, hand-crafted test"।
এখানে fuzzer N বার এলোমেলোভাবে operator জোড়া দিয়ে টোকেন বানায় (DY-সীমার ভেতরে),
৪ real library + controlled target-এ চালায়, provenance oracle দিয়ে শ্রেণী দেয়।

দুই স্রোত, প্রতিটার ground-truth নির্মাণ থেকেই জানা:
  • HONEST: issuer নিজে বৈধ টোকেন সাইন করে (random alg/key/serialization)।
    provenance = honestly_issued。 oracle কখনো A দিলে = false positive (oracle bug)।
  • ATTACK: attacker শুধু নিজের হাতের material (নিজের secret, issuer-এর PUBLIC key)
    দিয়ে random forgery বানায় (alg:none, confusion, wrong-key, format-confusion,
    random header extra: kid/crit)। provenance = forged, attack_role=admin।
    ৪ hardened library-তে A আশা করি না (তারা reject করে); VULN-target-এ A আশা করি।

মেট্রিক (N iteration জুড়ে):
  • provenance oracle-এর false positive ৪ real library-তে (আশা: 0)।
  • VULN-target-এ true-positive detection।
  • কোন কোন attack-class random chain ছুঁলো (coverage)।

⚠️ সৎ সীমা: coverage-guided নয় (uniform random)। আধুনিক ৪ library hardened বলে
   তাদের মধ্যে সত্যিকারের bug নেই — VULN-target true-positive-এর জন্য।
"""
import random, json, hmac, hashlib, argparse, warnings
warnings.filterwarnings("ignore")
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
import operators as op
from harness import verify_all, measure_baseline
from controlled_targets import verify_VULN, verify_SAFE, verify_FORMAT_CONFUSED, verify_FORMAT_SAFE
from oracle import TokenTruth, judge_truth

# ── key material ──
ISSUER_RSA = rsa.generate_private_key(65537, 2048)
ISSUER_SECRET = b"issuer-hmac-secret-32-bytes-long!!"
PUB_PEM = ISSUER_RSA.public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
ATTACKER_SECRET = b"attacker-knows-only-this-secret!!"

HASH = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
LEGIT_ROLE, ATTACK_ROLE = "user", "admin"


def _b(x): return op.b64url(x if isinstance(x, bytes) else json.dumps(x, separators=(",", ":")).encode())


def _hmac(alg, key, si): return hmac.new(key, si, HASH[alg]).digest()


def honest_token(rng):
    """issuer বৈধ টোকেন — random HMAC/RSA/EC/EdDSA, legit role."""
    fam = rng.choice(["HS256", "HS384", "HS512", "RS256", "ES256", "EdDSA"])
    payload = {"role": LEGIT_ROLE, "iss": "real-issuer"}
    header = {"alg": fam, "typ": "JWT"}
    if rng.random() < 0.3:
        header["kid"] = rng.choice(["k1", "k2", "prod"])          # RFC-বৈধ header extra
    h, p = _b(header), _b(payload); si = f"{h}.{p}".encode()
    if fam.startswith("HS"):
        secret = ISSUER_SECRET if rng.random() < 0.7 else (b"k" * (int(fam[2:]) // 8))
        sig = _hmac(fam, secret, si); vkey = secret; algs = [fam]
    elif fam == "RS256":
        sig = ISSUER_RSA.sign(si, padding.PKCS1v15(), hashes.SHA256()); vkey = PUB_PEM; algs = [fam]
    elif fam == "ES256":
        k = ec.generate_private_key(ec.SECP256R1())
        r, s = decode_dss_signature(k.sign(si, ec.ECDSA(hashes.SHA256())))
        sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        vkey = k.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo); algs = [fam]
    else:  # EdDSA
        k = ed25519.Ed25519PrivateKey.generate(); sig = k.sign(si)
        vkey = k.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo); algs = [fam]
    token = f"{h}.{p}.{op.b64url(sig)}"
    truth = TokenTruth(honestly_issued=True, legit_role=LEGIT_ROLE)
    return dict(token=token, vkey=vkey, algs=algs, truth=truth, fmt="compact",
                cls=f"honest/{fam}")


def attack_token(rng):
    """attacker random forgery — শুধু হাতের material দিয়ে (DY-সীমা)।"""
    kind = rng.choice(["alg_none", "confusion", "wrong_key", "wrong_rsa", "format_confusion"])
    payload = {"role": ATTACK_ROLE, "iss": "real-issuer"}
    truth = TokenTruth(honestly_issued=False, legit_role=LEGIT_ROLE, attack_role=ATTACK_ROLE)
    header = {"alg": "HS256", "typ": "JWT"}
    if rng.random() < 0.3:
        header["kid"] = rng.choice(["k1", "attacker", "../../etc"])
    if rng.random() < 0.2:
        header["crit"] = ["exp"]                                   # RFC-বৈধ কিন্তু বিরল

    if kind == "alg_none":
        header["alg"] = "none"
        h, p = _b(header), _b(payload)
        return dict(token=f"{h}.{p}.", vkey=PUB_PEM, algs=["RS256", "HS256"],
                    truth=truth, fmt="compact", cls="attack/alg_none")
    if kind == "confusion":                                        # pubkey → HMAC secret
        h, p = _b(header), _b(payload); si = f"{h}.{p}".encode()
        sig = _hmac("HS256", PUB_PEM, si)
        return dict(token=f"{h}.{p}.{op.b64url(sig)}", vkey=PUB_PEM, algs=["RS256", "HS256"],
                    truth=truth, fmt="compact", cls="attack/confusion")
    if kind == "wrong_key":                                        # attacker-এর নিজের secret
        h, p = _b(header), _b(payload); si = f"{h}.{p}".encode()
        sig = _hmac("HS256", ATTACKER_SECRET, si)
        return dict(token=f"{h}.{p}.{op.b64url(sig)}", vkey=ISSUER_SECRET, algs=["HS256"],
                    truth=truth, fmt="compact", cls="attack/wrong_key")
    if kind == "wrong_rsa":                                        # attacker-এর নিজের RSA
        a = rsa.generate_private_key(65537, 2048)
        header["alg"] = "RS256"; h, p = _b(header), _b(payload); si = f"{h}.{p}".encode()
        sig = a.sign(si, padding.PKCS1v15(), hashes.SHA256())
        return dict(token=f"{h}.{p}.{op.b64url(sig)}", vkey=PUB_PEM, algs=["RS256"],
                    truth=truth, fmt="compact", cls="attack/wrong_rsa")
    # format_confusion: signature আসল user-payload-এ, জাল admin unsigned field-এ
    real_payload = {"role": LEGIT_ROLE, "iss": "real-issuer"}
    header["alg"] = "HS256"; h, p = _b(header), _b(real_payload); si = f"{h}.{p}".encode()
    real_sig = _hmac("HS256", ISSUER_SECRET, si)
    tok = op.fn_json_with_extra(header, real_payload, real_sig, "fakeiss", {"role": ATTACK_ROLE})
    return dict(token=tok, vkey=ISSUER_SECRET, algs=["HS256"], truth=truth,
                fmt="json", cls="attack/format_confusion")


def run_targets(item):
    """compact হলে ৪ real lib + VULN/SAFE; json হলে FORMAT target।"""
    if item["fmt"] == "json":
        return [verify_FORMAT_CONFUSED(item["token"], item["vkey"]),
                verify_FORMAT_SAFE(item["token"], item["vkey"])]
    real = verify_all(item["token"], item["vkey"], item["algs"])
    return real + [verify_VULN(item["token"], item["vkey"], item["algs"]),
                   verify_SAFE(item["token"], item["vkey"], item["algs"])]


REAL_LIBS = {"PyJWT", "python-jose", "Authlib", "jwcrypto"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-n", type=int, default=2000); ap.add_argument("--seed", type=int, default=1337)
    args = ap.parse_args()
    rng = random.Random(args.seed)

    base = honest_token(random.Random(0))
    baseline = measure_baseline(base["token"], base["vkey"], base["algs"])

    fp_real = 0                       # provenance oracle A on a hardened real library (bug!)
    tp_vuln = 0                       # provenance oracle A on VULN-target for attack tokens
    attack_seen = 0
    real_lib_A = 0                    # any real-lib genuine A (would be a real finding)
    cls_hit = {}
    fp_examples = []

    for i in range(args.n):
        item = attack_token(rng) if rng.random() < 0.5 else honest_token(rng)
        cls_hit[item["cls"]] = cls_hit.get(item["cls"], 0) + 1
        results = run_targets(item)
        for r in results:
            j = judge_truth(r, item["truth"], baseline)
            if j.klass == "A":
                if r.library in REAL_LIBS:
                    if item["truth"].honestly_issued:
                        fp_real += 1
                        if len(fp_examples) < 5: fp_examples.append((item["cls"], r.library, r.error[:40]))
                    else:
                        real_lib_A += 1          # forged token genuinely accepted by real lib
                elif r.library == "VULN-target" or r.library == "FMT-CONFUSED":
                    if not item["truth"].honestly_issued:
                        tp_vuln += 1
        if not item["truth"].honestly_issued:
            attack_seen += 1

    print("=" * 72)
    print(f"Random mutation-chain fuzzing — N={args.n}, seed={args.seed}")
    print("=" * 72)
    print(f"  iterations: {args.n}  (attack {attack_seen}, honest {args.n - attack_seen})")
    print(f"  provenance-oracle false positives on hardened real libraries: {fp_real}")
    print(f"  genuine class-A on a real library (would be a real bug):       {real_lib_A}")
    print(f"  true-positive detections on controlled vulnerable target:     {tp_vuln}")
    print("  attack/honest class coverage reached:")
    for c in sorted(cls_hit): print(f"      {c:26} {cls_hit[c]}")
    if fp_examples:
        print("  ⚠️ false-positive examples (oracle bug — investigate):")
        for c, lib, e in fp_examples: print(f"      {c} {lib}: {e}")
    print("-" * 72)
    ok = (fp_real == 0)
    print(f"→ {'✅' if ok else '❌'} provenance oracle: {fp_real} false positive across "
          f"{args.n} random iterations; VULN-target true positives={tp_vuln}.")
    if real_lib_A:
        print(f"   NB: {real_lib_A} forged token(s) accepted by a REAL library — investigate (possible real finding).")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
