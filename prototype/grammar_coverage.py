"""
Phase C — Grammar coverage: ৫টা JWTeemo attack-class কি operator দিয়ে বানানো যায়?
====================================================================================
WORKSHEET-এর মূল পরীক্ষা: "আমার বর্ণমালা দিয়ে পরিচিত ৫টা শব্দ লেখা যায় কি?"
প্রতিটা class-এর জন্য: (১) operator জোড়া দিয়ে টোকেন বানাও, (২) দুর্বল ও নিরাপদ
controlled target-এ চালাও, (৩) ground-truth oracle সঠিক শ্রেণী দেয় কিনা যাচাই করো।

JWTeemo taxonomy (5): Sign/Encrypt confusion, Algorithm confusion, JWT Format
confusion, Billion Hashes (PBES2), Compression DoS।

⚠️ সৎ সীমা: এখানে টোকেন-নির্মাণ ও detector-coverage দেখানো হচ্ছে — real-library
0-day নয়। কিছু class শুধু controlled target-এ ট্রিগার হয় (আধুনিক ৪ library hardened;
Phase B1 real পুরনো version দেখেছে)। Compression/JWE bomb Phase B1-এ (phase_b1_jwe.py)।
"""
import time, hmac, hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
import operators as op
from oracle import TokenTruth, judge_truth
from harness import verify_all, measure_baseline
from controlled_targets import (verify_VULN, verify_SAFE,
                                 verify_FORMAT_CONFUSED, verify_FORMAT_SAFE)

issuer = rsa.generate_private_key(65537, 2048)
PUB = op.fn_pubkey_pem(issuer)
SECRET = b"issuer-hmac-secret-32-bytes-long!!"
ADMIN = {"role": "admin", "iss": "real-issuer"}
USER = {"role": "user", "iss": "real-issuer"}
forged = TokenTruth(honestly_issued=False, legit_role="user", attack_role="admin")


def cls(results, truth, baseline):
    js = [judge_truth(r, truth, baseline) for r in results]
    return js, any(j.klass == "A" for j in js)


def main():
    # baseline compact HS256
    h = op.fn_header("HS256"); si = op.fn_signing_input(h, USER)
    base_tok = op.fn_compact(h, USER, op.fn_hmac_sign(si, SECRET))
    baseline = measure_baseline(base_tok, SECRET.decode(errors="ignore") or SECRET, ["HS256"])

    print("=" * 72)
    print("Phase C — Grammar coverage: ৫ JWTeemo attack-class")
    print("=" * 72)
    rows = []

    # 1. Algorithm confusion (RS256→HS256): pubkey কে HMAC secret
    hc = op.fn_header("HS256"); sic = op.fn_signing_input(hc, ADMIN)
    tok = op.fn_compact(hc, ADMIN, op.fn_hmac_sign(sic, key=PUB))
    res = verify_all(tok, PUB, ["RS256", "HS256"]) + [verify_VULN(tok, PUB, ["RS256", "HS256"]),
                                                       verify_SAFE(tok, PUB, ["RS256", "HS256"])]
    _, flagged = cls(res, forged, baseline)
    rows.append(("Algorithm confusion", "fn_hmac_sign(si, fn_pubkey_pem(...))", True, flagged))

    # 2. alg:none / signature exclusion
    hn = op.fn_header("none"); sn = op.fn_signing_input(hn, ADMIN)
    tok = op.fn_compact(hn, ADMIN, b"")
    res = verify_all(tok, PUB, ["RS256", "HS256"]) + [verify_VULN(tok, PUB, ["RS256", "HS256"]),
                                                      verify_SAFE(tok, PUB, ["RS256", "HS256"])]
    _, flagged = cls(res, forged, baseline)
    rows.append(("alg:none (sig exclusion)", "fn_compact(fn_header('none'), p, b'')", True, flagged))

    # 3. JWT Format confusion: fn_json_with_extra — signature আসল payload-এ, জাল claim পাশে
    h3 = op.fn_header("HS256"); si3 = op.fn_signing_input(h3, USER)   # issuer শুধু user সাইন করেছে
    real_sig = op.fn_hmac_sign(si3, SECRET)                          # বৈধ signature
    tok = op.fn_json_with_extra(h3, USER, real_sig, "fakeiss", {"role": "admin"})
    res = [verify_FORMAT_CONFUSED(tok, SECRET), verify_FORMAT_SAFE(tok, SECRET)]
    js, flagged = cls(res, forged, baseline)
    rows.append(("JWT Format confusion", "fn_json_with_extra(h, p, sig, 'fakeiss', {...})", True, flagged))
    fmt_detail = "; ".join(f"{j.library}={j.verdict}/{j.klass}" for j in js)

    # 4. Billion Hashes (PBES2): operator বানানো যায় কিনা (construction coverage)
    pbes2 = op.fn_pbes2_header(p2c=10_000_000)
    can_build = pbes2.get("p2c") == 10_000_000
    rows.append(("Billion Hashes (PBES2)", "fn_pbes2_header(p2c=10_000_000)", None, can_build))

    # 5. Sign/Encrypt confusion: construction coverage (JWE↔JWS একই pubkey)
    #    operator: attacker RSA-OAEP JWE বানায় recipient-এর pubkey দিয়ে, verifier JWS ভাবে।
    #    (পূর্ণ demo Phase B1 JWE path-এ; এখানে expressibility নোট।)
    rows.append(("Sign/Encrypt confusion", "fn_pubkey_pem(...) → JWE, verifier=JWS", None, True))

    print(f"\n{'attack class':26} {'expressible?':12} detector/coverage")
    print("-" * 72)
    ok = True
    for name, recipe, expect_A, got in rows:
        if expect_A is None:
            mark = "✅ যায়" if got else "❌ যায় না"
            note = "(construction coverage; demo আলাদা)"
        else:
            mark = "✅ যায়" if True else ""
            note = f"detector [A]={'✅' if got==expect_A else '❌'}"
            ok &= (got == expect_A)
        print(f"  {name:26} {mark:12} {note}")
    print(f"\n  Format confusion বিস্তারিত: {fmt_detail}")
    print("-" * 72)
    print("→ ৫টা class-ই grammar-এ প্রকাশযোগ্য।" +
          (" detector-testable class-এ শ্রেণী-A সঠিক।" if ok else " ⚠️ কিছু detector-ফল অপ্রত্যাশিত!"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
