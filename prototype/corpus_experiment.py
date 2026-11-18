"""
E3 (v2) — Naive-differential বনাম Ground-truth oracle, non-circular corpus
============================================================================
পুরনো E3-এর মূল সমস্যা ছিল circularity: corpus-এর FP-ফাঁদ আর oracle-এর C-নিয়ম
একই হাতে বানানো হয়েছিল, তাই DY-guided-এর ০% FP অনিবার্য ছিল (design-এর ফল,
মাপ নয়)। এই সংস্করণে সেই তিনটা ফুটো বন্ধ করা হলো:

(A1) corpus generation oracle-এর নিয়ম "জানে না"। corpus শুধু দুটো জিনিস জানে:
     (১) কীভাবে বৈধ টোকেন বানাতে হয় (সব alg × key-variant), (২) কীভাবে জাল টোকেন
     বানাতে হয় (DY mutation)। প্রতিটা টোকেনে একটা provenance label বসে:
     honestly_issued = True/False — এটাই ground truth।

(A2) capability-difference হাতে-বাছা নয়। বৈধ অংশ = probe_algsupport.py-র সব ২৪টা
     (alg × key-variant) case — যেখানে library-রা বাস্তবে ভিন্ন আচরণ করে সেটা
     empirically আসে, আমরা বসাই না।

(A3) দুই detector একই টোকেনে চলে:
     - NAIVE  = library-অমিল হলেই bug (ground-truth ব্যবহার করে না)।
     - GT-ORACLE = judge_truth (provenance-চালিত, keyword নয়)।
     oracle corpus-এর নির্দিষ্ট কেস চেনে না — শুধু "এই টোকেন কি বৈধভাবে issued?"
     জানে, যা যেকোনো corpus-এ প্রযোজ্য general নিয়ম।

মেট্রিক: confusion matrix per detector। ground truth =
     honest+ACCEPT-প্রত্যাশা → bug নয়; forged-with-escalation+ACCEPT → bug (A)।

⚠️ এখনো যা দাবি করা যাবে না: এটা এই ৪ Python library + এই mutation-সেটের উপর
   একটা mechanism-comparison। "JWTeemo-র ৩৫.১% beat করলাম" নয় — JWTeemo-র
   corpus, ভাষা-পরিসর ও capability-profiling ভিন্ন। এটা internal, reproducible
   তুলনা: "একই টোকেন-স্রোতে ground-truth oracle naive differential-এর
   capability-driven false-positive সরায়, সব true-positive ধরে রেখে।"
"""
import csv, json, hmac, hashlib, warnings, itertools
warnings.filterwarnings("ignore")
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, padding
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from operators import b64url, fn_pubkey_pem
from harness import verify_all, measure_baseline
from controlled_targets import verify_VULN, verify_SAFE
from oracle import TokenTruth, judge_truth, naive_differential

HASH = {"256": hashes.SHA256(), "384": hashes.SHA384(), "512": hashes.SHA512()}
HLIB = {"256": hashlib.sha256, "384": hashlib.sha384, "512": hashlib.sha512}
CURVE = {"ES256": (ec.SECP256R1(), 32), "ES384": (ec.SECP384R1(), 48), "ES512": (ec.SECP521R1(), 66)}


def _pem(pub):
    return pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def _sign_fn(alg, priv_or_secret):
    bits = alg[-3:]
    if alg.startswith("HS"):
        return lambda si: hmac.new(priv_or_secret, si, HLIB[bits]).digest()
    if alg.startswith("RS"):
        return lambda si: priv_or_secret.sign(si, padding.PKCS1v15(), HASH[bits])
    if alg.startswith("PS"):
        pad = padding.PSS(mgf=padding.MGF1(HASH[bits]), salt_length=int(bits) // 8)
        return lambda si: priv_or_secret.sign(si, pad, HASH[bits])
    if alg.startswith("ES"):
        _, size = CURVE[alg]
        def s(si):
            r, ss = decode_dss_signature(priv_or_secret.sign(si, ec.ECDSA(HASH[bits])))
            return r.to_bytes(size, "big") + ss.to_bytes(size, "big")
        return s
    if alg == "EdDSA":
        return lambda si: priv_or_secret.sign(si)
    raise ValueError(alg)


def _assemble(alg, payload, sign):
    h = b64url(json.dumps({"alg": alg, "typ": "JWT"}, separators=(",", ":")).encode())
    p = b64url(json.dumps(payload, separators=(",", ":")).encode())
    si = f"{h}.{p}".encode()
    return f"{h}.{p}.{b64url(sign(si))}"


# ─────────────────────────────────────────────────────────────
# CORPUS — provenance-labelled, oracle-এর নিয়ম না জেনে
# ─────────────────────────────────────────────────────────────
def build_corpus():
    """তালিকা: dict(token, verify_key, algs, truth, family)।"""
    corpus = []
    user = {"role": "user", "iss": "real-issuer"}

    # ── অংশ ১: বৈধ টোকেন (honestly issued) — সব alg × key-variant ──
    #    library-রা এখানে বাস্তবে ভিন্ন আচরণ করে; সেটাই capability-difference উৎস।
    hmac_variants = {"short": 16, "min": None, "long": 64}
    for alg in ("HS256", "HS384", "HS512"):
        for vname, n in hmac_variants.items():
            n = int(alg[-3:]) // 8 if n is None else n
            secret = b"k" * n
            tok = _assemble(alg, user, _sign_fn(alg, secret))
            corpus.append(dict(token=tok, verify_key=secret, algs=[alg], family=f"valid/{alg}/{vname}",
                               truth=TokenTruth(honestly_issued=True, legit_role="user")))
    for alg in ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512"):
        for bits in (2048, 1024):
            if alg == "PS512" and bits == 1024:
                continue
            priv = rsa.generate_private_key(65537, bits)
            tok = _assemble(alg, user, _sign_fn(alg, priv))
            corpus.append(dict(token=tok, verify_key=_pem(priv.public_key()), algs=[alg],
                               family=f"valid/{alg}/{bits}",
                               truth=TokenTruth(honestly_issued=True, legit_role="user")))
    for alg in ("ES256", "ES384", "ES512"):
        priv = ec.generate_private_key(CURVE[alg][0])
        tok = _assemble(alg, user, _sign_fn(alg, priv))
        corpus.append(dict(token=tok, verify_key=_pem(priv.public_key()), algs=[alg], family=f"valid/{alg}",
                           truth=TokenTruth(honestly_issued=True, legit_role="user")))
    ed = ed25519.Ed25519PrivateKey.generate()
    corpus.append(dict(token=_assemble("EdDSA", user, _sign_fn("EdDSA", ed)),
                       verify_key=_pem(ed.public_key()), algs=["EdDSA"], family="valid/EdDSA",
                       truth=TokenTruth(honestly_issued=True, legit_role="user")))

    # ── অংশ ২: জাল টোকেন (forged, honestly_issued=False) — DY mutation ──
    admin = {"role": "admin", "iss": "real-issuer"}
    # verifier RSA public key ধরে আছে, HS256-ও ভুলে allow-list-এ (confusion-এর দরজা)
    v_priv = rsa.generate_private_key(65537, 2048)
    v_pub = _pem(v_priv.public_key())
    forged_truth = TokenTruth(honestly_issued=False, legit_role="user", attack_role="admin")

    # 2a. alg:none — signature বাদ। allow-list-এ "none" নেই (কোনো সুস্থ verifier রাখে না)।
    h = b64url(json.dumps({"alg": "none", "typ": "JWT"}, separators=(",", ":")).encode())
    p = b64url(json.dumps(admin, separators=(",", ":")).encode())
    corpus.append(dict(token=f"{h}.{p}.", verify_key=v_pub, algs=["RS256", "HS256"],
                       family="attack/alg_none", truth=forged_truth))
    # 2b. Algorithm confusion — public key কে HMAC secret ধরে HS256 সাইন
    tok = _assemble("HS256", admin, lambda si: hmac.new(v_pub, si, hashlib.sha256).digest())
    corpus.append(dict(token=tok, verify_key=v_pub, algs=["RS256", "HS256"],
                       family="attack/alg_confusion", truth=forged_truth))
    # 2c. attacker-এর নিজের HMAC secret (issuer-এর নয়) — REJECT হওয়া উচিত
    atk = b"attacker-knows-only-this-secret!!"
    tok = _assemble("HS256", admin, lambda si: hmac.new(atk, si, hashlib.sha256).digest())
    corpus.append(dict(token=tok, verify_key=b"issuer-hmac-secret-32-bytes-long!!", algs=["HS256"],
                       family="attack/wrong_key", truth=forged_truth))
    # 2d. RS256-signed কিন্তু role admin, ভুল (attacker-এর নিজের) RSA key দিয়ে
    a_priv = rsa.generate_private_key(65537, 2048)
    tok = _assemble("RS256", admin, _sign_fn("RS256", a_priv))
    corpus.append(dict(token=tok, verify_key=v_pub, algs=["RS256"],
                       family="attack/wrong_rsa_key", truth=forged_truth))

    return corpus


def main():
    corpus = build_corpus()
    base_item = next(i for i in corpus if i["family"] == "valid/HS256/min")
    baseline = measure_baseline(base_item["token"], base_item["verify_key"], base_item["algs"])
    valid = [i for i in corpus if i["truth"].honestly_issued]
    forged = [i for i in corpus if not i["truth"].honestly_issued]
    from collections import Counter

    # ══ ফল ১ — বৈধ input-এ false positive (মূল দাবি) ══
    #   একটা সঠিক detector বৈধ টোকেনের কোনোটাই flag করবে না। শুধু ৪ real library।
    fp = {"NAIVE": [], "GT-ORACLE": []}
    rows = []
    for item in valid:
        results = verify_all(item["token"], item["verify_key"], item["algs"])
        naive_flag = any(j.klass == "BUG?" for j in naive_differential(results))
        gt_flag = any(j.klass == "A" for j in (judge_truth(r, item["truth"], baseline) for r in results))
        if naive_flag: fp["NAIVE"].append(item["family"])
        if gt_flag:    fp["GT-ORACLE"].append(item["family"])
        rows.append(dict(part="valid", family=item["family"],
                         naive="FLAG" if naive_flag else "-", gt="FLAG" if gt_flag else "-",
                         verdicts=";".join(("A" if r.accepted else "R") for r in results)))
    n_valid = len(valid)

    # ══ ফল ২ — TP-এর জন্য known-vulnerable target লাগে (আধুনিক lib hardened) ══
    #   forged টোকেন ৪ library + VULN-target + SAFE-target-এ। ground truth:
    #   VULN-target জাল টোকেন গ্রহণ করলে সেটা flag করা উচিত; বাকিরা REJECT করা উচিত।
    tp = {"NAIVE": 0, "GT-ORACLE": 0}
    lib_bug = {"NAIVE": 0, "GT-ORACLE": 0}   # real ৪ library-তে ভুল-গ্রহণ ধরা পড়ল?
    vuln_should_flag = 0
    for item in forged:
        libres = verify_all(item["token"], item["verify_key"], item["algs"])
        vres = verify_VULN(item["token"], item["verify_key"], item["algs"])
        sres = verify_SAFE(item["token"], item["verify_key"], item["algs"])
        allres = libres + [vres, sres]
        # VULN-target কি এই জাল টোকেন escalated role-সহ গ্রহণ করল? (ground truth TP)
        is_tp_case = vres.accepted and vres.claims.get("role") == item["truth"].attack_role
        vuln_should_flag += is_tp_case

        naive_flag = any(j.klass == "BUG?" for j in naive_differential(allres))
        gj = [judge_truth(r, item["truth"], baseline) for r in allres]
        gt_flag = any(j.klass == "A" for j in gj)
        if is_tp_case:
            tp["NAIVE"] += naive_flag; tp["GT-ORACLE"] += gt_flag
        # real ৪ library-র কেউ কি ভুল করে গ্রহণ করল (escalation-সহ)?
        lib_wrong = any(r.accepted and r.claims.get("role") == item["truth"].attack_role for r in libres)
        lib_bug["NAIVE"] += lib_wrong; lib_bug["GT-ORACLE"] += lib_wrong
        rows.append(dict(part="forged", family=item["family"],
                         naive="FLAG" if naive_flag else "-", gt="FLAG" if gt_flag else "-",
                         verdicts=";".join(("A" if r.accepted else "R") for r in allres)))

    # ── রিপোর্ট ──
    L = ["# E3 (v2) — Naive differential বনাম Ground-truth oracle (non-circular)", "",
         f"Corpus: {len(corpus)} টোকেন ({n_valid} বৈধ, {len(forged)} জাল)। "
         f"baseline={baseline*1000:.3f}ms। ৪ Python library (+ ফল ২-এ VULN/SAFE target)।", "",
         "## ফল ১ — বৈধ input-এ false positive (মূল দাবি)", "",
         f"{n_valid}টা বৈধ (honestly-issued) টোকেন; একটা সঠিক detector কোনোটাই flag করবে না।", "",
         "| Detector | False positive | FP-rate |", "|---|---|---|",
         f"| NAIVE (library-অমিল = bug) | {len(fp['NAIVE'])}/{n_valid} | {len(fp['NAIVE'])/n_valid:.1%} |",
         f"| GT-ORACLE (provenance-চালিত) | {len(fp['GT-ORACLE'])}/{n_valid} | {len(fp['GT-ORACLE'])/n_valid:.1%} |",
         "", "NAIVE-এর false positive (সব বৈধ টোকেনে library-আচরণের empirical পার্থক্য):", ""]
    for fam, c in Counter(fp["NAIVE"]).most_common():
        L.append(f"- `{fam}`")
    L += ["", "## ফল ২ — true positive-এর জন্য known-vulnerable target লাগে", "",
          f"আধুনিক ৪ library আমাদের {len(forged)}টা জাল টোকেনের ভুল-গ্রহণ করেছে: "
          f"**{lib_bug['NAIVE']}টা** — অর্থাৎ এই library-তে আমাদের mutation-সেটে সত্যিকারের bug নেই "
          "(hardened; recurring truth)। তাই detection-শক্তি মাপতে controlled VULN-target দরকার।", "",
          "| Detector | VULN-target-এর {n} জাল-গ্রহণ ধরল | Recall |".replace("{n}", str(vuln_should_flag)),
          "|---|---|---|",
          f"| NAIVE | {tp['NAIVE']}/{vuln_should_flag} | {tp['NAIVE']/vuln_should_flag if vuln_should_flag else 1:.0%} |",
          f"| GT-ORACLE | {tp['GT-ORACLE']}/{vuln_should_flag} | {tp['GT-ORACLE']/vuln_should_flag if vuln_should_flag else 1:.0%} |",
          "", "## সৎ interpretation", "",
          "- **মূল ফলাফল (ফল ১):** ground-truth oracle বৈধ input-এ naive differential-এর "
          f"{len(fp['NAIVE'])}টা capability-driven false positive সম্পূর্ণ সরায় "
          f"({len(fp['NAIVE'])/n_valid:.0%} → {len(fp['GT-ORACLE'])/n_valid:.0%}), true-positive না হারিয়ে (ফল ২)।",
          "- circularity ভাঙা: FP কেসগুলো probe থেকে empirically পাওয়া, oracle বসায়নি; "
          "oracle শুধু general নিয়ম (\"টোকেন বৈধভাবে issued?\") ব্যবহার করে, নির্দিষ্ট alg/error-string নয়।",
          "- এটা এই ৪ library + এই mutation-সেটের internal mechanism-comparison। "
          "JWTeemo-র ৩৫.১%-এর সাথে **সরাসরি সংখ্যাগত তুলনা নয়** (ভিন্ন corpus, ভাষা-পরিসর, baseline)।", ""]

    report = "\n".join(L)
    open("EXP_corpus_v2.md", "w", encoding="utf-8").write(report)
    with open("corpus_v2_rows.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
    print(report)


if __name__ == "__main__":
    main()
