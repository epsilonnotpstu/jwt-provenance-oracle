"""
E2 — True-positive যাচাই: ৪ library + controlled VULN/SAFE target
===================================================================
(২২ সেপ্টে পুনর্গঠিত — আগের ফাইলটা এই folder-এ ছিল না।)

প্রশ্ন: oracle কি সত্যিকারের দুর্বলতা ধরতে পারে (VULN-target-এ শ্রেণী-A),
        এবং নিরাপদ verifier-এ মিথ্যা alarm দেয় না (SAFE-target + library-তে REJECT)?

প্রত্যাশা (ground truth, construction থেকে):
  - VULN-target: alg:none ও Algorithm Confusion-এ ACCEPT → [A]
  - VULN-target: attacker-এর নিজের secret → REJECT (oracle অন্ধভাবে A বলে না)
  - SAFE-target ও ৪ library: সব আক্রমণে REJECT

⚠️ সীমা: VULN-target আমাদের নিজের বানানো। এখানে [A] = detector-এর sanity check,
   "real vulnerability discovery" নয়।
"""
from cryptography.hazmat.primitives.asymmetric import rsa
import operators as op
import mutations as mut
from mutations import Recipe, build_token
from harness import verify_all, measure_baseline
from controlled_targets import verify_VULN, verify_SAFE
from oracle import GroundTruth, judge, summarize

issuer_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ISSUER_KEYS = {
    "issuer_secret":     b"issuer-hmac-secret-32-bytes-long!!",
    "issuer_priv":       issuer_priv,
    "issuer_pubkey_pem": op.fn_pubkey_pem(issuer_priv),
}
ATTACKER_KEYS = {                                   # DY সীমা: issuer-এর গোপন কিছু নেই
    "attacker_secret":   b"attacker-knows-only-this-secret!!",
    "issuer_pubkey_pem": op.fn_pubkey_pem(issuer_priv),
}
gt = GroundTruth(legit_role="user", attack_role="admin")

HS_SEED = Recipe(alg="HS256", role="user", sign_key_kind="issuer_secret", label="seed")
RS_SEED = Recipe(alg="RS256", role="user", sign_key_kind="issuer_private_rsa", label="seed")
CONFIGS = {
    "HMAC": dict(seed=HS_SEED, key=ISSUER_KEYS["issuer_secret"], algs=["HS256"]),
    "RSA":  dict(seed=RS_SEED, key=ISSUER_KEYS["issuer_pubkey_pem"], algs=["RS256", "HS256"]),
}

# (নাম, config, recipe, প্রত্যাশিত VULN-ফল) — প্রত্যাশা আগে থেকে লেখা, ফল দেখার আগে
MUTANTS = [
    ("বৈধ seed (HMAC)",          "HMAC", HS_SEED, "ACCEPT"),
    ("বৈধ seed (RSA)",           "RSA",  RS_SEED, "ACCEPT"),
    ("alg:none + escalate",      "HMAC", mut.mut_drop_signature(mut.mut_escalate_role(HS_SEED)), "A"),
    ("attacker-এর নিজের secret", "HMAC", mut.mut_replace_key(mut.mut_escalate_role(HS_SEED), "attacker_secret"), "REJECT"),
    ("Algorithm Confusion",      "RSA",  mut.mut_replace_key(mut.mut_replace_alg(mut.mut_escalate_role(RS_SEED), "HS256"), "issuer_pubkey"), "A"),
]


def run_all(token, key, algs):
    return verify_all(token, key, algs) + [verify_VULN(token, key, algs), verify_SAFE(token, key, algs)]


def main():
    for cfg in CONFIGS.values():
        cfg["baseline_sec"] = measure_baseline(build_token(cfg["seed"], ISSUER_KEYS), cfg["key"], cfg["algs"])

    print("=" * 72)
    print("E2 — True-positive যাচাই (৪ library + VULN/SAFE controlled target)")
    print("=" * 72)
    mismatches = 0
    for name, cfg_name, recipe, expect_vuln in MUTANTS:
        cfg = CONFIGS[cfg_name]
        keys = ISSUER_KEYS if recipe.label == "seed" else ATTACKER_KEYS
        token = build_token(recipe, keys)
        judgments = [judge(r, gt, cfg["baseline_sec"]) for r in run_all(token, cfg["key"], cfg["algs"])]
        line = summarize(judgments)

        print(f"\n▶ {name}   [verifier={cfg_name}]")
        for j in judgments:
            tag = f"[{j.klass}]" if j.klass not in ("-", "OK") else "   "
            print(f"    {tag} {j.library:12} {j.verdict:7} {j.note}")
        print(f"    → {line}")

        # প্রত্যাশা বনাম ফল
        vuln = next(j for j in judgments if j.library == "VULN-target")
        got_vuln = "A" if vuln.klass == "A" else vuln.verdict
        others_ok = all(j.klass != "A" for j in judgments if j.library != "VULN-target")
        ok = (got_vuln == expect_vuln) and others_ok
        mismatches += not ok
        print(f"    প্রত্যাশা VULN={expect_vuln}, পেলাম={got_vuln}; অন্যদের কেউ A নয়={others_ok} → {'✅' if ok else '❌'}")

    print("\n" + "=" * 72)
    print(f"প্রত্যাশার সাথে অমিল: {mismatches}/{len(MUTANTS)}")
    return mismatches


if __name__ == "__main__":
    raise SystemExit(main())
