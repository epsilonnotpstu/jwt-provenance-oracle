"""
প্রথম পূর্ণ Fuzzer (ছোট, DY-model-guided)
==========================================
loop: seed → mutation → operator দিয়ে token বানাও → ৪ library-তে চালাও
      → oracle A/B/C শ্রেণীতে ফেলো → রিপোর্ট।
"""
from cryptography.hazmat.primitives.asymmetric import rsa
import operators as op
import mutations as mut
from mutations import Recipe, build_token
from harness import verify_all, measure_baseline
from oracle import GroundTruth, judge, summarize

# ── key উপকরণ ──
issuer_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# Issuer-এর সব চাবি — শুধু বৈধ seed বানাতে (honest issuer)
ISSUER_KEYS = {
    "issuer_secret":      b"issuer-hmac-secret-32-bytes-long!!",   # 33 বাইট
    "issuer_priv":        issuer_priv,
    "issuer_pubkey_pem":  op.fn_pubkey_pem(issuer_priv),
}

# ⚠️ DY সীমা: attacker যা যা পায় — issuer-এর secret/private কখনো নয়।
#   issuer_secret / issuer_priv এখানে ইচ্ছাকৃতভাবে অনুপস্থিত।
ATTACKER_KEYS = {
    "attacker_secret":    b"attacker-knows-only-this-secret!!",
    "issuer_pubkey_pem":  op.fn_pubkey_pem(issuer_priv),   # public — প্রকাশ্য
}

# ── SEED (#৪): Issuer বৈধভাবে HS256 দিয়ে role=user সাইন করল ──
seed = Recipe(alg="HS256", role="user", sign_key_kind="issuer_secret", label="seed")

# ── GroundTruth: issuer আসলে কী সাইন করেছিল ──
gt = GroundTruth(legit_role="user", attack_role="admin")

# ── দুটো verifier config (২২ সেপ্টে ঠিক করা) ──
#   আগে একটাই config ছিল: VERIFY_KEY = issuer HMAC secret। কিন্তু Algorithm
#   Confusion-এর পূর্বশর্ত হলো verifier *RSA public key* ধরে আছে। HMAC secret ধরা
#   verifier-এ confusion token REJECT হওয়া অনিবার্য — ওই test কিছুই মাপছিল না।
#   এখন প্রতিটা mutant তার প্রাসঙ্গিক config-এ চলে।
CONFIGS = {
    "HMAC": dict(seed=seed, key=ISSUER_KEYS["issuer_secret"], algs=["HS256"]),
    # RSA verifier, misconfig: HS256-ও allow-list-এ (confusion-এর দরজা)
    "RSA":  dict(seed=Recipe(alg="RS256", role="user", sign_key_kind="issuer_private_rsa", label="seed"),
                 key=ISSUER_KEYS["issuer_pubkey_pem"], algs=["RS256", "HS256"]),
}

# ── baseline: প্রতিটা config-এ বৈধ seed-এর median সময় ──
for cfg in CONFIGS.values():
    tok = build_token(cfg["seed"], ISSUER_KEYS)
    cfg["baseline_sec"] = measure_baseline(tok, cfg["key"], cfg["algs"])

# ── mutation তালিকা: (নাম, config, recipe) ──
hs, rs = CONFIGS["HMAC"]["seed"], CONFIGS["RSA"]["seed"]
mutants = [
    ("বৈধ seed (control, HMAC)",  "HMAC", hs),
    ("বৈধ seed (control, RSA)",   "RSA",  rs),
    ("alg:none (signature বাদ)",  "HMAC", mut.mut_drop_signature(mut.mut_escalate_role(hs))),
    ("role escalate, একই key",    "HMAC", mut.mut_escalate_role(hs)),
    ("attacker-এর নিজের secret",  "HMAC", mut.mut_replace_key(mut.mut_escalate_role(hs), "attacker_secret")),
    ("Algorithm Confusion",       "RSA",  mut.mut_replace_key(mut.mut_replace_alg(mut.mut_escalate_role(rs), "HS256"), "issuer_pubkey")),
]

print("=" * 70)
print(f"DY-guided JWT Fuzzer — ৪ library, {len(mutants)} mutation, ২ verifier config")
print("=" * 70)

for name, cfg_name, recipe in mutants:
    cfg = CONFIGS[cfg_name]
    # seed (control) issuer বানায়; বাকি সব attacker বানায় (DY সীমা প্রয়োগ)
    keys = ISSUER_KEYS if recipe.label == "seed" else ATTACKER_KEYS
    try:
        token = build_token(recipe, keys)
    except (KeyError, ValueError):
        print(f"\n▶ {name}")
        print(f"    ⊘ attacker-এর পক্ষে অসম্ভব (issuer-এর চাবি লাগে) — DY সীমা")
        continue

    results = verify_all(token, cfg["key"], cfg["algs"])
    judgments = [judge(r, gt, cfg["baseline_sec"]) for r in results]
    verdict_line = summarize(judgments)   # klass সেট করে

    print(f"\n▶ {name}   [verifier={cfg_name}, algs={cfg['algs']}]")
    for j in judgments:
        tag = f"[{j.klass}]" if j.klass not in ("-", "OK") else "   "
        print(f"    {tag} {j.library:12} {j.verdict:7} {j.note}")
    print(f"    → {verdict_line}")

print("\n" + "=" * 70)
print("শেষ। শ্রেণী-A = যাচাই-যোগ্য lead; C = false-positive (স্বয়ংক্রিয় ছাঁকা)।")
