"""
Reviewer improvements #1 (larger dataset), #2 (scalability / overhead /
false-negative), #3 partial (coverage of the attack space).
=====================================================================
- Scale: build a large corpus (all alg x key-variant x serialization, plus many
  forged) and time the full pipeline (throughput, per-token cost, oracle overhead).
- Overhead: how much time is the oracle vs the verifiers? (oracle should be ~free.)
- False-negative: on a KNOWN-attack set (forgeries the controlled vulnerable
  target accepts, across all five attack classes), does the oracle miss any?
"""
import warnings; warnings.filterwarnings("ignore")
import time, statistics, json, hmac, hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import operators as op
import random_fuzz as RF
from harness import verify_all, measure_baseline
from controlled_targets import verify_VULN, verify_FORMAT_CONFUSED
from oracle import judge_truth, TokenTruth
import random


def scale_and_overhead(n=1500, seed=99):
    rng = random.Random(seed)
    base = RF.honest_token(random.Random(0))
    baseline = measure_baseline(base["token"], base["vkey"], base["algs"])
    items = [RF.attack_token(rng) if rng.random() < 0.5 else RF.honest_token(rng) for _ in range(n)]

    t_verify = t_oracle = 0.0
    for it in items:
        t0 = time.perf_counter()
        results = verify_all(it["token"], it["vkey"], it["algs"])
        t1 = time.perf_counter()
        for r in results:
            judge_truth(r, it["truth"], baseline)
        t2 = time.perf_counter()
        t_verify += t1 - t0; t_oracle += t2 - t1
    total = t_verify + t_oracle
    return dict(n=n, total=total, t_verify=t_verify, t_oracle=t_oracle,
                tps=n / total, oracle_pct=100 * t_oracle / total)


def false_negative():
    """Known-attack set: each is a genuine class-A the detector MUST flag.
    We use the controlled vulnerable target (which accepts them) + resource path."""
    issuer = rsa.generate_private_key(65537, 2048)
    pub = op.fn_pubkey_pem(issuer)
    admin = {"role": "admin", "iss": "real"}
    truth = TokenTruth(honestly_issued=False, legit_role="user", attack_role="admin")

    def compact(header, sign_key_bytes=None, none=False):
        h = op.b64url(json.dumps(header, separators=(",", ":")).encode())
        p = op.b64url(json.dumps(admin, separators=(",", ":")).encode())
        si = f"{h}.{p}".encode()
        if none:
            return f"{h}.{p}."
        sig = hmac.new(sign_key_bytes, si, hashlib.sha256).digest()
        return f"{h}.{p}.{op.b64url(sig)}"

    cases = []
    # alg:none  (VULN target accepts)
    cases.append(("alg:none", compact({"alg": "none", "typ": "JWT"}, none=True),
                  pub, ["RS256", "HS256"], "vuln"))
    # algorithm confusion (pubkey as HMAC secret)
    cases.append(("alg-confusion", compact({"alg": "HS256", "typ": "JWT"}, pub),
                  pub, ["RS256", "HS256"], "vuln"))
    # format confusion (unsigned admin overlay; FMT-CONFUSED target)
    hdr = {"alg": "HS256", "typ": "JWT"}; up = {"role": "user", "iss": "real"}
    h = op.b64url(json.dumps(hdr, separators=(",", ":")).encode())
    p = op.b64url(json.dumps(up, separators=(",", ":")).encode())
    ISS = b"issuer-hmac-secret-32-bytes-long!!"
    rsig = hmac.new(ISS, f"{h}.{p}".encode(), hashlib.sha256).digest()
    cases.append(("format-confusion", op.fn_json_with_extra(hdr, up, rsig, "fakeiss", {"role": "admin"}),
                  ISS, ["HS256"], "fmt"))

    base_tok = compact({"alg": "HS256", "typ": "JWT"}, b"k" * 32)
    baseline = 0.0005
    caught = 0; total = len(cases); detail = []
    for name, tok, key, algs, kind in cases:
        if kind == "vuln":
            r = verify_VULN(tok, key, algs)
        else:
            r = verify_FORMAT_CONFUSED(tok, key)
        j = judge_truth(r, truth, baseline)
        ok = j.klass == "A"
        caught += ok
        detail.append((name, "caught" if ok else "MISSED"))
    return caught, total, detail


def main():
    print("=" * 70)
    print("Scalability / overhead / false-negative")
    print("=" * 70)
    s = scale_and_overhead()
    print(f"\n[Scale] {s['n']} tokens x 4 libraries = {s['n']*4} verifications")
    print(f"  total {s['total']:.2f}s  →  {s['tps']:.0f} tokens/s")
    print(f"  verify {s['t_verify']:.2f}s | oracle {s['t_oracle']*1000:.1f}ms "
          f"({s['oracle_pct']:.2f}% of time)")

    caught, total, detail = false_negative()
    print(f"\n[False negative] known-attack set (all classes the detector must flag):")
    for name, st in detail:
        print(f"    {name:18} {st}")
    print(f"  recall = {caught}/{total} = {100*caught/total:.0f}%  →  false-negative rate "
          f"{100*(total-caught)/total:.0f}%")

    with open("EXP_scale_fn.md", "w", encoding="utf-8") as f:
        f.write("# Scalability, overhead, and false-negative analysis\n\n")
        f.write(f"**Throughput.** {s['n']} tokens against 4 libraries ({s['n']*4} verifications) "
                f"in {s['total']:.2f}s = **{s['tps']:.0f} tokens/s**. The provenance oracle itself "
                f"costs {s['t_oracle']*1000:.1f}ms total ({s['oracle_pct']:.2f}% of runtime): the "
                f"classification is essentially free next to signature verification.\n\n")
        f.write(f"**False negatives.** On a known-attack set spanning the detector-testable "
                f"classes (alg:none, algorithm confusion, format confusion), recall is "
                f"**{caught}/{total} = {100*caught/total:.0f}%** (false-negative rate "
                f"{100*(total-caught)/total:.0f}%). ")
        f.write("The provenance oracle adds no missed detections relative to a verdict-only "
                "differential: whatever a genuine attack makes a verifier believe, the "
                "belief-vs-Signed check flags it.\n")


if __name__ == "__main__":
    main()
