"""Resource oracle v2 — PREREG_resource.md অনুযায়ী মূল্যায়ন (corpus_r-এ)।
ধাপ: (১) মূল রান, (২) baseline = V1 seed-1 × R_b, (৩) screening (> T·B), (৪) candidate × R_c confirmation,
(৫) SLOW ⇔ median > T·B এবং median − B > F, (৬) R1/R2 + v1 তুলনা, (৭) positive control (R3)।
ব্যবহার: python resource_v2.py   (আগে থেকে থাকা ধাপের ফল থাকলে সেটা আবার চালায় না; --fresh দিলে সব নতুন)"""
import hashlib, hmac, json, statistics, subprocess, sys, time
from collections import defaultdict
from pathlib import Path

import judge
from oracle import TokenTruth, judge_truth

D = judge.D
CR, RR = D / "corpus_r", D / "results_r"
T, R_B, R_C, F_NS = 20, 15, 15, 1_000_000
PRIMARY = json.loads((D / "results/analysis.json").read_text())["primary_impls"]


def run_all(cases_path, outdir):
    if outdir.exists() and any(outdir.glob("*.jsonl")) and "--fresh" not in sys.argv:
        return
    subprocess.run([str(D / "run_all.sh"), str(cases_path), str(outdir)], check=True,
                   stdout=subprocess.DEVNULL)


def reps(cases, prefix, n):
    return [{**c, "id": f"{prefix}/{c['id']}#{k}"} for c in cases for k in range(n)]


def per_rep_median(res, impls):
    """res[impl]["PFX/<id>#k"] → {(impl, id): median ns}, keyload বাদ।"""
    acc = defaultdict(list)
    for i in impls:
        for cid, r in res[i].items():
            if r.stage == "keyload": continue
            base = cid.split("/", 1)[1].rsplit("#", 1)[0]
            acc[(i, base)].append(r.seconds * 1e9)
    return {k: statistics.median(v) for k, v in acc.items()}


def main():
    cases = json.loads((CR / "cases.json").read_text())["cases"]
    byid = {c["id"]: c for c in cases}
    truth = {k: TokenTruth(**v) for k, v in json.loads((CR / "truth.json").read_text()).items()}

    # (১) মূল রান
    run_all(CR / "cases.json", RR / "main")
    main_res = judge.load_results(RR / "main")

    # (২) baseline
    v1s1 = [c for c in cases if c["meta"]["family"] == "V1" and c["meta"]["seed"] == 1]
    (CR / "baseline.json").write_text(json.dumps({"cases": reps(v1s1, "RB", R_B)}))
    run_all(CR / "baseline.json", RR / "baseline")
    bmed = per_rep_median(judge.load_results(RR / "baseline"), PRIMARY)
    B = {(i, byid[cid]["meta"]["alg"], byid[cid]["meta"]["variant"]): m for (i, cid), m in bmed.items()}
    Bmax = {i: max(m for (j, _, _), m in B.items() if j == i) for i in PRIMARY}

    def base(i, c):
        return B.get((i, c["meta"]["alg"], c["meta"]["variant"]), Bmax[i])

    # (৩) screening
    cand = [(i, c["id"]) for c in cases for i in PRIMARY
            if c["id"] in main_res[i] and main_res[i][c["id"]].stage != "keyload"
            and main_res[i][c["id"]].seconds * 1e9 > T * base(i, c)]
    # (৪) confirmation
    cids = sorted({cid for _, cid in cand})
    (CR / "confirm.json").write_text(json.dumps({"cases": reps([byid[x] for x in cids], "RC", R_C)}))
    if cids:
        run_all(CR / "confirm.json", RR / "confirm")
        cmed = per_rep_median(judge.load_results(RR / "confirm"), PRIMARY)
    else:
        cmed = {}
    # (৫) SLOW
    slow = {(i, cid) for i, cid in cand
            if (i, cid) in cmed and cmed[(i, cid)] > T * base(i, byid[cid]) and cmed[(i, cid)] - base(i, byid[cid]) > F_NS}

    # (৬) R1/R2 + v1 তুলনা
    honest = [c["id"] for c in cases if truth[c["id"]].honestly_issued]
    forged = [c["id"] for c in cases if not truth[c["id"]].honestly_issued]
    hsmin = [c["id"] for c in cases if c["id"].startswith("V1/HS256/min/")]
    v1base = {i: statistics.median(main_res[i][x].seconds for x in hsmin) for i in PRIMARY}
    def rs(cid): return [main_res[i][cid] for i in PRIMARY if cid in main_res[i] and main_res[i][cid].stage != "keyload"]
    claimA = {cid for cid in byid if any(judge_truth(r, truth[cid], 0).klass == "A" for r in rs(cid))}
    res2 = {cid for _, cid in slow}
    v1 = {cid for cid in byid if any(judge_truth(r, truth[cid], v1base[r.library]).klass == "A" for r in rs(cid))}
    out = dict(
        n_impls=len(PRIMARY), n_honest=len(honest), n_forged=len(forged),
        screen_candidates=len(cand), confirm_tokens=len(cids), slow_pairs=sorted(slow),
        R1_honest_fp=sorted(x for x in honest if x in res2 or x in claimA),
        R2_forged_flags=sorted(x for x in forged if x in res2),
        v1_honest_fp=sum(x in v1 for x in honest), v1_forged_flags=sum(x in v1 for x in forged),
        screen_by_impl={i: sum(1 for j, _ in cand if j == i) for i in PRIMARY if any(j == i for j, _ in cand)},
    )
    out["R1_supported"] = not out["R1_honest_fp"]
    out["R2_supported"] = not out["R2_forged_flags"]

    # (৭) positive control
    out["R3"] = control(byid)
    out["R3_supported"] = all(v["slow"] == v["n"] for k, v in out["R3"].items() if k in ("1e4", "1e5", "1e6")) \
        and out["R3"]["absent"]["slow"] == 0
    (RR / "resource_v2.json").write_text(json.dumps(out, indent=1, default=str))
    print(json.dumps({k: v for k, v in out.items() if k != "slow_pairs"}, indent=1, default=str))


# ── positive control: x-cost অনুযায়ী SHA-256 iteration চালানো controlled HS256 verifier ──
def control(byid):
    import operators as op
    base_case = byid["V1/HS256/min/s1"]
    key = bytes.fromhex(base_case["key"]["secret_hex"])

    def verify_cost(tok):
        h, p, s = tok.split(".")
        hdr = json.loads(op.b64url_decode(h))
        x = b"x"
        for _ in range(int(hdr.get("x-cost", 0))):
            x = hashlib.sha256(x).digest()
        if not hmac.compare_digest(op.b64url(hmac.new(key, f"{h}.{p}".encode(), hashlib.sha256).digest()), s):
            raise ValueError("bad sig")
        return json.loads(op.b64url_decode(p))

    def timed(tok):
        t0 = time.perf_counter_ns()
        try: verify_cost(tok)
        except Exception: pass
        return time.perf_counter_ns() - t0

    def mk(cost, n):
        hdr = {"alg": "HS256", "typ": "JWT", **({"x-cost": cost} if cost else {})}
        pl = {"sub": "alice", "role": "user", "iss": "real-issuer", "iat": 1758758400, "exp": 4102444800, "n": n}
        hb = op.b64url(json.dumps(hdr, separators=(",", ":")).encode())
        pb = op.b64url(json.dumps(pl, separators=(",", ":")).encode())
        return f"{hb}.{pb}.{op.b64url(hmac.new(key, f'{hb}.{pb}'.encode(), hashlib.sha256).digest())}"

    timed(base_case["token"])                                   # warm-up
    B = statistics.median(timed(base_case["token"]) for _ in range(R_B))
    out = {"baseline_ns": B}
    for label, cost in (("absent", 0), ("1e3", 10**3), ("1e4", 10**4), ("1e5", 10**5), ("1e6", 10**6)):
        slow = 0
        for n in range(5):
            tok = mk(cost, n)
            if timed(tok) > T * B:
                m = statistics.median(timed(tok) for _ in range(R_C))
                slow += m > T * B and m - B > F_NS
        out[label] = dict(n=5, slow=slow)
    return out


if __name__ == "__main__":
    main()
