"""PREREG_B2plus মূল্যায়ন: header/claim-সচেতন profile (B2+) — P1 (T-same), P2 (T-new), P3 (চুপ হওয়া জোড়া)।
category শুধু টোকেন আর key থেকে; truth ব্যবহার হয় শুধু FP/PROV_claim গণনায়।"""
import json, random
from pathlib import Path

import judge
from oracle import TokenTruth, judge_truth
import operators as op

D = judge.D
RNG = random.Random(20260925)
PRIMARY = json.loads((D / "results/analysis.json").read_text())["primary_impls"]
REGISTERED = {"alg", "typ", "cty", "kid", "jku", "jwk", "x5u", "x5c", "x5t", "x5t#S256", "crit"}
RARE = {"jwk", "jku", "x5u", "x5c", "x5t", "x5t#S256"}


def parts(tok):
    if tok.lstrip().startswith("{"):
        o = json.loads(tok); return o.get("protected", ""), o.get("payload", "")
    p = tok.split(".")
    return p[0], (p[1] if len(p) > 1 else "")


def _json(b64):
    try: return json.loads(op.b64url_decode(b64))
    except Exception: return {}


def cats(c, variant_only=False):
    """non-default category-র set (PREREG_B2plus §1)।"""
    h64, p64 = parts(c["token"])
    h, p = _json(h64), _json(p64)
    raw = op.b64url_decode(p64) if p64 else b""
    out = set() if variant_only else {("C1", c["meta"]["alg"], c["meta"]["variant"])}
    if isinstance(h, dict):
        if "typ" not in h: out.add("C2:absent")
        elif h["typ"] != "JWT": out.add("C2:other")
        if "kid" in h: out.add("C3")
        if set(h) - REGISTERED: out.add("C4")
        if "cty" in h: out.add("C5")
        if set(h) & RARE: out.add("C6")
    if isinstance(p, dict):
        if "aud" in p: out.add("C7")
        if any(b > 127 for b in raw) or any(ord(ch) > 127 for ch in json.dumps(p, ensure_ascii=False)): out.add("C8")
        def big(v):
            if isinstance(v, bool): return False
            if isinstance(v, int): return abs(v) > 2 ** 53
            if isinstance(v, dict): return any(big(x) for x in v.values())
            if isinstance(v, list): return any(big(x) for x in v)
            return False
        if big(p): out.add("C9")
        if "nbf" in p: out.add("C10")
        if "exp" in p and not isinstance(p["exp"], int): out.add("C11")
        if len(raw) > 4096: out.add("C12")
        if any(isinstance(v, dict) for v in p.values()): out.add("C13")
        if "jti" in p: out.add("C14")
    return out


def profiles(train_cases, res):
    P = {i: set() for i in PRIMARY}
    for c in train_cases:
        fam = c["meta"]["family"]
        add = {("C1", c["meta"]["alg"], c["meta"]["variant"])} if fam == "V1" else cats(c, variant_only=True)
        for i in PRIMARY:
            r = res[i].get(c["id"])
            if r and not r.accepted and r.stage != "keyload":
                P[i] |= add
    return P


def b2plus_flag(c, rs, P):
    ct = cats(c)
    keep = [r for r in rs if not (ct & P[r.library])]
    a = sum(r.accepted for r in keep)
    return 0 < a < len(keep), len(rs) - len(keep)


def boot(v, n=10000):
    m = sorted(sum(RNG.choice(v) for _ in v) / len(v) for _ in range(n))
    return m[int(.025 * n)], m[int(.975 * n)]


def main():
    main_cases = json.loads((D / "corpus/cases.json").read_text())["cases"]
    main_truth = {k: TokenTruth(**v) for k, v in json.loads((D / "corpus/truth.json").read_text()).items()}
    main_res = judge.load_results(D / "results/main")
    train = [c for c in main_cases if c["meta"]["family"] in ("V1", "V2", "V3") and c["meta"]["seed"] == 1]
    P = profiles(train, main_res)
    P2old = judge.cap_profile(main_res, main_cases, PRIMARY)          # scale30-এর B2 (শুধু C1)

    bc = json.loads((D / "corpus_b/cases.json").read_text())["cases"]
    bt = {k: TokenTruth(**v) for k, v in json.loads((D / "corpus_b/truth.json").read_text()).items()}
    bres = judge.load_results(D / "results_b/main")
    out = {"profile_rules": {i: sorted(map(str, P[i])) for i in PRIMARY if P[i]},
           "n_rules": sum(len(P[i]) for i in PRIMARY)}
    rows = {}
    for c in bc:
        rs = [bres[i][c["id"]] for i in PRIMARY if c["id"] in bres[i] and bres[i][c["id"]].stage != "keyload"]
        f, _ = b2plus_flag(c, rs, P)
        b0 = 0 < sum(r.accepted for r in rs) < len(rs)
        key = (c["meta"]["alg"], c["meta"]["variant"])
        rs2 = [r for r in rs if key not in P2old.get(r.library, ())]
        b2 = 0 < sum(r.accepted for r in rs2) < len(rs2)
        pc = any(judge_truth(r, bt[c["id"]], 0).klass == "A" for r in rs)
        rows[c["id"]] = dict(fam=c["meta"]["family"], B0=b0, B2=b2, B2plus=f, PROV_claim=pc,
                             rejecters=[r.library for r in rs if not r.accepted])
    for fam in ("TS", "TN"):
        ids = [x for x, r in rows.items() if r["fam"] == fam]
        res_f = {}
        for d in ("B0", "B2", "B2plus", "PROV_claim"):
            v = [int(rows[x][d]) for x in ids]
            res_f[d] = dict(fp=sum(v), n=len(v), rate=sum(v) / len(v), ci95=boot(v))
        by_variant = {}
        for x in ids:
            vname = x.split("/")[3]
            by_variant.setdefault(vname, {"B2plus_fp": 0, "n": 0, "rejecters": set()})
            by_variant[vname]["n"] += 1
            by_variant[vname]["B2plus_fp"] += rows[x]["B2plus"]
            by_variant[vname]["rejecters"] |= set(rows[x]["rejecters"])
        res_f["by_variant"] = {k: {**v, "rejecters": sorted(v["rejecters"])} for k, v in by_variant.items()}
        out[fam] = res_f
    out["P1_supported"] = out["TS"]["B2plus"]["rate"] < 0.05
    out["P2_supported"] = out["TN"]["B2plus"]["rate"] >= 0.05 and out["TN"]["B2plus"]["ci95"][0] > 0

    # P3: জাল টোকেনে চুপ হওয়া (impl, টোকেন) জোড়া
    forged = [c for c in main_cases if not main_truth[c["id"]].honestly_issued]
    tot = sil_plus = sil_old = 0
    for c in forged:
        rs = [main_res[i][c["id"]] for i in PRIMARY if c["id"] in main_res[i] and main_res[i][c["id"]].stage != "keyload"]
        tot += len(rs)
        sil_plus += b2plus_flag(c, rs, P)[1]
        key = (c["meta"]["alg"], c["meta"]["variant"])
        sil_old += sum(key in P2old.get(r.library, ()) for r in rs)
    out["P3"] = dict(pairs=tot, silenced_B2=sil_old, silenced_B2plus=sil_plus,
                     rate_B2=sil_old / tot, rate_B2plus=sil_plus / tot)
    (D / "results_b/b2plus.json").write_text(json.dumps(out, indent=1, default=str))
    print(json.dumps({k: v for k, v in out.items() if k != "profile_rules"}, indent=1, default=str))


if __name__ == "__main__":
    main()
