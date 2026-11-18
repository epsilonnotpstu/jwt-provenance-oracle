"""PREREG_g2 analysis — oracle v4 (full claim set, ν + E1/E2) on an honest corpus, vs B0/B1/B2; H-G0..H-G4.

usage:
  python analyze_g2.py --corpus corpus_g2 --results corpus_g2/results [--newlangs corpus_g2/results_new]
Writes <results>/analysis_g2.json and prints the report. Primary impls, B2 profile and the scale30 honest
reference set come from the frozen scale30 run (results/analysis.json, results/main), as in judge.run_custom.
"""
import argparse, json, math, random, sys
from collections import Counter, defaultdict
from decimal import Decimal
from pathlib import Path

D = Path(__file__).resolve().parent
sys.path.insert(0, str(D))
import judge  # noqa: E402

EXCL = {"precision", "decimal_inexact"}           # PREREG_g2 §2: outside the primary stratum
BOOT, SUB, SEED = 10000, 1000, 1
UNPARSEABLE = []                                   # cases whose signed bytes are not JSON (PREREG_g2 D1)


# ───────── ν (PREREG_g2 §3) ─────────
def isnum(x): return isinstance(x, (int, Decimal)) and not isinstance(x, bool)


def veq(a, b):
    if isnum(a) and isnum(b): return Decimal(a) == Decimal(b)
    if isinstance(a, bool) or isinstance(b, bool) or a is None or b is None: return a is b
    if isinstance(a, str) and isinstance(b, str): return a == b
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(veq(x, y) for x, y in zip(a, b))
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(veq(a[k], b[k]) for k in a)
    return False


def aud_norm(v):                                   # E1 (string ≡ one-element array) + E2 (order ignored)
    v = [v] if isinstance(v, str) else v
    return sorted(v, key=repr) if isinstance(v, list) and all(isinstance(x, str) for x in v) else None


def claim_eq(k, b, s):
    if k == "aud" and aud_norm(b) is not None and aud_norm(s) is not None: return aud_norm(b) == aud_norm(s)
    return veq(b, s)


def kind(b, s):
    """kind of the first differing leaf (nested containers are descended)."""
    if isnum(b) and isnum(s): return "num"
    if isinstance(b, str) and isinstance(s, str): return "str"
    if isinstance(b, list) and isinstance(s, list) and len(b) == len(s):
        return next((kind(x, y) for x, y in zip(b, s) if not veq(x, y)), "other")
    if isinstance(b, dict) and isinstance(s, dict):
        if b.keys() != s.keys(): return "extra" if b.keys() - s.keys() else "other"
        return next((kind(b[k], s[k]) for k in b if not veq(b[k], s[k])), "other")
    if type(b) is not type(s) and not (isnum(b) and isnum(s)): return "type"
    return "other"


def v4(belief, signed):
    """→ (list of (claim, kind) violations, list of dropped claims)."""
    viol = [(k, "extra") if k not in signed else (k, kind(v, signed[k]))
            for k, v in belief.items() if k not in signed or not claim_eq(k, v, signed[k])]
    return viol, [k for k in signed if k not in belief]


# ───────── stats ─────────
def wilson(x, n, z=1.96):
    if n == 0: return (0.0, 0.0)
    p = x / n; d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d; h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def cluster_boot(per_token, n=BOOT, seed=SEED):
    """per_token = [(A count, obs count)] → 95% percentile CI of the pooled rate, resampling tokens."""
    rng, T = random.Random(seed), len(per_token)
    rates = []
    for _ in range(n):
        s = [per_token[rng.randrange(T)] for _ in range(T)]
        den = sum(o for _, o in s); rates.append(sum(a for a, _ in s) / den if den else 0.0)
    rates.sort()
    return rates[int(0.025 * n)], rates[int(0.975 * n) - 1]


def mcnemar(b, c):
    """exact two-sided McNemar on discordant counts b, c."""
    n = b + c
    if n == 0: return 1.0
    k = min(b, c)
    return min(1.0, 2 * sum(math.comb(n, i) for i in range(k + 1)) / 2 ** n)


def holm(ps):
    order, m, adj, run = sorted(range(len(ps)), key=lambda i: ps[i]), len(ps), [0.0] * len(ps), 0.0
    for r, i in enumerate(order):
        run = max(run, min(1.0, (m - r) * ps[i])); adj[i] = run
    return adj


def cochran_armitage(x, n):
    N, s = sum(n), list(range(len(n)))
    if N == 0: return float("nan"), 1.0
    p = sum(x) / N
    T = sum(si * (xi - ni * p) for si, xi, ni in zip(s, x, n))
    var = p * (1 - p) * (sum(ni * si * si for si, ni in zip(s, n)) - sum(ni * si for si, ni in zip(s, n)) ** 2 / N)
    if var == 0: return 0.0, 1.0
    z = T / math.sqrt(var)
    return z, math.erfc(abs(z) / math.sqrt(2))


# ───────── data ─────────
def load_raw(d):
    """impl → case → raw row, claims parsed with exact decimals."""
    out = defaultdict(dict)
    for f in sorted(Path(d).glob("*.jsonl")):
        for line in f.open():
            r = json.loads(line, parse_float=Decimal)
            out[r["impl"]][r["case"]] = r
    return out


def v4_table(cases, signed, raw, impls):
    """per case: list of per-impl observations {impl, stage, accepted, viol, drop}."""
    T = {}
    for c in cases:
        try: s = json.loads(signed[c["id"]], parse_float=Decimal)
        except ValueError: T[c["id"]] = []; UNPARSEABLE.append(c["id"]); continue   # Signed(t) undefined (D1)
        obs = []
        for i in impls:
            r = raw.get(i, {}).get(c["id"])
            if r is None or r["stage"] == "keyload": continue
            viol, drop = v4(r["claims"] or {}, s) if r["accepted"] else ([], [])
            obs.append(dict(impl=i, accepted=r["accepted"], viol=viol, drop=drop))
        T[c["id"]] = obs
    return T


def accept_vectors(cases, raw, impls):
    vec = {}
    for c in cases:
        v = []
        for i in impls:
            r = raw.get(i, {}).get(c["id"])
            v.append("-" if r is None else "K" if r["stage"] == "keyload" else "A" if r["accepted"] else "R")
        vec[c["id"]] = "".join(v)
    return vec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", required=True); ap.add_argument("--results", required=True)
    ap.add_argument("--newlangs")
    a = ap.parse_args()
    cdir, rdir = Path(a.corpus), Path(a.results)
    cases = json.loads((cdir / "cases.json").read_text())["cases"]
    signed = json.loads((cdir / "signed.json").read_text())
    rows, impls, keyload = judge.run_custom(cdir, rdir)          # B0/B1/B2/PROV/PROV_claim per case
    R = {r["case"]: r for r in rows}
    raw = load_raw(rdir)
    T = v4_table(cases, signed, raw, impls)
    tags = {c["id"]: set(c["meta"].get("tags", [])) for c in cases}
    prim = [c["id"] for c in cases if not tags[c["id"]] & EXCL]
    out, L = {"n_cases": len(cases), "n_primary": len(prim), "impls": impls, "keyload": dict(keyload),
              "signed_unparseable": UNPARSEABLE}, []
    if UNPARSEABLE: L.append(f"D1: {len(UNPARSEABLE)} case(s) with unparseable signed bytes skipped for v4: {UNPARSEABLE}")

    # H-G0
    g0 = sum(R[x]["PROV_claim"] for x in R)
    out["H-G0"] = {"v3_claim_A_on_honest": g0, "holds": g0 == 0}
    L.append(f"H-G0 v3 claim-path A on honest = {g0} → {'holds' if g0 == 0 else 'HARNESS DEFECT'}")

    # H-G1
    per_tok = [(sum(bool(o["viol"]) for o in T[x]), len(T[x])) for x in prim]
    A, n = sum(p[0] for p in per_tok), sum(p[1] for p in per_tok)
    fpr, wl, bl = (A / n if n else 0.0), wilson(A, n), cluster_boot(per_tok)
    g1 = fpr <= 0.01 and bl[1] <= 0.02
    out["H-G1"] = dict(A=A, n=n, fpr=fpr, wilson=wl, boot=bl, holds=g1)
    L.append(f"H-G1 FPR_v4 primary = {A}/{n} = {fpr:.2%}  Wilson [{wl[0]:.2%},{wl[1]:.2%}]  "
             f"boot [{bl[0]:.2%},{bl[1]:.2%}] → {'supported' if g1 else 'FALSIFIED'}")

    # H-G2 (token level, primary stratum)
    tok_v4 = {x: any(o["viol"] for o in T[x]) for x in prim}
    ps, g2 = [], {}
    for B in ("B0", "B1", "B2"):
        b = sum(tok_v4[x] and not R[x][B] for x in prim); c = sum(R[x][B] and not tok_v4[x] for x in prim)
        g2[B] = dict(baseline_flags=sum(bool(R[x][B]) for x in prim), v4_flags=sum(tok_v4.values()),
                     v4_only=b, baseline_only=c, p=mcnemar(b, c)); ps.append(g2[B]["p"])
    for B, pa in zip(("B0", "B1", "B2"), holm(ps)):
        g2[B]["p_holm"] = pa; g2[B]["supported"] = pa < 0.05 and g2[B]["baseline_only"] > g2[B]["v4_only"]
        L.append(f"H-G2 v4 {g2[B]['v4_flags']}/{len(prim)} vs {B} {g2[B]['baseline_flags']}/{len(prim)}  "
                 f"discordant {g2[B]['v4_only']}:{g2[B]['baseline_only']}  p_holm={pa:.3g} → "
                 f"{'supported' if g2[B]['supported'] else 'not supported'}")
    out["H-G2"] = g2

    # H-G3 (test dimension) — scale30 honest V1–V3 as the reference corpus
    ref_cases = [c for c in json.loads((D / "corpus/cases.json").read_text())["cases"]
                 if c["meta"]["family"] in ("V1", "V2", "V3")]
    ref_vec = accept_vectors(ref_cases, load_raw(D / "results/main"), impls)
    new_vec = accept_vectors(cases, raw, impls)
    k, ref_n = len(ref_cases), len(set(ref_vec.values()))
    rng, ids, wins, counts = random.Random(SEED), list(new_vec), 0, []
    if len(ids) >= k:
        for _ in range(SUB):
            cnt = len({new_vec[x] for x in rng.sample(ids, k)}); counts.append(cnt); wins += cnt > ref_n
        g3 = wins / SUB >= 0.95
        out["H-G3"] = dict(k=k, ref_distinct=ref_n, new_distinct_full=len(set(new_vec.values())),
                           new_median_at_k=sorted(counts)[SUB // 2], win_rate=wins / SUB, holds=g3)
        L.append(f"H-G3 distinct acceptance vectors @n={k}: scale30 {ref_n} vs g2 median "
                 f"{sorted(counts)[SUB // 2]} (full g2 {len(set(new_vec.values()))}); g2 > ref in "
                 f"{wins / SUB:.1%} → {'supported' if g3 else 'not supported'}")
    else:
        L.append(f"H-G3 skipped: corpus has {len(ids)} < {k} cases")

    # H-G4 (depth trend)
    depth = {c["id"]: c["meta"].get("depth") for c in cases}
    ds = sorted({d for d in depth.values() if d is not None})
    if ds:
        x = [sum(bool(R[i]["B0"]) for i in R if depth[i] == d) for d in ds]
        nn = [sum(depth[i] == d for i in R) for d in ds]
        z, p = cochran_armitage(x, nn)
        v4d = {}
        for d in ds:
            pt = [(sum(bool(o["viol"]) for o in T[i]), len(T[i])) for i in R if depth[i] == d and i in set(prim)]
            v4d[d] = sum(a for a, _ in pt) / max(1, sum(o for _, o in pt))
        out["H-G4"] = dict(B0_by_depth=dict(zip(ds, zip(x, nn))), z=z, p=p, v4_fpr_by_depth=v4d,
                           holds=not (z < 0 and p < 0.05))
        L.append("H-G4 B0 by depth " + "  ".join(f"d{d}:{xi}/{ni}" for d, xi, ni in zip(ds, x, nn)) +
                 f"  CA z={z:.2f} p={p:.3g} → {'decrease rejected' if z < 0 and p < 0.05 else 'no decrease'}")
        L.append("      FPR_v4 by depth " + "  ".join(f"d{d}:{v:.2%}" for d, v in v4d.items()))

    # descriptive
    cat = Counter(); drops = Counter(); by_impl = Counter()
    for x in R:
        for o in T[x]:
            for cl, kd in o["viol"]:
                strata = sorted(tags[x] & (EXCL | {"nul", "unicode", "uesc", "num_respelled", "aud"})) or ["-"]
                cat[(o["impl"], kd, cl if cl in ("aud", "iat", "exp", "nbf") else "x_*", ",".join(strata))] += 1
            if o["viol"]: by_impl[o["impl"]] += 1
            for cl in o["drop"]: drops[(o["impl"], cl)] += 1
    out["catalogue"] = [dict(impl=i, kind=k, claim=c, strata=s, n=v) for (i, k, c, s), v in cat.most_common()]
    out["drops"] = [dict(impl=i, claim=c, n=v) for (i, c), v in drops.most_common()]
    out["v4_A_obs_by_impl"] = dict(by_impl.most_common())
    for st in sorted(EXCL):
        ids_ = [x for x in R if st in tags[x]]
        pt = [(sum(bool(o["viol"]) for o in T[x]), len(T[x])) for x in ids_]
        a_, n_ = sum(p[0] for p in pt), sum(p[1] for p in pt)
        out[f"stratum_{st}"] = dict(tokens=len(ids_), A=a_, n=n_)
        L.append(f"stratum {st}: tokens={len(ids_)}  FPR_v4 = {a_}/{n_}" + (f" = {a_ / n_:.2%}" if n_ else ""))
    alg = {c["id"]: c["meta"]["alg"] for c in cases}
    hr = [x for x in prim if alg[x] in ("HS256", "RS256")]
    out["HS256_RS256"] = {B: [sum(bool(R[x][B]) for x in hr), len(hr)] for B in ("B0", "B1", "B2")}
    out["HS256_RS256"]["v4"] = [sum(tok_v4[x] for x in hr), len(hr)]
    L.append("HS256/RS256 only: " + "  ".join(f"{k}={v[0]}/{v[1]}" for k, v in out["HS256_RS256"].items()))
    out["PROV_v1_resource_descriptive"] = sum(bool(r["PROV"]) for r in rows)
    L.append(f"judge PROV (v1 resource incl., descriptive) flags = {out['PROV_v1_resource_descriptive']}")
    L.append("v4 A observations by impl: " + ", ".join(f"{i}={v}" for i, v in by_impl.most_common()))
    L.append("top coercions (impl, kind, claim, strata → n):")
    for e in out["catalogue"][:25]: L.append(f"   {e['impl']:28} {e['kind']:5} {e['claim']:4} {e['strata']:30} {e['n']}")
    if out["drops"]: L.append("drops: " + ", ".join(f"{e['impl']}:{e['claim']}={e['n']}" for e in out["drops"][:15]))

    if a.newlangs:                                  # descriptive only (PREREG_g2 §1)
        nraw = load_raw(a.newlangs); nimpl = sorted(nraw)
        NT = v4_table(cases, signed, nraw, nimpl)
        nd = {}
        for i in nimpl:
            ob = [o for x in prim for o in NT[x] if o["impl"] == i]
            nd[i] = dict(A=sum(bool(o["viol"]) for o in ob), n=len(ob), accepted=sum(o["accepted"] for o in ob),
                         kinds=dict(Counter(k for o in ob for _, k in o["viol"])))
            L.append(f"newlangs {i}: accepted {nd[i]['accepted']}/{nd[i]['n']}  v4 A={nd[i]['A']} {nd[i]['kinds']}")
        out["newlangs"] = nd

    (rdir / "analysis_g2.json").write_text(json.dumps(out, indent=1, default=str))
    print("\n".join(L)); print(f"→ {rdir / 'analysis_g2.json'}")


if __name__ == "__main__":
    main()
