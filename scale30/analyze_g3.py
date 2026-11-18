"""PREREG_g3 analysis — v4-IJ (binary64 number policy) primary, v4-exact secondary; H3-0..H3-5 + descriptives.

usage: python analyze_g3.py --corpus corpus_g3 --results corpus_g3/results [--newlangs DIR]
Reuses the frozen g2 helpers (analyze_g2.py @ 0052ebb): ν, E1/E2, kinds, stats, loaders.
"""
import argparse, json, math, random, sys
from collections import Counter
from decimal import Decimal
from pathlib import Path

D = Path(__file__).resolve().parent
sys.path.insert(0, str(D))
import judge  # noqa: E402
import analyze_g2 as A  # noqa: E402

EXCL = {"nonconformant", "must_reject", "parse_ambiguous", "non_ijson"}      # PREREG_g3 §2
G2_COMPACT_N, G2_COMPACT_VECTORS = 978, 57                                    # EXP_g2 saturation reference


def dbl(x):
    try: return float(Decimal(x))
    except (OverflowError, ValueError): return None


def veq_ij(a, b):
    """ν of PREREG_g2 §3, but numbers compare at binary64 (PREREG_g3 §3)."""
    if A.isnum(a) and A.isnum(b):
        fa, fb = dbl(a), dbl(b)
        return fa is not None and fb is not None and math.isfinite(fa) and math.isfinite(fb) and fa == fb
    if isinstance(a, bool) or isinstance(b, bool) or a is None or b is None: return a is b
    if isinstance(a, str) and isinstance(b, str): return a == b
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(veq_ij(x, y) for x, y in zip(a, b))
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(veq_ij(a[k], b[k]) for k in a)
    return False


def v4(belief, signed, policy):
    """policy 'ij' or 'exact' → (violations [(claim, kind)], drops)."""
    eq = veq_ij if policy == "ij" else A.veq
    def claim_eq(k, b, s):
        if k == "aud" and A.aud_norm(b) is not None and A.aud_norm(s) is not None: return A.aud_norm(b) == A.aud_norm(s)
        return eq(b, s)
    viol = [(k, "extra") if k not in signed else (k, A.kind(v, signed[k]))
            for k, v in belief.items() if k not in signed or not claim_eq(k, v, signed[k])]
    return viol, [k for k in signed if k not in belief]


def table(cases, signed, raw, impls, policy):
    T = {}
    for c in cases:
        try: s = json.loads(signed[c["id"]], parse_float=Decimal)
        except ValueError: T[c["id"]] = []; continue
        obs = []
        for i in impls:
            r = raw.get(i, {}).get(c["id"])
            if r is None or r["stage"] == "keyload": continue
            viol, drop = v4(r["claims"] or {}, s, policy) if r["accepted"] else ([], [])
            obs.append(dict(impl=i, accepted=r["accepted"], viol=viol, drop=drop))
        T[c["id"]] = obs
    return T


def rate(T, ids, accepted_only=False):
    pt = [(sum(bool(o["viol"]) for o in T[x]), sum(1 for o in T[x] if o["accepted"] or not accepted_only)) for x in ids]
    a, n = sum(p[0] for p in pt), sum(p[1] for p in pt)
    return a, n, pt


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", required=True); ap.add_argument("--results", required=True)
    ap.add_argument("--newlangs")
    a = ap.parse_args()
    cdir, rdir = Path(a.corpus), Path(a.results)
    cases = json.loads((cdir / "cases.json").read_text())["cases"]
    signed = json.loads((cdir / "signed.json").read_text())
    rows, impls, keyload = judge.run_custom(cdir, rdir)
    R = {r["case"]: r for r in rows}
    raw = A.load_raw(rdir)
    TI, TX = table(cases, signed, raw, impls, "ij"), table(cases, signed, raw, impls, "exact")
    meta = {c["id"]: c["meta"] for c in cases}
    tags = {x: set(m.get("tags", [])) for x, m in meta.items()}
    prim = [x for x in meta if not tags[x] & EXCL]
    out, L = {"n_cases": len(cases), "n_primary": len(prim), "impls": impls, "keyload": dict(keyload)}, []

    g0 = sum(bool(R[x]["PROV_claim"]) for x in R)
    out["H3-0"] = dict(v3_A=g0, holds=g0 == 0)
    L.append(f"H3-0 v3 claim-path A on honest = {g0} → {'holds' if g0 == 0 else 'HARNESS DEFECT'}")

    A1, n1, pt = rate(TI, prim); Aa, na, _ = rate(TI, prim, accepted_only=True)
    wl, bl = A.wilson(A1, n1), A.cluster_boot(pt)
    ok = A1 / n1 <= 0.01 and bl[1] <= 0.02 and Aa / na <= 0.01
    out["H3-1"] = dict(A=A1, n=n1, fpr=A1 / n1, wilson=wl, boot=bl, A_acc=Aa, n_acc=na, fpr_acc=Aa / na, holds=ok)
    L.append(f"H3-1 FPR_v4-IJ primary = {A1}/{n1} = {A1 / n1:.3%} Wilson [{wl[0]:.3%},{wl[1]:.3%}] boot "
             f"[{bl[0]:.3%},{bl[1]:.3%}]; per accepted {Aa}/{na} = {Aa / na:.3%} → {'supported' if ok else 'FALSIFIED'}")

    tok = {x: any(o["viol"] for o in TI[x]) for x in prim}
    ps, g2 = [], {}
    for B in ("B0", "B1", "B2"):
        b = sum(tok[x] and not R[x][B] for x in prim); c = sum(R[x][B] and not tok[x] for x in prim)
        g2[B] = dict(baseline=sum(bool(R[x][B]) for x in prim), v4=sum(tok.values()), v4_only=b, base_only=c,
                     p=A.mcnemar(b, c)); ps.append(g2[B]["p"])
    for B, pa in zip(("B0", "B1", "B2"), A.holm(ps)):
        g = g2[B]; g["p_holm"] = pa; g["v4_lower"] = pa < 0.05 and g["base_only"] > g["v4_only"]
        L.append(f"H3-2 v4-IJ {g['v4']}/{len(prim)} vs {B} {g['baseline']}/{len(prim)} discordant "
                 f"{g['v4_only']}:{g['base_only']} p_holm={pa:.3g} → v4 lower: {g['v4_lower']}")
    out["H3-2"] = g2

    per = {}
    for i in impls:
        ob = [o for x in prim for o in TI[x] if o["impl"] == i]
        ai, ni = sum(bool(o["viol"]) for o in ob), sum(o["accepted"] for o in ob)
        per[i] = dict(A=ai, n_acc=ni, wilson_hi=A.wilson(ai, ni)[1] if ni else None,
                      ro3=(3 / ni if ni and ai == 0 else None))
    good = [i for i, v in per.items() if v["A"] == 0 and v["ro3"] is not None and v["ro3"] <= 0.001]
    out["H3-3"] = dict(per_impl=per, n_meeting=len(good), target=24, met=len(good) >= 24)
    L.append(f"H3-3 impls with 0 A and rule-of-three ≤0.1%: {len(good)}/32 (target 24) → "
             f"{'met' if len(good) >= 24 else 'not met'}")
    for i, v in sorted(per.items(), key=lambda kv: (-kv[1]["A"], kv[0])):
        L.append(f"      {i:28} A={v['A']:4} n_acc={v['n_acc']:5} " +
                 (f"ro3={v['ro3']:.3%}" if v["ro3"] is not None else f"wilson_hi={v['wilson_hi']:.3%}" if v["wilson_hi"] is not None else "no accepts"))

    ds = sorted({m["depth"] for m in meta.values()})
    x = [sum(bool(R[i]["B0"]) for i in R if meta[i]["depth"] == d) for d in ds]
    nn = [sum(meta[i]["depth"] == d for i in R) for d in ds]
    z, p2 = A.cochran_armitage(x, nn)
    p1 = p2 / 2 if z > 0 else 1 - p2 / 2
    out["H3-4"] = dict(B0_by_depth=list(zip(x, nn)), z=z, p_one_sided=p1, holds=z > 0 and p1 < 0.05)
    L.append("H3-4 B0 by depth " + " ".join(f"d{d}:{xi}/{ni}" for d, xi, ni in zip(ds, x, nn)) +
             f" CA z={z:.2f} one-sided p={p1:.3g} → {'supported' if z > 0 and p1 < 0.05 else 'NOT supported'}")

    vec = A.accept_vectors(cases, raw, impls)
    ids, rng, wins, cnts = list(vec), random.Random(A.SEED), 0, []
    for _ in range(A.SUB):
        cnt = len({vec[y] for y in rng.sample(ids, G2_COMPACT_N)}); cnts.append(cnt); wins += cnt > G2_COMPACT_VECTORS
    f = Counter(vec.values()); f1 = sum(v == 1 for v in f.values()); f2 = sum(v == 2 for v in f.values())
    chao1 = len(f) + (f1 * f1 / (2 * f2) if f2 else f1 * (f1 - 1) / 2)
    out["H3-5"] = dict(median_at_978=sorted(cnts)[A.SUB // 2], win=wins / A.SUB, full=len(f), chao1=chao1,
                       good_turing=f1 / len(ids), holds=wins / A.SUB >= 0.95)
    L.append(f"H3-5 distinct vectors @978: G3 median {sorted(cnts)[A.SUB // 2]} vs g2 57; wins {wins / A.SUB:.1%} → "
             f"{'supported' if wins / A.SUB >= 0.95 else 'NOT supported'}; full N: {len(f)} (Chao1 {chao1:.1f}, "
             f"Good–Turing P(new) {f1 / len(ids):.3%})")

    # ── descriptive ──
    Ax, nx, _ = rate(TX, prim)
    L.append(f"v4-exact primary (secondary): {Ax}/{nx} = {Ax / nx:.3%}")
    for st in sorted({"precision", "decimal_inexact", "numedge", "numdate_frac", "keyname", "stredge", "limits",
                      "uesc", "unicode", "nul"} | EXCL):
        ids_ = [y for y in meta if st in tags[y]]
        ai, ni, _ = rate(TI, ids_); ax, _, _ = rate(TX, ids_)
        acc = sum(o["accepted"] for y in ids_ for o in TI[y])
        out[f"stratum_{st}"] = dict(tokens=len(ids_), A_ij=ai, A_exact=ax, n=ni, accepted=acc)
        L.append(f"stratum {st:16} tokens={len(ids_):5} accepted {acc}/{ni}  A_ij={ai}  A_exact={ax}")
    conf = {}
    for i in impls:
        c_ = Counter()
        for y in meta:
            for tg in tags[y]:
                if tg.startswith("nonconf_") or tg == "must_reject":
                    r = raw.get(i, {}).get(y)
                    if r and r["stage"] != "keyload": c_[(tg, r["accepted"])] += 1
        conf[i] = {f"{tg}:{'acc' if ac else 'rej'}": v for (tg, ac), v in sorted(c_.items())}
    out["conformance"] = conf
    L.append("conformance acceptances (impl: stratum=accepted/total):")
    strata = sorted({k.split(":")[0] for v in conf.values() for k in v})
    for i in impls:
        s_ = [f"{st}={conf[i].get(st + ':acc', 0)}/{conf[i].get(st + ':acc', 0) + conf[i].get(st + ':rej', 0)}"
              for st in strata if conf[i].get(st + ":acc", 0)]
        if s_: L.append(f"   {i:28} " + " ".join(s_))
    cat = Counter((o["impl"], k, cl if not cl.startswith("x_") else "x_*") for y in prim for o in TI[y] for cl, k in o["viol"])
    out["catalogue_ij"] = [dict(impl=i, kind=k, claim=c, n=v) for (i, k, c), v in cat.most_common()]
    L.append("v4-IJ primary coercions (impl, kind, claim → n): " +
             "; ".join(f"{i} {k} {c}={v}" for (i, k, c), v in cat.most_common(20)))
    drops = Counter((o["impl"]) for y in prim for o in TI[y] for _ in o["drop"])
    L.append("drops by impl: " + ", ".join(f"{i}={v}" for i, v in drops.most_common()))
    out["PROV_v1_resource_descriptive"] = sum(bool(r["PROV"]) for r in rows)
    to = Counter(r_["impl"] for i in raw for r_ in raw[i].values() if r_["stage"] in ("timeout", "crash"))
    L.append(f"judge PROV (v1 resource) flags = {out['PROV_v1_resource_descriptive']}; timeouts/crashes: {dict(to)}")

    if a.newlangs:
        nraw = A.load_raw(a.newlangs); nimpl = sorted(nraw)
        NT = table(cases, signed, nraw, nimpl, "ij"); nd = {}
        for i in nimpl:
            ob = [o for y in prim for o in NT[y] if o["impl"] == i]
            nd[i] = dict(A=sum(bool(o["viol"]) for o in ob), n=len(ob), accepted=sum(o["accepted"] for o in ob),
                         kinds=dict(Counter(k for o in ob for _, k in o["viol"])))
            L.append(f"newlangs {i}: accepted {nd[i]['accepted']}/{nd[i]['n']} v4-IJ A={nd[i]['A']} {nd[i]['kinds']}")
        out["newlangs"] = nd

    (rdir / "analysis_g3.json").write_text(json.dumps(out, indent=1, default=str))
    print("\n".join(L)); print(f"→ {rdir / 'analysis_g3.json'}")


if __name__ == "__main__":
    main()
