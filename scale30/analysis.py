"""scale30 analysis — PREREG §6: D1 curve, H2 permutation, H3 bootstrap, D5 triage, D6 artifacts,
আর sensitivity (বাদ পড়া impl সহ / reserve ছাড়া)। ফল: results/analysis.json + stdout-এ markdown টেবিল।
PROV_claim = post-hoc secondary (pre-registered নয়)।"""
import json, random, statistics
from collections import defaultdict
from itertools import combinations
from pathlib import Path

import judge
from oracle import TokenTruth

D = judge.D
RNG = random.Random(20260925)
DET = ("B0", "B1", "B2", "PROV", "PROV_claim")


def lang(i): return i.split("/")[0]


def setup():
    cases = json.loads((D / "corpus/cases.json").read_text())["cases"]
    truth = {k: TokenTruth(**v) for k, v in json.loads((D / "corpus/truth.json").read_text()).items()}
    res = judge.load_results(D / "results/main")
    ok = judge.gate_pass(D / "results/gate")
    primary, status, kl = judge.select_impls(res, cases, ok)
    allrun = sorted(i for i in res if i in ok)
    P = judge.cap_profile(res, cases, allrun)
    base = judge.baselines(res, cases, allrun)
    return cases, truth, res, primary, status, kl, P, base, allrun


def flags_for(cases, truth, res, impls, P, base):
    """case id → {detector: bool} একটা নির্দিষ্ট impl-সেটের জন্য।"""
    out = {}
    for c in cases:
        rs = [res[i][c["id"]] for i in impls if c["id"] in res[i] and res[i][c["id"]].stage != "keyload"]
        out[c["id"]] = judge.detect(c, rs, truth[c["id"]], P, base)[0]
    return out


def fp_rate(fl, ids, d): return sum(fl[x][d] for x in ids) / len(ids)


def quota_subset(impls, k):
    """প্রতি ভাষা থেকে যতটা সম্ভব সমান (পার্থক্য ≤১, ক্ষমতা ফুরালে অন্যকে)।"""
    by = defaultdict(list)
    for i in impls: by[lang(i)].append(i)
    cnt = {l: 0 for l in by}
    for _ in range(k):
        cands = [l for l in by if cnt[l] < len(by[l])]
        m = min(cnt[l] for l in cands)
        cnt[RNG.choice([l for l in cands if cnt[l] == m])] += 1
    return [i for l in by for i in RNG.sample(by[l], cnt[l])]


def q(v):
    v = sorted(v)
    return dict(median=statistics.median(v), q1=v[len(v) // 4], q3=v[(3 * len(v)) // 4])


def boot_ci(vals, n=10000):
    """vals = ০/১ তালিকা → mean-এর 95% percentile bootstrap CI।"""
    m = [sum(RNG.choice(vals) for _ in vals) / len(vals) for _ in range(n)]
    m.sort()
    return m[int(0.025 * n)], m[int(0.975 * n)]


def main():
    cases, truth, res, primary, status, kl, P, base, allrun = setup()
    honest = [c["id"] for c in cases if truth[c["id"]].honestly_issued]
    forged = [c["id"] for c in cases if not truth[c["id"]].honestly_issued]
    out = {"primary_impls": primary, "n_impls": len(primary), "languages": sorted({lang(i) for i in primary}),
           "status": status, "n_honest": len(honest), "n_forged": len(forged)}

    # ── সব impl-সহ মূল ফল ──
    fl = flags_for(cases, truth, res, primary, P, base)
    out["headline"] = {d: dict(honest_fp=sum(fl[x][d] for x in honest),
                               honest_fp_rate=fp_rate(fl, honest, d),
                               forged_flags=sum(fl[x][d] for x in forged)) for d in DET}

    # ── D1: FP(k) curve, ১০০০ ভাষা-quota subset ──
    d1 = {}
    for k in (2, 4, 8, 16, 24, len(primary)):
        reps = 1 if k == len(primary) else 1000
        acc = defaultdict(list)
        for _ in range(reps):
            sub = primary if k == len(primary) else quota_subset(primary, k)
            f = flags_for([c for c in cases if c["id"] in set(honest)], truth, res, sub, P, base)
            for d in DET: acc[d].append(fp_rate(f, honest, d))
        d1[k] = {d: q(v) for d, v in acc.items()}
    out["D1"] = d1

    # ── H2: pairwise disagreement, cross বনাম within language ──
    def verdict(i, x):
        r = res[i].get(x)
        return None if r is None or r.stage == "keyload" else r.accepted
    pairs = {}
    for a, b in combinations(primary, 2):
        v = [(verdict(a, x), verdict(b, x)) for x in honest]
        v = [(p, s) for p, s in v if p is not None and s is not None]
        pairs[(a, b)] = [int(p != s) for p, s in v]
    def rate(lst): return sum(lst) / len(lst) if lst else 0.0
    def diff(labels):
        cross = [rate(v) for (a, b), v in pairs.items() if labels[a] != labels[b]]
        within = [rate(v) for (a, b), v in pairs.items() if labels[a] == labels[b]]
        return statistics.mean(cross) - statistics.mean(within), statistics.mean(cross), statistics.mean(within)
    labels = {i: lang(i) for i in primary}
    obs, cross_m, within_m = diff(labels)
    langs = [labels[i] for i in primary]
    ge = 0
    for _ in range(10000):
        RNG.shuffle(langs)
        ge += diff(dict(zip(primary, langs)))[0] >= obs
    p = (ge + 1) / 10001
    # bootstrap CI (honest টোকেন resample)
    idx = {x: n for n, x in enumerate(honest)}
    pair_tok = {}
    for (a, b) in pairs:
        pair_tok[(a, b)] = {x: int(verdict(a, x) != verdict(b, x)) for x in honest
                            if verdict(a, x) is not None and verdict(b, x) is not None}
    bs = []
    for _ in range(2000):
        samp = [RNG.choice(honest) for _ in honest]
        cr, wi = [], []
        for (a, b), d in pair_tok.items():
            v = [d[x] for x in samp if x in d]
            if not v: continue
            (cr if labels[a] != labels[b] else wi).append(sum(v) / len(v))
        bs.append(statistics.mean(cr) - statistics.mean(wi))
    bs.sort()
    out["H2"] = dict(cross_mean=cross_m, within_mean=within_m, diff_pp=100 * obs, p_one_sided=p,
                     boot95_pp=(100 * bs[50], 100 * bs[1949]), n_pairs=len(pairs),
                     supported=bool(p < 0.05 and obs > 0))

    # ── H3: B2 held-out FP ──
    groups = {"V1_seed2-3": [x for x in honest if x.startswith("V1/") and not x.endswith("/s1")],
              "V2": [x for x in honest if x.startswith("V2/")], "V3": [x for x in honest if x.startswith("V3/")]}
    groups["heldout_all"] = sum(groups.values(), [])
    h3 = {}
    for g, ids in groups.items():
        v = [int(fl[x]["B2"]) for x in ids]
        lo, hi = boot_ci(v)
        h3[g] = dict(n=len(ids), fp=sum(v), rate=sum(v) / len(v), ci95=(lo, hi))
    h3["profile_rules"] = sum(len(P[i]) for i in primary)
    h3["supported"] = h3["heldout_all"]["rate"] >= 0.05 and h3["heldout_all"]["ci95"][0] > 0
    out["H3"] = h3

    # ── D5: triage ──
    def eclass(r): return "SLOW" if False else (r.error.split(":")[0] or "reject")
    d5 = {}
    for d in DET:
        flagged = [x for x in fl if fl[x][d]]
        clusters = set()
        for x in flagged:
            rs = [(i, res[i][x]) for i in primary if x in res[i] and res[i][x].stage != "keyload"]
            if d.startswith("PROV"):
                clusters |= {(i, "A") for i, r in rs if judge.judge_truth(r, truth[x], 0 if d == "PROV_claim" else base[i]).klass == "A"}
            else:
                clusters |= {(i, eclass(r)) for i, r in rs if not r.accepted}
        d5[d] = dict(alerts=len(flagged), per_1000=1000 * len(flagged) / len(fl), clusters=len(clusters))
    out["D5"] = d5

    # ── D6: artifacts ──
    out["D6"] = dict(keyload_rate={i: kl[i] for i in sorted(kl)},
                     excluded={i: s for i, s in status.items() if s not in ("ok", "not run")})

    # ── sensitivity ──
    sens = {}
    for name, impls in (("with_excluded", sorted(set(primary) | {i for i in allrun if status.get(i, "").startswith("keyload")})),
                        ("without_reserves", [i for i in primary if i not in judge.RESERVES])):
        f = flags_for([c for c in cases if c["id"] in set(honest)], truth, res, impls, P, base)
        sens[name] = dict(n_impls=len(impls), **{d: fp_rate(f, honest, d) for d in DET})
    out["sensitivity"] = sens

    (D / "results/analysis.json").write_text(json.dumps(out, indent=1, default=str))
    # ── stdout ──
    print(f"primary: {len(primary)} impls, {len(out['languages'])} languages; honest={len(honest)}, forged={len(forged)}")
    print("\n| detector | honest FP | rate | forged flags |\n|---|---|---|---|")
    for d in DET:
        h = out["headline"][d]
        print(f"| {d} | {h['honest_fp']}/{len(honest)} | {h['honest_fp_rate']:.1%} | {h['forged_flags']} |")
    print("\nD1 (median [IQR]):\n| k | " + " | ".join(DET) + " |\n|---|" + "---|" * len(DET))
    for k, v in d1.items():
        print(f"| {k} | " + " | ".join(f"{v[d]['median']:.1%} [{v[d]['q1']:.1%}–{v[d]['q3']:.1%}]" for d in DET) + " |")
    h2 = out["H2"]
    print(f"\nH2: cross={h2['cross_mean']:.3f} within={h2['within_mean']:.3f} diff={h2['diff_pp']:.1f}pp "
          f"95%CI=[{h2['boot95_pp'][0]:.1f},{h2['boot95_pp'][1]:.1f}] p={h2['p_one_sided']:.4f} → supported={h2['supported']}")
    print("\nH3 (B2 held-out):")
    for g in groups:
        x = h3[g]; print(f"  {g:12} {x['fp']}/{x['n']} = {x['rate']:.1%}  CI95=[{x['ci95'][0]:.1%},{x['ci95'][1]:.1%}]")
    print(f"  profile rules={h3['profile_rules']}  → supported={h3['supported']}")
    print("\nD5:", {d: (v["alerts"], round(v["per_1000"], 1), v["clusters"]) for d, v in d5.items()})
    print("sensitivity:", json.dumps(sens))


if __name__ == "__main__":
    main()
