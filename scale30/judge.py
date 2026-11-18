"""scale30 judge — results + truth → B0/B1/B2/PROV (PREREG §5)।
ব্যবহার:
  python judge.py                       # সব gate-পাস impl, পুরো corpus → results/judged.csv + সারাংশ
  python judge.py --regression          # PREREG §7: পুরনো ৪ Python lib × E3-এর ২৪ family (আশা: B0 = 9/24)
  python judge.py --corpus DIR --results DIR
                                        # নিজের corpus (DIR/cases.json + DIR/truth.json), run_all.sh-এর ফল DIR-এ;
                                        # primary ৩২টা impl, B2 profile আর baseline মূল scale30 থেকে → DIR/judged.csv
  python judge.py --newset DIR          # PREREG_newlangs: নতুন impl (DIR/gate, DIR/main), মূল corpus → L1–L3
"""
import argparse, csv, json, statistics, sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

D = Path(__file__).resolve().parent
sys.path.insert(0, str(D.parent))
from oracle import TokenTruth, judge_truth  # noqa: E402

E3_IMPLS = ["python/pyjwt", "python/python-jose", "python/authlib", "python/jwcrypto"]
E3_FAMILIES = ([f"V1/{a}/{v}/s1" for a in ("HS256", "HS384", "HS512") for v in ("16B", "min", "64B")]
               + [f"V1/{a}/{b}/s1" for a in ("RS256", "RS384", "RS512") for b in (2048, 1024)]
               + [f"V1/{a}/{b}/s1" for a in ("PS256", "PS384") for b in (2048, 1024)] + ["V1/PS512/2048/s1"]
               + ["V1/ES256/P-256/s1", "V1/ES384/P-384/s1", "V1/ES512/P-521/s1", "V1/EdDSA/Ed25519/s1"])


@dataclass
class R:                                  # oracle.judge_truth যে আকার চায়
    library: str
    accepted: bool
    claims: dict = field(default_factory=dict)
    error: str = ""
    seconds: float = 0.0
    stage: str = ""


def load_results(d):
    res = defaultdict(dict)               # impl → case → R
    for f in sorted(Path(d).glob("*.jsonl")):
        for line in f.open():
            r = json.loads(line)
            res[r["impl"]][r["case"]] = R(r["impl"], r["accepted"], r["claims"] or {}, r["error"],
                                          r["ns"] / 1e9, r["stage"])
    return res


# PREREG §2 — প্রার্থী (ক্রম = বাদ পড়ার ক্রম নির্ধারণে ব্যবহৃত) আর reserve (ক্রমানুসারে)
CANDIDATES = ["python/pyjwt", "python/python-jose", "python/authlib", "python/jwcrypto", "python/joserfc",
              "python/jwskate", "python/cryptojwt", "node/jose", "node/jsonwebtoken", "node/fast-jwt",
              "node/jsrsasign", "node/njwt", "node/node-jose", "go/golang-jwt", "go/jwx", "go/go-jose",
              "go/kataras-jwt", "java/nimbus-jose-jwt", "java/jjwt", "java/java-jwt", "java/jose4j",
              "php/php-jwt", "php/lcobucci-jwt", "php/jwt-framework", "rust/jsonwebtoken", "rust/josekit",
              "rust/jwt-simple", "ruby/ruby-jwt", "ruby/json-jwt", "dotnet/IdentityModel", "dotnet/jose-jwt",
              "dotnet/JWT"]
RESERVES = ["node/jwt-simple", "node/cloudflare-worker-jwt"]
# PREREG §3 G1 ব্যতিক্রম: library-র নিজের documentation-এ unsupported বলা alg (উৎস সহ)
DOC_UNSUPPORTED = {
    "node/jwt-simple": ({"ES256"}, "README §Algorithms: HS256, HS384, HS512, RS256 only"),
}
KEYLOAD_MAX = 0.05


def gate_status(d):
    """impl → [fail কারণ] (খালি = pass)।"""
    out = {}
    for impl, rows in load_results(d).items():
        unsup, _ = DOC_UNSUPPORTED.get(impl, (set(), ""))
        fails = []
        for c, r in rows.items():
            g, alg = c.split("/")[0], c.split("/")[2] if c.count("/") >= 2 else ""
            if g == "G1":
                if alg in unsup: continue
                if not r.accepted: fails.append(f"G1 {c[3:]} rejected [{r.stage}] {r.error[:90]}")
                elif r.claims.get("role") != "user": fails.append(f"G3 {c[3:]} role={r.claims.get('role')!r}")
            elif r.accepted:
                fails.append(f"{g} {c[3:]} ACCEPTED")
        out[impl] = fails
    return out


def gate_pass(d):
    return {i for i, f in gate_status(d).items() if not f}


def select_impls(res, cases, ok):
    """PREREG §2/§3: gate + keyload ≤5% → primary set; বাদ পড়া প্রার্থীর সমান সংখ্যক reserve।"""
    honest = [c["id"] for c in cases if c["meta"]["family"] in ("V1", "V2", "V3")]
    def kl(i): return sum(res[i][x].stage == "keyload" for x in honest if x in res[i]) / len(honest)
    status = {}
    for i in CANDIDATES + RESERVES:
        if i not in res: status[i] = "not run"
        elif i not in ok: status[i] = "gate fail"
        elif kl(i) > KEYLOAD_MAX: status[i] = f"keyload {kl(i):.1%} > 5%"
        else: status[i] = "ok"
    dropped = [i for i in CANDIDATES if status[i] not in ("ok", "not run")]
    ran = [i for i in CANDIDATES if status[i] != "not run"]
    chosen = [i for i in ran if status[i] == "ok"]
    need = len(dropped)
    for r in RESERVES:
        if need and status[r] == "ok": chosen.append(r); need -= 1
    return sorted(chosen), status, {i: kl(i) for i in res}


def cap_profile(res, cases, impls):
    """B2: P_i = V1 seed-1-এর যে (alg, variant) বৈধ টোকেন i reject করল (verify stage)।"""
    P = {i: set() for i in impls}
    for c in cases:
        m = c["meta"]
        if m["family"] == "V1" and m["seed"] == 1:
            for i in impls:
                r = res[i].get(c["id"])
                if r and not r.accepted and r.stage != "keyload":
                    P[i].add((m["alg"], m["variant"]))
    return P


def baselines(res, cases, impls):
    """resource baseline প্রতি impl-এ: বৈধ HS256-min কেসের median (PREREG §3)।"""
    ids = [c["id"] for c in cases if c["id"].startswith("V1/HS256/min/")]
    return {i: statistics.median(res[i][x].seconds for x in ids if x in res[i]) for i in impls}


def detect(case, rs, truth, P, base):
    """rs = keyload বাদ দেওয়া R-এর তালিকা। ফেরত: dict(detector → flag)।"""
    acc = [r for r in rs if r.accepted]
    n, a = len(rs), len(acc)
    b0 = 0 < a < n
    b1 = 0 < a < n / 2
    key = (case["meta"]["alg"], case["meta"]["variant"])
    rs2 = [r for r in rs if key not in P.get(r.library, ())]
    a2 = sum(r.accepted for r in rs2)
    b2 = 0 < a2 < len(rs2)
    prov_j = [judge_truth(r, truth, base[r.library]) for r in rs]
    prov = any(j.klass == "A" for j in prov_j)
    # POST-HOC (pre-registered নয়): শুধু claim oracle — resource (SLOW) উপাদান বাদ।
    # কারণ: single-shot timing + alg-নিরপেক্ষ baseline runtime-জুড়ে অস্থির (EXP_scale30.md দেখুন)
    prov_claim = any(judge_truth(r, truth, 0).klass == "A" for r in rs)
    return dict(B0=b0, B1=b1, B2=b2, PROV=prov, PROV_claim=prov_claim), prov_j


def judge_cases(cases, truth, res, impls, P, base):
    """প্রতি কেসে detector flag-এর একটা row; keyload ব্যর্থতা বাদ দিয়ে গোনা।"""
    rows, keyload = [], defaultdict(int)
    for c in cases:
        rs = []
        for i in impls:
            r = res.get(i, {}).get(c["id"])
            if r is None: continue
            if r.stage == "keyload": keyload[i] += 1; continue
            rs.append(r)
        flags, pj = detect(c, rs, truth[c["id"]], P, base)
        rows.append(dict(case=c["id"], family=c["meta"]["family"], honest=truth[c["id"]].honestly_issued,
                         n=len(rs), n_accept=sum(r.accepted for r in rs), **flags,
                         prov_A=";".join(j.library for j in pj if j.klass == "A"),
                         rejecters=";".join(r.library for r in rs if not r.accepted),
                         acceptors=";".join(r.library for r in rs if r.accepted)))
    return rows, keyload


def run(impls_filter=None, case_filter=None, quiet=False):
    cases = json.loads((D / "corpus/cases.json").read_text())["cases"]
    truth = {k: TokenTruth(**v) for k, v in json.loads((D / "corpus/truth.json").read_text()).items()}
    res = load_results(D / "results/main")
    ok = gate_pass(D / "results/gate")
    allcases = json.loads((D / "corpus/cases.json").read_text())["cases"]
    if impls_filter:
        impls = sorted(i for i in res if i in ok and i in impls_filter)
    else:
        impls, status, _ = select_impls(res, allcases, ok)
        if not quiet:
            for i, st in status.items():
                if st not in ("ok", "not run"): print(f"  excluded (PREREG): {i} — {st}")
    if case_filter: cases = [c for c in cases if c["id"] in case_filter]
    P = cap_profile(res, allcases, impls)
    base = baselines(res, allcases, impls)
    rows, keyload = judge_cases(cases, truth, res, impls, P, base)
    return rows, impls, P, keyload, base


def summarize(rows, impls, keyload):
    L = [f"impls ({len(impls)}): {', '.join(impls)}"]
    for grp in ("V1", "V2", "V3", "F1", "F2"):
        g = [r for r in rows if r["family"] == grp]
        if not g: continue
        L.append(f"{grp:3} n={len(g):5} " + "  ".join(f"{d}={sum(r[d] for r in g):4}" for d in ("B0", "B1", "B2", "PROV", "PROV_claim")))
    h = [r for r in rows if r["honest"]]
    L.append(f"honest total n={len(h)}: " + "  ".join(f"{d} FP={sum(r[d] for r in h)}" for d in ("B0", "B1", "B2", "PROV", "PROV_claim")))
    if keyload: L.append("keyload artifacts: " + ", ".join(f"{k}={v}" for k, v in keyload.items()))
    return "\n".join(L)


def run_custom(corpus_dir, results_dir):
    """নিজের corpus: primary set, B2 profile আর resource baseline মূল scale30 থেকে (তুলনীয় রাখতে)।"""
    corpus_dir, results_dir = Path(corpus_dir), Path(results_dir)
    main_cases = json.loads((D / "corpus/cases.json").read_text())["cases"]
    main_res = load_results(D / "results/main")
    primary = json.loads((D / "results/analysis.json").read_text())["primary_impls"]
    P = cap_profile(main_res, main_cases, primary)
    base = baselines(main_res, main_cases, primary)
    cases = json.loads((corpus_dir / "cases.json").read_text())["cases"]
    truth = {k: TokenTruth(**v) for k, v in json.loads((corpus_dir / "truth.json").read_text()).items()}
    res = load_results(results_dir)
    missing = [i for i in primary if i not in res]
    if missing: print("  ⚠️ ফল নেই:", ", ".join(missing))
    for c in cases:
        c.setdefault("meta", {}).setdefault("alg", ""); c["meta"].setdefault("variant", "")
        c["meta"].setdefault("family", c["id"].split("/")[0])
    rows, keyload = judge_cases(cases, truth, res, primary, P, {i: base.get(i, 0) for i in primary})
    return rows, primary, keyload


# PREREG_newlangs §2 — নতুন ecosystem-এর প্রার্থী; reserve নেই। নাম = adapter-এর `impl` field।
NEW_CANDIDATES = ["c/libjwt", "c/cjose", "erlang/erlang-jose", "swift/jwt-kit", "swift/swift-jwt",
                  "dart/dart_jsonwebtoken", "dart/jose"]
HELDOUT = {"V1_seed2-3": lambda x: x.startswith("V1/") and not x.endswith("/s1"),
           "V2": lambda x: x.startswith("V2/"), "V3": lambda x: x.startswith("V3/")}


def boot_ci(vals, n=10000, seed=1):
    """০/১ তালিকা → mean-এর 95% percentile bootstrap CI (analysis.py-র মতো)।"""
    import random
    rng = random.Random(seed)
    m = sorted(sum(rng.choice(vals) for _ in vals) / len(vals) for _ in range(n))
    return m[int(0.025 * n)], m[int(0.975 * n)]


def run_newset(d):
    """PREREG_newlangs: মূল corpus-এ নতুন impl-set আলাদাভাবে। B2 profile আর baseline এই set থেকেই।"""
    d = Path(d)
    cases = json.loads((D / "corpus/cases.json").read_text())["cases"]
    truth = {k: TokenTruth(**v) for k, v in json.loads((D / "corpus/truth.json").read_text()).items()}
    res, ok = load_results(d / "main"), gate_pass(d / "gate")
    honest = [c["id"] for c in cases if c["meta"]["family"] in ("V1", "V2", "V3")]
    status, impls = {}, []
    for i in NEW_CANDIDATES:
        if i not in res: status[i] = "not run"; continue
        if i not in ok: status[i] = "gate fail"; continue
        kl = sum(res[i][x].stage == "keyload" for x in honest if x in res[i]) / len(honest)
        status[i] = f"keyload {kl:.1%} > 5%" if kl > KEYLOAD_MAX else "ok"
        if status[i] == "ok": impls.append(i)
    P = cap_profile(res, cases, impls)
    base = baselines(res, cases, impls)
    rows, keyload = judge_cases(cases, truth, res, impls, P, base)
    return rows, impls, status, keyload


def newset_report(rows, impls, status):
    L = [f"{i}: {st}" for i, st in status.items()]
    L.append(f"impls ({len(impls)}): {', '.join(impls)}")
    forged_acc = [r for r in rows if not r["honest"] and r["acceptors"]]
    L.append(f"L1: জাল টোকেন গৃহীত = {len(forged_acc)} → " + ("supported" if not forged_acc else "FALSIFIED (sealed/-এ নাও)"))
    for r in forged_acc: L.append(f"   {r['case']} → {r['acceptors']}")
    ids = {r["case"]: r for r in rows if r["honest"]}
    allv = []
    for g, f in HELDOUT.items():
        v = [int(r["B2"]) for x, r in ids.items() if f(x)]
        allv += v
        if v: L.append(f"L2 {g:10} n={len(v):3} B2 FP={sum(v):3} ({sum(v)/len(v):.1%})")
    if allv:
        lo, hi = boot_ci(allv); rate = sum(allv) / len(allv)
        L.append(f"L2 held-out  n={len(allv)} rate={rate:.1%} CI95=[{lo:.1%}, {hi:.1%}] → " +
                 ("supported" if rate >= 0.05 and lo > 0 else "not supported"))
    pc = sum(r["PROV_claim"] for r in ids.values())
    L.append(f"L3: PROV_claim honest FP = {pc} → " + ("supported" if pc == 0 else "FALSIFIED"))
    L.append("honest FP: " + "  ".join(f"{k}={sum(r[k] for r in ids.values())}" for k in ("B0", "B1", "B2", "PROV")))
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--regression", action="store_true")
    ap.add_argument("--corpus"); ap.add_argument("--results")
    ap.add_argument("--newset", metavar="DIR", help="PREREG_newlangs: DIR/gate + DIR/main")
    a = ap.parse_args()
    if a.newset:
        rows, impls, status, keyload = run_newset(a.newset)
        if not impls: sys.exit("\n".join(f"{i}: {st}" for i, st in status.items()) + "\nকোনো impl নেই")
        out = Path(a.newset) / "judged.csv"
        with out.open("w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
        print(newset_report(rows, impls, status))
        if keyload: print("keyload artifacts: " + ", ".join(f"{k}={v}" for k, v in keyload.items()))
        print(f"→ {out}")
        return
    if a.corpus:
        res_dir = a.results or a.corpus
        rows, impls, keyload = run_custom(a.corpus, res_dir)
        if not rows: sys.exit("corpus-এ কোনো কেস নেই")
        out = Path(res_dir) / "judged.csv"
        with out.open("w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
        fams = sorted({r["family"] for r in rows})
        for fam in fams:
            g = [r for r in rows if r["family"] == fam]
            print(f"{fam:6} n={len(g):4} honest={sum(r['honest'] for r in g):4} " +
                  "  ".join(f"{d}={sum(r[d] for r in g)}" for d in ("B0", "B1", "B2", "PROV", "PROV_claim")))
        acc = [r for r in rows if not r["honest"] and r["acceptors"]]
        print(f"জাল টোকেন যা কেউ গ্রহণ করেছে: {len(acc)}")
        for r in acc: print("  ", r["case"], "→", r["acceptors"])
        print(f"→ {out}")
        return
    if a.regression:
        rows, impls, *_ = run(set(E3_IMPLS), set(E3_FAMILIES))
        fp = [r["case"] for r in rows if r["B0"]]
        print(f"REGRESSION: B0 FP = {len(fp)}/{len(rows)} (E3-তে ছিল 9/24)")
        for x in fp: print("  ", x, "| rejecters:", [r["rejecters"] for r in rows if r["case"] == x][0])
        return
    rows, impls, P, keyload, base = run()
    out = D / "results/judged.csv"
    with out.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
    print(summarize(rows, impls, keyload))
    print(f"→ {out}")


if __name__ == "__main__":
    main()
