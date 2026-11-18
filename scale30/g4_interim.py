"""PREREG_g4 §2 interim look: acceptance vectors ONLY (no v4/v3/baselines). Prints the stopping decision.
usage: python g4_interim.py            (reads corpus_g4/batch_*/cases.json + batch_*/results)
"""
import json, sys
from collections import Counter
from pathlib import Path
D = Path(__file__).resolve().parent
sys.path.insert(0, str(D))
import analyze_g2 as A  # noqa: E402

impls = json.loads((D / "results/analysis.json").read_text())["primary_impls"]
vec, rows = {}, []
for b in sorted((D / "corpus_g4").glob("batch_*"), key=lambda p: int(p.name.split("_")[1])):
    if not (b / "results").is_dir(): continue
    cases = json.loads((b / "cases.json").read_text())["cases"]
    vec.update(A.accept_vectors(cases, A.load_raw(b / "results"), impls))
    f = Counter(vec.values()); f1, f2 = sum(v == 1 for v in f.values()), sum(v == 2 for v in f.values())
    gt = f1 / len(vec); chao1 = len(f) + (f1 * f1 / (2 * f2) if f2 else f1 * (f1 - 1) / 2)
    rows.append(dict(batch=int(b.name.split("_")[1]), N=len(vec), distinct=len(f), f1=f1, f2=f2, good_turing=gt, chao1=chao1))
for r in rows:
    print(f"after batch {r['batch']}: N={r['N']} distinct={r['distinct']} f1={r['f1']} f2={r['f2']} "
          f"Good–Turing={r['good_turing']:.3%} Chao1={r['chao1']:.1f}")
last = rows[-1]
stop = last["good_turing"] < 0.005 or last["N"] >= 24000
print("DECISION:", "STOP" + (" (saturated)" if last["good_turing"] < 0.005 else " (N cap)") if stop else "CONTINUE")
(D / "corpus_g4/interim.json").write_text(json.dumps(rows, indent=1))
