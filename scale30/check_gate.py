"""PREREG §3 gate report (judge.gate_status ব্যবহার করে — একই নিয়ম এক জায়গায়)।"""
import sys
from pathlib import Path
from judge import gate_status, load_results, DOC_UNSUPPORTED, D
d = Path(sys.argv[1]) if len(sys.argv) > 1 else D / "results" / "gate"
res = load_results(d)
for impl, fails in sorted(gate_status(d).items()):
    ver = ""
    print(f"{'PASS' if not fails else 'FAIL'}  {impl:<34}" + (f"  (G1 exempt: {DOC_UNSUPPORTED[impl][1]})" if impl in DOC_UNSUPPORTED else ""))
    for x in fails: print("      ", x)
