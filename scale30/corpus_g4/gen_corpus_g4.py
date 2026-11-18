"""G4 batch generator (PREREG_g4.md §2): the frozen G3 generator, one 4,000-token batch per call.
usage: python gen_corpus_g4.py <k>        → corpus_g4/batch_<k>/ (seed 20261100+k, ids G4/b<k>/d<d>/<i>)
"""
import json, subprocess, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
k = int(sys.argv[1])
out = HERE / f"batch_{k}"
subprocess.run([sys.executable, str(HERE.parent / "corpus_g3" / "gen_corpus_g3.py"), "--seed", str(20261100 + k),
                "--out", str(out), "--per-depth", "800"], check=True, stdout=subprocess.DEVNULL)
# re-key ids G3/d<d>/<i> → G4/b<k>/d<d>/<i> in every file (content, signatures and tags unchanged)
for f in ("cases.json", "truth.json", "signed.json"):
    p = out / f
    obj = json.loads(p.read_text())
    if f == "cases.json":
        for c in obj["cases"]:
            c["id"] = c["id"].replace("G3/", f"G4/b{k}/", 1); c["meta"]["family"] = "G4"; c["meta"]["batch"] = k
    else:
        obj = {x.replace("G3/", f"G4/b{k}/", 1): v for x, v in obj.items()}
    p.write_text(json.dumps(obj, indent=0, ensure_ascii=False))
man = json.loads((out / "corpus_manifest.json").read_text())
import hashlib
man["batch"] = k
man["sha256"] = {f: hashlib.sha256((out / f).read_bytes()).hexdigest() for f in ("cases.json", "truth.json", "signed.json")}
(out / "corpus_manifest.json").write_text(json.dumps(man, indent=1))
print(json.dumps({x: man[x] for x in ("batch", "n_cases", "seed", "self_check", "primary_stratum", "sha256")}))
