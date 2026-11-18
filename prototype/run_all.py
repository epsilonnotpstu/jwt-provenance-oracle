"""
run_all.py — পুরো pipeline এক কমান্ডে (reproducibility)
========================================================
    python run_all.py

ধাপে ধাপে চালায়: unit test → baseline → E2 (true-positive) → capability matrix
→ E3 (non-circular corpus)। শেষে এক লাইনের সারাংশ।
"""
import subprocess, sys, warnings
warnings.filterwarnings("ignore")

STEPS = [
    ("Unit — ঘর ১ (message struct)", "test_ghor1.py"),
    ("Unit — harness baseline (৪ library)", "test_harness.py"),
    ("E2 — true-positive যাচাই (VULN/SAFE target)", "fuzz_with_targets.py"),
    ("Capability matrix (empirical C-শ্রেণী)", "probe_algsupport.py"),
    ("E3 — naive বনাম ground-truth oracle", "corpus_experiment.py"),
    ("Phase C — grammar coverage (৫ attack-class)", "grammar_coverage.py"),
    ("Phase C-2 — random fuzzing campaign (seeded)", "random_fuzz.py"),
]


def main():
    py = sys.executable
    for title, script in STEPS:
        print("\n" + "█" * 72)
        print(f"█ {title}   ({script})")
        print("█" * 72)
        r = subprocess.run([py, "-W", "ignore", script], capture_output=True, text=True)
        out = "\n".join(l for l in r.stdout.splitlines()
                        if "deprecat" not in l.lower() and "import jwt" not in l and "compatible before" not in l)
        print(out)
        if r.returncode != 0:
            print(f"❌ {script} ব্যর্থ (exit {r.returncode}):\n{r.stderr[-800:]}")
            return r.returncode
    print("\n" + "=" * 72)
    print("✅ সব ধাপ সম্পন্ন। মূল ফল: EXP_corpus_v2.md, capability_matrix.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
