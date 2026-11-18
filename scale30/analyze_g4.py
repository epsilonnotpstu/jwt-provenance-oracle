"""PREREG_g4 analysis: analyze_g3 (frozen @948d312) with numdate_frac moved out of the primary stratum.
usage: python analyze_g4.py --corpus corpus_g4/merged --results corpus_g4/merged/results [--newlangs DIR]
Printed labels H3-1..H3-4 correspond to H4-1..H4-4 (PREREG_g4 §3)."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import analyze_g3 as G3  # noqa: E402
G3.EXCL = G3.EXCL | {"numdate_frac"}
if __name__ == "__main__":
    G3.main()
