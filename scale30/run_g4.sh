#!/usr/bin/env bash
# PREREG_g4 §2 driver: batch k = 1..6 → generate, run 32 primary + newlangs, interim (acceptance vectors only), stop rule.
set -u
D="$(cd "$(dirname "$0")" && pwd)"; cd "$D"
for k in 1 2 3 4 5 6; do
  B=corpus_g4/batch_$k
  [ -f $B/cases.json ] || ../.venv/bin/python corpus_g4/gen_corpus_g4.py $k | tee -a corpus_g4/manifests.log
  ./run_all.sh $B/cases.json $B/results > $B/run_main.log 2>&1 || { echo "batch $k: run_all FAILED"; exit 1; }
  for f in $B/results/*.jsonl; do n=$(wc -l < "$f"); [ "$n" -ne 4000 ] && { echo "batch $k: SHORT $f $n"; exit 1; }; done
  ./run_newlangs.sh $B/cases.json $B/results_new > $B/run_new.log 2>&1 || echo "batch $k: newlangs failed (descriptive only)"
  ../.venv/bin/python g4_interim.py | tee corpus_g4/interim_latest.txt
  grep -q "DECISION: STOP" corpus_g4/interim_latest.txt && { echo "stopped after batch $k"; exit 0; }
done
