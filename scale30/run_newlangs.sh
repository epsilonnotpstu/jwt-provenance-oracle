#!/usr/bin/env bash
# ব্যবহার: scale30/run_newlangs.sh <cases.json> <outdir> — PREREG_newlangs-এর নতুন ecosystem (C, BEAM, Swift, Dart)।
# run_all.sh (মূল ৩২) অপরিবর্তিত রাখতে আলাদা। প্রতিটা adapter network ছাড়া (unshare -rn), TZ=UTC, LC_ALL=C।
set -e
D="$(cd "$(dirname "$0")" && pwd)"
C="$(realpath "$1")"; O="$(realpath -m "$2")"; mkdir -p "$O"
for a in c erlang swift dart; do
  env TZ=UTC LC_ALL=C unshare -rn "$D/adapters/$a/run.sh" "$C" "$O"
done
