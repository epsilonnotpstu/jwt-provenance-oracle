#!/usr/bin/env bash
# ব্যবহার: adapters/rust/run.sh <cases.json> <outdir>  — দুটো binary (BoringSSL/OpenSSL symbol সংঘর্ষ এড়াতে)
D="$(cd "$(dirname "$0")" && pwd)"
"$D/target/release/scale30_rust" "$@" && "$D/target-jwtsimple/release/scale30_rust" "$@"
