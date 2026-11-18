#!/usr/bin/env bash
# ব্যবহার: scale30/run_all.sh <cases.json> <outdir>  — ৮ ভাষার সব adapter একই cases ফাইলে
set -e
D="$(cd "$(dirname "$0")" && pwd)"
C="$(realpath "$1")"; O="$(realpath -m "$2")"; mkdir -p "$O"
source "$D/env.sh"
(cd "$D/adapters/python" && .venv/bin/python run.py "$C" "$O")
node "$D/adapters/node/run.mjs" "$C" "$O" jose jsonwebtoken fast-jwt jsrsasign njwt node-jose jwt-simple cloudflare-worker-jwt
"$D/adapters/go/bin/adapter" "$C" "$O"
"$D/adapters/java/run.sh" "$C" "$O" 2>&1 | grep -v '^SLF4J' >&2
"$D/adapters/php/run.sh" "$C" "$O"
"$D/adapters/rust/run.sh" "$C" "$O"
"$D/adapters/ruby/run.sh" "$C" "$O"
"$D/adapters/dotnet/run.sh" "$C" "$O"
