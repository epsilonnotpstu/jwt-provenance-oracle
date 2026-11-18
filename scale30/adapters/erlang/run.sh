#!/usr/bin/env bash
# Erlang/BEAM adapter — micromamba env `beam` (conda-forge erlang + elixir, sudo ছাড়া)।
# build: ./run.sh --build   (mix deps.get + escript)
set -euo pipefail
D="$(cd "$(dirname "$0")" && pwd)"
export PATH="$HOME/.local/opt/mamba/envs/beam/bin:$PATH" ELIXIR_ERL_OPTIONS="+fnu" ERL_FLAGS="+fnu"
if [ "${1:-}" = "--build" ]; then cd "$D" && mix deps.get >/dev/null && MIX_ENV=prod mix escript.build; exit; fi
exec escript "$D/scale30_erlang" "$@"
