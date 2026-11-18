#!/usr/bin/env bash
# micromamba Ruby 3.3 (sudo ছাড়া install), gem গুলো vendor/bundle-এ
D="$(cd "$(dirname "$0")" && pwd)"
export PATH="$HOME/.local/opt/mamba/envs/ruby/bin:$PATH" BUNDLE_GEMFILE="$D/Gemfile"
exec ruby "$D/run.rb" "$@"
