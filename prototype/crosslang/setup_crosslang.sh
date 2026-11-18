#!/usr/bin/env bash
# Cross-language (Node) setup — reproducibility। পূর্বশর্ত: node + npm।
# চালাও:  bash setup_crosslang.sh      (তারপর: bash run_crosslang.sh)
cd "$(dirname "$0")"
install() {   # $1 = dir, $2 = npm spec
  mkdir -p "$1"
  ( cd "$1" && npm init -y >/dev/null 2>&1 && npm install "$2" >/dev/null 2>&1 ) \
    && echo "  $1 <- $2 OK" || echo "  $1 <- $2 FAILED"
}
install v851       "jsonwebtoken@8.5.1"
install v902       "jsonwebtoken@9.0.2"
install hono_vuln  "hono@4.11.3"
install hono_fixed "hono@4.11.4"
echo "✅ done। এখন চালাও: bash run_crosslang.sh"
