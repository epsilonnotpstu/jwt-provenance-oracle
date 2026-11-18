#!/usr/bin/env bash
# Cross-language Phase B-ext runner (Node)। পূর্বশর্ত: setup_crosslang.sh চালানো।
set -e
cd "$(dirname "$0")"
echo "########## jsonwebtoken algorithm confusion"
node confusion_jsonwebtoken.js ./v851/node_modules/jsonwebtoken
echo
node confusion_jsonwebtoken.js ./v902/node_modules/jsonwebtoken
echo
echo "########## Hono CVE-2026-22817 (verifyWithJwks alg fallback)"
node cve_2026_22817_hono.js ./hono_vuln/node_modules/hono
echo
node cve_2026_22817_hono.js ./hono_fixed/node_modules/hono
