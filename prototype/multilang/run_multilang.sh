#!/usr/bin/env bash
# Cross-language algorithm-confusion survey runner. পূর্বশর্ত: setup_multilang.sh।
# যা installed শুধু তাই চলে; বাকিটা skip।
cd "$(dirname "$0")"
ROOT="$(cd .. && pwd)"
echo "########## Python (extra libs: joserfc, python-jwt)"
"$ROOT/.venv/bin/python" py_extra_confusion.py 2>/dev/null | grep -vE '^$'
echo; echo "########## Go (golang-jwt/v5)"
( cd go && bash -c 'GOFLAGS=-mod=mod go run confusion.go' 2>/dev/null )
echo; echo "########## Node (panva/jose)"
( cd node_jose && node confusion.mjs 2>/dev/null )
echo; echo "########## Java (nimbus-jose-jwt)"
( cd java && java -cp "lib/nimbus.jar:." Confusion 2>/dev/null )
echo; echo "########## PHP (firebase/php-jwt)"
( cd php && php confusion.php 2>/dev/null )
echo; echo "########## (see ../crosslang for jsonwebtoken old/new + Hono CVE)"
