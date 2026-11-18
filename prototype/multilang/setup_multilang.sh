#!/usr/bin/env bash
# Cross-language survey setup (reproducibility)। পূর্বশর্ত: go, node/npm, java(javac),
# php, এবং প্রকল্পের .venv (uv)। যা toolchain নেই তা skip করো।
set -u
cd "$(dirname "$0")"
ROOT="$(cd .. && pwd)"

echo "== Python extra libs =="
uv pip install -q --python "$ROOT/.venv/bin/python" python-jwt joserfc jwcrypto && echo "  ok"

echo "== Go golang-jwt/v5 =="
( cd go && bash -c 'GOFLAGS=-mod=mod go get "github.com/golang-jwt/jwt/v5@v5.2.1"' >/dev/null 2>&1 && echo "  ok" )

echo "== Node panva/jose =="
( cd node_jose && npm init -y >/dev/null 2>&1 && npm install jose@5 >/dev/null 2>&1 && echo "  ok" )

echo "== Java nimbus-jose-jwt =="
mkdir -p java/lib
curl -fsSL -o java/lib/nimbus.jar \
  "https://repo1.maven.org/maven2/com/nimbusds/nimbus-jose-jwt/9.40/nimbus-jose-jwt-9.40.jar" \
  && ( cd java && javac -cp lib/nimbus.jar Confusion.java ) && echo "  ok"

echo "== PHP firebase/php-jwt (single-file source) =="
mkdir -p php/src
for f in JWT Key SignatureInvalidException BeforeValidException ExpiredException JWTExceptionWithPayloadInterface; do
  curl -fsSL -o "php/src/$f.php" "https://raw.githubusercontent.com/firebase/php-jwt/v6.10.0/src/$f.php"
done && echo "  ok"

echo "✅ done → bash run_multilang.sh"
