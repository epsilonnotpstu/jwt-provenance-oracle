#!/usr/bin/env bash
# Dart adapter (AOT exe) — `dart compile exe run.dart -o bin/adapter` দিয়ে build
D="$(cd "$(dirname "$0")" && pwd)"
exec "$D/bin/adapter" "$@"
