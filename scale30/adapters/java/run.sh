#!/usr/bin/env bash
# ব্যবহার: adapters/java/run.sh <cases.json> <outdir> [impl ...]  (আগে: mvn compile dependency:build-classpath -Dmdep.outputFile=cp.txt)
D="$(cd "$(dirname "$0")" && pwd)"
exec java -cp "$D/target/classes:$(cat "$D/cp.txt")" scale30.Main "$@"
