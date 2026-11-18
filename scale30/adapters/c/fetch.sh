#!/usr/bin/env bash
# C library source — release tag-এ পিন করা (PREREG §2 নিয়ম ৪: সর্বশেষ stable release, ২৫ সেপ্ট ২০২৬)।
# cjose: মূল cisco/cjose (OpenIDC/cjose এর fork, তাই বাদ — PREREG §2 নিয়ম ২)।
set -euo pipefail
D="$(cd "$(dirname "$0")" && pwd)"; mkdir -p "$D/src"
get() {  # name url tag commit
  [ -d "$D/src/$1" ] || git clone -q --depth 1 --branch "$3" "$2" "$D/src/$1"
  got=$(git -C "$D/src/$1" rev-parse HEAD)
  [ "$got" = "$4" ] || { echo "$1: commit $got != pinned $4" >&2; exit 1; }
}
get libjwt https://github.com/benmcollins/libjwt.git v3.6.1 f4edfe5b2c44ac57edf00342550e81017f5329eb
get cjose  https://github.com/cisco/cjose.git        0.8.1  6fdb5fe75a86acb9cd34ca2eb13d9e090a6df588
