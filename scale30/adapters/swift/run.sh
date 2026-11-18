#!/usr/bin/env bash
# Swift adapter — swiftly দিয়ে Swift 6.4.0 (Ubuntu 24.04 toolchain, sudo ছাড়া)। Manjaro-তে libncurses.so.6 নেই →
# toolchain-এর RUNPATH dir-এ libncursesw.so.6-এর symlink (ADAPTERS.md)। build: ./run.sh --build
set -euo pipefail
D="$(cd "$(dirname "$0")" && pwd)"
export PATH="$HOME/.local/opt/swiftly-home/toolchains/6.4.0/usr/bin:$PATH"
if [ "${1:-}" = "--build" ]; then
  L="$HOME/.local/opt/swiftly-home/toolchains/6.4.0/usr/lib/swift/linux"
  [ -e "$L/libncurses.so.6" ] || ln -s /usr/lib/libncursesw.so.6 "$L/libncurses.so.6"
  cd "$D" && swift build -c release 2>&1 | tail -3; exit "${PIPESTATUS[0]}"
fi
exec "$D/.build/release/adapter" "$@"
