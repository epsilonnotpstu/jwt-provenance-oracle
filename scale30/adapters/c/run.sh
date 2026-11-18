#!/usr/bin/env bash
# C adapter — libjwt + cjose, source release tag-এ পিন (fetch.sh), build path-এ space চলে না তাই
# ~/.local/opt/scale30-c symlink দিয়ে build। প্রথমবার: ./fetch.sh && ./run.sh --build
set -euo pipefail
D="$(cd "$(dirname "$0")" && pwd)"; B="$HOME/.local/opt/scale30-c"; P="$B/prefix"
if [ "${1:-}" = "--build" ]; then
  ln -sfn "$D" "$B"
  for L in libjwt cjose; do
    cmake -S "$B/src/$L" -B "$B/build/$L" -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$P" \
      -DWITH_GNUTLS=OFF -DWITH_MBEDTLS=OFF -DWITH_LIBCURL=OFF -DWITH_TESTS=OFF -DBUILD_TESTING=OFF >/dev/null
    cmake --build "$B/build/$L" -j8 >/dev/null && cmake --install "$B/build/$L" >/dev/null
  done
  export PKG_CONFIG_PATH="$P/lib/pkgconfig"
  mkdir -p "$D/bin"
  cc -O2 -Wall -Wextra -o "$D/bin/adapter" "$D/run.c" -DLIBJWT_VER="\"$(pkg-config --modversion libjwt)\"" \
    -I"$P/include" -L"$P/lib" -Wl,-rpath,"$P/lib" -ljwt -lcjose $(pkg-config --cflags --libs jansson)
  echo built; exit 0
fi
mkdir -p "$2"
exec "$D/bin/adapter" "$@"
