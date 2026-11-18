#!/usr/bin/env bash
# Phase B1 — পুরনো-দুর্বল ও fixed library version-এর venv বানায় (reproducibility)।
# চালাও:  bash setup_oldlibs.sh
# পূর্বশর্ত: uv installed (https://docs.astral.sh/uv/)। Python 3.9 ও 3.12 uv নামিয়ে নেবে।
set -e
cd "$(dirname "$0")"
mkdir -p _oldlibs

# আধুনিক (fixed) — মূল pipeline-এর venv, Python 3.12
uv venv -q .venv --python 3.12
uv pip install -q --python .venv/bin/python -r requirements.txt

uv python install 3.9

# ছোট version → Python 3.12-এ চলে
for spec in "pyjwt==1.7.1" "python-jose==3.3.0" "python-jose==2.0.2" "authlib==0.15.5"; do
  d="_oldlibs/venv_$(echo "$spec"|tr '=<>.' '____')"
  uv venv -q "$d" --python 3.12
  uv pip install -q --python "$d/bin/python" "$spec" cryptography
done

# খুব পুরনো version → `from collections import Mapping` লাগে → Python 3.9
for spec in "pyjwt==0.2.3" "pyjwt==0.4.3" "pyjwt==1.4.2" "pyjwt==1.5.0" "python-jose==2.0.2"; do
  d="_oldlibs/venv_$(echo "$spec"|tr '=<>.' '____')_py39"
  uv venv -q "$d" --python 3.9
  uv pip install -q --python "$d/bin/python" "$spec" cryptography
done

# JWE bomb-এর জন্য jose 3.3.0-র সাথে *বেমানান-নয়* এমন পুরনো cryptography
uv venv -q _oldlibs/venv_jose330bomb --python 3.9
uv pip install -q --python _oldlibs/venv_jose330bomb/bin/python "python-jose==3.3.0" "cryptography==3.4.8"

echo "✅ venv তৈরি। এখন চালাও:  .venv/bin/python run_phase_b1.py"
