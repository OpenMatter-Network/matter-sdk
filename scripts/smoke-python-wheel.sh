#!/usr/bin/env bash
# `pip install` the wheel into a fresh venv outside this repo and prove it works. Used
# before publish (wheel dir) and after (PyPI).
#
#   usage: scripts/smoke-python-wheel.sh <wheels-dir | pep440-version>
#     PYTHON  interpreter to test with (default python3)
#
# Given a directory, pip chooses among ALL wheels, which tests the platform tags.
set -euo pipefail
spec=${1:?usage: smoke-python-wheel.sh <wheels-dir | pep440-version>}
repo=$(cd "$(dirname "$0")/.." && pwd)
readonly repo
readonly PACKAGE=matter-sdk
python=${PYTHON:-python3}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
"$python" -m venv "$work/venv"
pip() { "$work/venv/bin/python" -m pip --quiet --disable-pip-version-check "$@"; }

if [ -d "$spec" ]; then
  wheels=$(realpath "$spec")
  # --no-index: only these files. --pre: allow release candidates.
  pip install --no-index --find-links "$wheels" --only-binary :all: --pre "$PACKAGE"
else
  pip install --only-binary :all: "$PACKAGE==$spec"
fi

cd "$work" # repo sources must not be importable
cp "$repo/scripts/smoke/python-consumer.py" .
"$work/venv/bin/python" python-consumer.py "$repo/testvectors/open_secret.json"

echo "python wheel smoke ok: $("$work/venv/bin/python" -c 'import importlib.metadata as m, platform, sys; print(f"matter-sdk {m.version(sys.argv[1])} on {platform.python_implementation()} {platform.python_version()}, {platform.platform()}")' "$PACKAGE")"
