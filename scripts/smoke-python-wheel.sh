#!/usr/bin/env bash
# `pip install` the wheel the way a consumer does — into a fresh virtualenv outside this
# repository — and prove it imports and works. Run before publishing against the built
# wheels, and after against PyPI: the same script, so "verified" and "published" are the
# same claim.
#
#   usage: scripts/smoke-python-wheel.sh <wheels-dir | pep440-version>
#     PYTHON  the interpreter to test with (default python3). The Linux rows run inside
#             the PyPA manylinux/musllinux images, which carry the OLDEST libc their tag
#             promises and keep their interpreters under /opt/python.
#
# Given a directory, pip is pointed at ALL the wheels and left to choose. That is the
# test of the platform tags: a wheel pip will not select here is one no consumer on this
# platform would ever receive.
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
  # --no-index: nothing but these files may satisfy the install. --pre: a directory of
  # release candidates holds no final release for pip to prefer.
  pip install --no-index --find-links "$wheels" --only-binary :all: --pre "$PACKAGE"
else
  pip install --only-binary :all: "$PACKAGE==$spec"
fi

cd "$work" # never the repository: its sources must not be importable
cp "$repo/scripts/smoke/python-consumer.py" .
"$work/venv/bin/python" python-consumer.py "$repo/testvectors/open_secret.json"

echo "python wheel smoke ok: $("$work/venv/bin/python" -c 'import importlib.metadata as m, platform, sys; print(f"matter-sdk {m.version(sys.argv[1])} on {platform.python_implementation()} {platform.python_version()}, {platform.platform()}")' "$PACKAGE")"
