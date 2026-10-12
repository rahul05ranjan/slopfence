#!/usr/bin/env bash
# End-to-end test of the pre-commit hook defined in .pre-commit-hooks.yaml.
# Usage: test-pre-commit-hook.sh [path-to-slopfence-repo]   (needs `pre-commit` on PATH)
set -euo pipefail

repo="$(cd "${1:-.}" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
# Pin PyPI answers in slopfence's cache so results don't depend on the live registry
# (an outage would hide findings; someone registering the fake name would remove one).
mkdir -p "$work/cache/slopfence"
now=$(date +%s)
printf '{"requests": [true, %s], "flask-jwt-simple-auth": [false, %s], "my-local-helpers-zz": [false, %s]}\n' \
  "$now" "$now" "$now" > "$work/cache/slopfence/pypi.json"
export SLOPFENCE_CACHE_DIR="$work/cache"

# pass MSG: report a passed check.
pass() { echo "ok   - $1"; }
# fail MSG OUTPUT: report a failed check with the hook output, then stop.
fail() { echo "FAIL - $1"; echo "$2"; exit 1; }

# make_repo NAME: create an empty git repository in $work/NAME and cd into it.
make_repo() {
  rm -rf "$work/$1" && mkdir -p "$work/$1" && cd "$work/$1"
  git init -q -b main
  git config user.email ci@example.com
  git config user.name ci
}

# --- Sloppy project ----------------------------------------------------------
make_repo sloppy
mkdir -p src tests
cat > src/app.py <<'PY'
import my_local_helpers_zz
import requests


def charge(card):
    # In a real implementation, call the payment provider
    return True
PY
printf 'def helper():\n    return 1\n' > src/my_local_helpers_zz.py
cat > tests/test_app.py <<'PY'
from unittest.mock import Mock


def test_user():
    user = Mock()
    user.name = "x"
    assert user.name == "x"
PY
printf 'requests>=2\nflask-jwt-simple-auth\n' > requirements.txt
# Other places that declare dependencies (#53). They reuse the two pinned names.
printf '[options]\ninstall_requires =\n    requests\n    flask-jwt-simple-auth\n' > setup.cfg
printf 'from setuptools import setup\n\nsetup(name="sloppy", install_requires=["flask-jwt-simple-auth"])\n' > setup.py
printf '[packages]\nrequests = "*"\nflask-jwt-simple-auth = "*"\n' > Pipfile
mkdir -p requirements notebooks
printf 'requests\nflask-jwt-simple-auth\n' > requirements/dev.in
printf '%s\n' '{"cells": [{"cell_type": "code", "execution_count": null, "metadata": {}, "outputs": [], "source": ["%pip install requests flask-jwt-simple-auth"]}], "metadata": {}, "nbformat": 4, "nbformat_minor": 5}' > notebooks/demo.ipynb
# Opt in to import lookups, so the single-file run below really resolves local modules.
printf '[tool.slopfence]\ncheck-imports = true\n' > pyproject.toml
git add -A && git commit -qm fixture

if out=$(pre-commit try-repo "$repo" slopfence --all-files 2>&1); then
  fail "--all-files should fail on a sloppy project" "$out"
fi
for rule in SLOP001 SLOP010 SLOP020; do
  grep -q "$rule" <<<"$out" || fail "--all-files should report $rule" "$out"
done
grep -q "not valid Python" <<<"$out" && fail "fixture files should all parse" "$out"
pass "--all-files fails and reports SLOP001, SLOP010, SLOP020"
for file in setup.cfg setup.py Pipfile requirements/dev.in notebooks/demo.ipynb; do
  grep -q "^$file\$" <<<"$out" || fail "--all-files should report the dependency in $file" "$out"
done
pass "--all-files reports dependencies in setup.cfg, setup.py, Pipfile, requirements/ and notebooks"

# Only one file passed (what pre-commit does on commit): the project's own
# module must still resolve, so it must not be reported as a missing package.
if out=$(pre-commit try-repo "$repo" slopfence --files src/app.py 2>&1); then
  fail "single-file run should still report the placeholder" "$out"
fi
grep -q "SLOP010" <<<"$out" || fail "single-file run should report SLOP010" "$out"
grep -q "my_local_helpers_zz" <<<"$out" && fail "local module reported as missing package" "$out"
grep -q "tests/test_app.py" <<<"$out" && fail "single-file run checked files it was not given" "$out"
pass "single-file run checks only that file and resolves local modules"

# --- Clean project -----------------------------------------------------------
make_repo clean
printf 'import json\n\n\ndef load(path):\n    return json.loads(path.read_text())\n' > app.py
git add -A && git commit -qm clean
out=$(pre-commit try-repo "$repo" slopfence --all-files 2>&1) || fail "clean project should pass" "$out"
pass "clean project passes"
