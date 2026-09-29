#!/usr/bin/env bash
set -euo pipefail

HERE=$(cd "$(dirname "$0")/.." && pwd)
cd "$HERE"

BASE=${UPSTREAM_BASE:-$(git rev-parse --verify upstream/2_12 2>/dev/null || git rev-parse --verify hostap_2_12)}

git diff --check "$BASE" HEAD -- ':(exclude)dist/*.patch'
bash -n pocs/*.sh
python3 -m py_compile pocs/driver-test-fuzz.py
test -f tests/build/build-hostapd-driver-test.config
test -f tests/build/build-wpa_supplicant-driver-test.config
test -f tests/hwsim/auth_serv/ca.pem
test -f tests/hwsim/auth_serv/server.key
unexpected_keys=$(git diff --name-only "$BASE" HEAD -- '*.key' '*.pem' |
	grep -v '^tests/hwsim/auth_serv/' || true)
test -z "$unexpected_keys"
echo 'release checks passed'
