#!/usr/bin/env bash
set -euo pipefail

HERE=$(cd "$(dirname "$0")/.." && pwd)
cd "$HERE"

git diff --check upstream/2_12 HEAD -- ':(exclude)dist/*.patch'
bash -n pocs/*.sh
python3 -m py_compile pocs/driver-test-fuzz.py
test -f tests/build/build-hostapd-driver-test.config
test -f tests/build/build-wpa_supplicant-driver-test.config
test -f tests/hwsim/auth_serv/ca.pem
test -f tests/hwsim/auth_serv/server.key
unexpected_keys=$(git diff --name-only upstream/2_12 HEAD -- '*.key' '*.pem' |
	grep -v '^tests/hwsim/auth_serv/' || true)
test -z "$unexpected_keys"
echo 'release checks passed'
