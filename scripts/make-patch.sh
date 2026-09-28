#!/usr/bin/env bash
set -euo pipefail

HERE=$(cd "$(dirname "$0")/.." && pwd)
cd "$HERE"

BASE=${1:-$(git rev-parse upstream/2_12)}
OUT=${2:-hostapd-driver-test-$(git describe --tags --always --dirty).patch}

git diff --check "$BASE" HEAD -- \
  doc/testing_tools.doxygen \
  hostapd/defconfig \
  src/ap/eth_p_oui.c src/ap/wpa_auth_glue.c \
  src/drivers/driver.h src/drivers/driver_test.c src/drivers/driver_test.h \
  src/drivers/drivers.c src/drivers/drivers.mak src/drivers/drivers.mk \
  tests/Makefile tests/build/build-hostapd-driver-test-min.config \
  tests/build/build-hostapd-driver-test.config \
  tests/build/build-wpa_supplicant-driver-test-min.config \
  tests/build/build-wpa_supplicant-driver-test.config tests/test-driver_test.c \
  wpa_supplicant/defconfig wpa_supplicant/wpa_supplicant.c

git diff --binary "$BASE" HEAD -- \
  doc/testing_tools.doxygen hostapd/defconfig \
  src/ap/eth_p_oui.c src/ap/wpa_auth_glue.c \
  src/drivers/driver.h src/drivers/driver_test.c src/drivers/driver_test.h \
  src/drivers/drivers.c src/drivers/drivers.mak src/drivers/drivers.mk \
  tests/Makefile tests/build tests/test-driver_test.c \
  wpa_supplicant/defconfig wpa_supplicant/wpa_supplicant.c > "$OUT"

sha256=$(shasum -a 256 "$OUT" | awk '{print $1}')
echo "$sha256  $OUT"
