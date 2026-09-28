#!/usr/bin/env bash
# Run driver-test-fuzz.py against live (sanitizer) hostapd + wpa_supplicant instances.
# Usage: fuzz-run.sh <name> <ap.conf> [ap2.conf|-] <sta.conf> [iterations]
set -u
NAME=$1; AP_CONF=$2; AP2_CONF=$3; STA_CONF=$4; ITER=${5:-500}
HERE=$(cd "$(dirname "$0")" && pwd)
SRC=${HOSTAP_SRC:-/tmp/work/hostap-asan}
AUTH_SERV=${AUTH_SERV:-$SRC/tests/hwsim/auth_serv}
RUNDIR=${RUNDIR:-/tmp/driver-test-run/fuzz-$NAME}
export ASAN_OPTIONS="detect_leaks=1:exitcode=98"
export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1:exitcode=97"
rm -rf "$RUNDIR"; mkdir -p "$RUNDIR"
sed -e "s#@RUNDIR@#$RUNDIR#g" -e "s#@AUTH_SERV@#$AUTH_SERV#g" "$AP_CONF" > "$RUNDIR/ap.conf"
sed -e "s#@RUNDIR@#$RUNDIR#g" -e "s#@AUTH_SERV@#$AUTH_SERV#g" "$STA_CONF" > "$RUNDIR/sta.conf"
APARGS="$RUNDIR/ap.conf"
if [ "$AP2_CONF" != "-" ]; then sed -e "s#@RUNDIR@#$RUNDIR#g" -e "s#@AUTH_SERV@#$AUTH_SERV#g" "$AP2_CONF" > "$RUNDIR/ap2.conf"; APARGS="$APARGS $RUNDIR/ap2.conf"; fi
$SRC/hostapd/hostapd -ddt -K $APARGS > "$RUNDIR/hostapd.log" 2>&1 &
AP_PID=$!
sleep 1
$SRC/wpa_supplicant/wpa_supplicant -Dtest -ista1 -c "$RUNDIR/sta.conf" -ddt -K > "$RUNDIR/wpa_supplicant.log" 2>&1 &
STA_PID=$!
# wait for the STA to connect so that the fuzzing hits associated state too
for i in $(seq 1 60); do grep -q CTRL-EVENT-CONNECTED "$RUNDIR/wpa_supplicant.log" && break; sleep 0.25; done
python3 "$HERE/driver-test-fuzz.py" --ap-sock "$RUNDIR/ap1" --sta-sock "$RUNDIR/STA-sta1" \
	--iterations "$ITER" --seed 7 --report "$RUNDIR/fuzz-report.txt"
FUZZ_RC=$?
sleep 1
$SRC/hostapd/hostapd_cli -i ap1 -p "$RUNDIR/hostapd-ctrl" status driver > "$RUNDIR/ap-status-driver.txt" 2>&1
$SRC/wpa_supplicant/wpa_cli -i sta1 -p "$RUNDIR/wpas-ctrl" status driver > "$RUNDIR/sta-status-driver.txt" 2>&1
$SRC/wpa_supplicant/wpa_cli -i sta1 -p "$RUNDIR/wpas-ctrl" status > "$RUNDIR/sta-status.txt" 2>&1
kill -TERM $STA_PID; sleep 0.7; kill -TERM $AP_PID; sleep 0.7
wait $STA_PID; STA_RC=$?; wait $AP_PID; AP_RC=$?
status=PASS
[ $FUZZ_RC -eq 0 ] || status="FAIL(fuzz_rc=$FUZZ_RC)"
[ $STA_RC -eq 0 ] || status="$status FAIL(sta_exit=$STA_RC)"
[ $AP_RC -eq 0 ] || status="$status FAIL(ap_exit=$AP_RC)"
grep -qE "AddressSanitizer|runtime error:" "$RUNDIR"/*.log && status="$status FAIL(sanitizer)"
echo "[fuzz-$NAME] $status (fuzz_rc=$FUZZ_RC sta_exit=$STA_RC ap_exit=$AP_RC)"
echo "$status" > "$RUNDIR/RESULT"
[ "$status" = PASS ]
