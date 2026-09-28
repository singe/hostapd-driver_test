#!/usr/bin/env bash
# Peer disappearance: connect, kill hostapd (SIGKILL, so no Deauthentication
# frame is sent), and expect the STA test driver to detect the vanished AP
# socket through its keepalive probe and report a locally generated
# deauthentication (reason 4, DISASSOC_DUE_TO_INACTIVITY).
set -u
NAME=$1; AP_CONF=$2; STA_CONF=$3
SRC=${HOSTAP_SRC:-/tmp/work/hostap}
AUTH_SERV=${AUTH_SERV:-$SRC/tests/hwsim/auth_serv}
HOSTAPD=${HOSTAPD:-$SRC/hostapd/hostapd}
WPA_SUPPLICANT=${WPA_SUPPLICANT:-$SRC/wpa_supplicant/wpa_supplicant}
RUNDIR=${RUNDIR:-/tmp/driver-test-run/$NAME}
WRAP=${WRAP:-}
rm -rf "$RUNDIR"; mkdir -p "$RUNDIR"
sed -e "s#@RUNDIR@#$RUNDIR#g" -e "s#@AUTH_SERV@#$AUTH_SERV#g" "$AP_CONF" > "$RUNDIR/ap.conf"
sed -e "s#@RUNDIR@#$RUNDIR#g" -e "s#@AUTH_SERV@#$AUTH_SERV#g" "$STA_CONF" > "$RUNDIR/sta.conf"
$WRAP $HOSTAPD -ddt -K "$RUNDIR/ap.conf" > "$RUNDIR/hostapd.log" 2>&1 &
AP_PID=$!
sleep 1
$WRAP $WPA_SUPPLICANT -Dtest -ista1 -c "$RUNDIR/sta.conf" -ddt -K > "$RUNDIR/wpa_supplicant.log" 2>&1 &
STA_PID=$!
deadline=$((SECONDS + 20)); ok=0
while [ $SECONDS -lt $deadline ]; do
	grep -q "CTRL-EVENT-CONNECTED" "$RUNDIR/wpa_supplicant.log" && { ok=1; break; }
	sleep 0.2
done
kill -9 $AP_PID 2>/dev/null; wait $AP_PID 2>/dev/null
rm -f "$RUNDIR/ap1"   # the AP socket file is gone as if the process vanished
lost=0
deadline=$((SECONDS + 10))
while [ $SECONDS -lt $deadline ]; do
	grep -q "AP socket disappeared" "$RUNDIR/wpa_supplicant.log" && \
	grep -q "CTRL-EVENT-DISCONNECTED.*reason=4 locally_generated=1" "$RUNDIR/wpa_supplicant.log" && { lost=1; break; }
	sleep 0.2
done
kill -TERM $STA_PID 2>/dev/null; sleep 0.7; wait $STA_PID 2>/dev/null; STA_RC=$?
status="PASS"
[ $ok -eq 1 ] || status="FAIL(connect)"
[ $lost -eq 1 ] || status="$status FAIL(loss-not-detected)"
[ "$STA_RC" -eq 0 ] || status="$status FAIL(sta_exit=$STA_RC)"
grep -qE "AddressSanitizer|runtime error:|definitely lost: [1-9]" "$RUNDIR"/*.log && status="$status FAIL(sanitizer)"
echo "$status" > "$RUNDIR/RESULT"
echo "[$NAME] $status (sta_exit=$STA_RC)"
[ "$status" = PASS ]
