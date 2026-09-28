#!/usr/bin/env bash
# Generic hostapd/wpa_supplicant driver=test scenario runner.
#
# Usage: run-scenario.sh <name> <ap.conf> <sta.conf> [--sta2 <sta2.conf>]
#        [--ap2 <ap2.conf>] [--expect "<regex>"] [--sta-cmds "<cmd;cmd>"]
#        [--ap-cmds "<cmd;cmd>"] [--post-sleep N] [--timeout N]
#        [--sta-param "<driver_param>"]
#
# Environment:
#   HOSTAPD, WPA_SUPPLICANT, WPA_CLI, HOSTAPD_CLI  binaries (default: build tree)
#   RUNDIR      directory for sockets/logs (default: /tmp/driver-test-run/<name>)
#   WRAP        optional wrapper (e.g. "valgrind --error-exitcode=99 -q")
#
# The runner never touches real network interfaces; everything runs over a
# UNIX datagram socket in RUNDIR.
set -u

NAME=$1; AP_CONF=$2; STA_CONF=$3; shift 3
STA2_CONF=""; AP2_CONF=""; EXPECT="CTRL-EVENT-CONNECTED"; STA_CMDS=""; AP_CMDS=""
POST_SLEEP=1; TIMEOUT=15; STA_PARAM=""
while [ $# -gt 0 ]; do
	case "$1" in
	--sta2) STA2_CONF=$2; shift 2;;
	--ap2) AP2_CONF=$2; shift 2;;
	--expect) EXPECT=$2; shift 2;;
	--sta-cmds) STA_CMDS=$2; shift 2;;
	--ap-cmds) AP_CMDS=$2; shift 2;;
	--post-sleep) POST_SLEEP=$2; shift 2;;
	--timeout) TIMEOUT=$2; shift 2;;
	--sta-param) STA_PARAM=$2; shift 2;;
	*) echo "unknown option $1" >&2; exit 2;;
	esac
done

SRC=${HOSTAP_SRC:-/tmp/work/hostap}
AUTH_SERV=${AUTH_SERV:-$SRC/tests/hwsim/auth_serv}
HOSTAPD=${HOSTAPD:-$SRC/hostapd/hostapd}
WPA_SUPPLICANT=${WPA_SUPPLICANT:-$SRC/wpa_supplicant/wpa_supplicant}
WPA_CLI=${WPA_CLI:-$SRC/wpa_supplicant/wpa_cli}
HOSTAPD_CLI=${HOSTAPD_CLI:-$SRC/hostapd/hostapd_cli}
RUNDIR=${RUNDIR:-/tmp/driver-test-run/$NAME}
WRAP=${WRAP:-}

rm -rf "$RUNDIR"; mkdir -p "$RUNDIR"
substitute_config() {
	local input=$1 output=$2
	sed -e "s#@RUNDIR@#$RUNDIR#g" -e "s#@AUTH_SERV@#$AUTH_SERV#g" \
		"$input" > "$output"
}
substitute_config "$AP_CONF" "$RUNDIR/ap.conf"
substitute_config "$STA_CONF" "$RUNDIR/sta.conf"
[ -n "$AP2_CONF" ] && substitute_config "$AP2_CONF" "$RUNDIR/ap2.conf"
[ -n "$STA2_CONF" ] && substitute_config "$STA2_CONF" "$RUNDIR/sta2.conf"
[ -n "$STA_PARAM" ] && sed -i "s|^driver_param=.*|driver_param=$STA_PARAM|" "$RUNDIR/sta.conf"

cleanup() {
	[ -n "${STA2_PID:-}" ] && kill "$STA2_PID" 2>/dev/null
	[ -n "${STA_PID:-}" ] && kill "$STA_PID" 2>/dev/null
	[ -n "${AP_PID:-}" ] && kill "$AP_PID" 2>/dev/null
	sleep 0.5
	[ -n "${STA2_PID:-}" ] && kill -9 "$STA2_PID" 2>/dev/null
	[ -n "${STA_PID:-}" ] && kill -9 "$STA_PID" 2>/dev/null
	[ -n "${AP_PID:-}" ] && kill -9 "$AP_PID" 2>/dev/null
	wait 2>/dev/null
}
trap cleanup EXIT

AP_ARGS="$RUNDIR/ap.conf"
[ -n "$AP2_CONF" ] && AP_ARGS="$AP_ARGS $RUNDIR/ap2.conf"
$WRAP $HOSTAPD -ddt -K $AP_ARGS > "$RUNDIR/hostapd.log" 2>&1 &
AP_PID=$!
sleep 1
if ! kill -0 $AP_PID 2>/dev/null; then
	echo "[$NAME] FAIL: hostapd did not start"; tail -20 "$RUNDIR/hostapd.log"; exit 1
fi

$WRAP $WPA_SUPPLICANT -Dtest -ista1 -c "$RUNDIR/sta.conf" -ddt -K > "$RUNDIR/wpa_supplicant.log" 2>&1 &
STA_PID=$!
if [ -n "$STA2_CONF" ]; then
	$WRAP $WPA_SUPPLICANT -Dtest -ista2 -c "$RUNDIR/sta2.conf" -ddt -K > "$RUNDIR/wpa_supplicant2.log" 2>&1 &
	STA2_PID=$!
fi

# Wait for the expected event in the wpa_supplicant log
deadline=$((SECONDS + TIMEOUT)); ok=0
while [ $SECONDS -lt $deadline ]; do
	if grep -qE "$EXPECT" "$RUNDIR/wpa_supplicant.log"; then ok=1; break; fi
	if ! kill -0 $STA_PID 2>/dev/null; then break; fi
	sleep 0.2
done

# Optional control interface commands after connection
run_cmds() {
	local cli=$1 iface=$2 sock=$3 cmds=$4 log=$5
	local -a list
	IFS=';' read -r -a list <<< "$cmds"
	for c in "${list[@]}"; do
		c=$(echo "$c" | sed 's/^ *//')
		[ -z "$c" ] && continue
		if [ "${c#sleep }" != "$c" ]; then
			sleep "${c#sleep }"; continue
		fi
		echo "> $c" >> "$log"
		# shellcheck disable=SC2086
		"$cli" -i "$iface" -p "$sock" $c >> "$log" 2>&1
		sleep "${CMD_SLEEP:-0.5}"
	done
}
if [ -n "$STA_CMDS" ]; then
	run_cmds "$WPA_CLI" sta1 "$RUNDIR/wpas-ctrl" "$STA_CMDS" "$RUNDIR/sta-ctrl.log"
fi
if [ -n "$AP_CMDS" ]; then
	run_cmds "$HOSTAPD_CLI" ap1 "$RUNDIR/hostapd-ctrl" "$AP_CMDS" "$RUNDIR/ap-ctrl.log"
fi
sleep "$POST_SLEEP"

# Collect driver status via control interfaces (text)
$WPA_CLI -i sta1 -p "$RUNDIR/wpas-ctrl" status driver > "$RUNDIR/sta-status-driver.txt" 2>&1
$WPA_CLI -i sta1 -p "$RUNDIR/wpas-ctrl" status > "$RUNDIR/sta-status.txt" 2>&1
$HOSTAPD_CLI -i ap1 -p "$RUNDIR/hostapd-ctrl" status driver > "$RUNDIR/ap-status-driver.txt" 2>&1
$HOSTAPD_CLI -i ap1 -p "$RUNDIR/hostapd-ctrl" all_sta > "$RUNDIR/ap-all-sta.txt" 2>&1

# Graceful shutdown to exercise deinit/cleanup paths
[ -n "${STA2_PID:-}" ] && kill -TERM $STA2_PID 2>/dev/null
kill -TERM $STA_PID 2>/dev/null
sleep 0.7
kill -TERM $AP_PID 2>/dev/null
sleep 0.7
wait $STA_PID 2>/dev/null; STA_RC=$?
wait $AP_PID 2>/dev/null; AP_RC=$?
[ -n "${STA2_PID:-}" ] && { wait $STA2_PID 2>/dev/null; }
STA_PID=""; AP_PID=""; STA2_PID=""

# Leftover sockets indicate a cleanup failure
leftover=$(find "$RUNDIR" -maxdepth 1 -type s | wc -l)

status="PASS"
[ $ok -eq 1 ] || status="FAIL(expect)"
[ "$STA_RC" -eq 0 ] || status="$status FAIL(sta_exit=$STA_RC)"
[ "$AP_RC" -eq 0 ] || status="$status FAIL(ap_exit=$AP_RC)"
[ "$leftover" -eq 0 ] || status="$status FAIL(leftover_sockets=$leftover)"
if grep -qE "AddressSanitizer|LeakSanitizer|runtime error:|ERROR: .*Sanitizer|Invalid read|Invalid write|definitely lost: [1-9]" "$RUNDIR"/*.log; then
	status="$status FAIL(sanitizer)"
fi
echo "[$NAME] $status (sta_exit=$STA_RC ap_exit=$AP_RC expect='$EXPECT')"
echo "$status" > "$RUNDIR/RESULT"
[ "$status" = "PASS" ]
