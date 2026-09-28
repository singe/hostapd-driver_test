#!/usr/bin/env bash
# driver-test-wpa2-wpa3.sh - reproducible AP/STA protocol test matrix for the
# hostapd/wpa_supplicant user space test driver (driver=test / -Dtest).
#
# Every scenario starts hostapd with an invented AP interface (ap1) and
# wpa_supplicant with an invented STA interface (sta1) connected through a
# local UNIX datagram socket. No kernel WLAN support, nl80211, or hardware is
# involved. Results are printed as "[name] PASS/FAIL" lines and a summary.
#
# Usage: driver-test-wpa2-wpa3.sh [--asan] [--valgrind] [--only <name>] [--quick]
#
# Environment:
#   HOSTAP_SRC    source tree containing built hostapd/ and wpa_supplicant/
#                 (default /tmp/work/hostap; --asan uses /tmp/work/hostap-asan)
#   RUNBASE       base directory for run artifacts (default /tmp/driver-test-run)
#   EVIDENCE_DIR  if set, text logs/summaries are copied there
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
CONF=$HERE/driver-test-configs
RUNNER=$HERE/run-scenario.sh
ONLY=""; QUICK=0; MODE="normal"
while [ $# -gt 0 ]; do
	case "$1" in
	--asan) MODE=asan; export HOSTAP_SRC=${HOSTAP_SRC:-/tmp/work/hostap-asan}; shift;;
	--valgrind) MODE=valgrind; export WRAP="valgrind -q --error-exitcode=99 --leak-check=full --errors-for-leak-kinds=definite --track-origins=no"; shift;;
	--only) ONLY=$2; shift 2;;
	--quick) QUICK=1; shift;;
	*) echo "unknown option $1"; exit 2;;
	esac
done
export HOSTAP_SRC=${HOSTAP_SRC:-/tmp/work/hostap}
export RUNBASE=${RUNBASE:-/tmp/driver-test-run}
if [ "$MODE" = asan ]; then
	export ASAN_OPTIONS="detect_leaks=1:abort_on_error=0:exitcode=98"
	export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1:exitcode=97"
fi
SUMMARY=$RUNBASE/summary-$MODE.txt
mkdir -p "$RUNBASE"; : > "$SUMMARY"
PASS=0; FAIL=0
run() {
	local name=$1; shift
	if [ -n "$ONLY" ] && [ "$name" != "$ONLY" ]; then return; fi
	RUNDIR=$RUNBASE/$MODE-$name bash "$RUNNER" "$name" "$@" 2>&1 | tail -n 1 | tee -a "$SUMMARY"
	if grep -q "^\[$name\] PASS" "$SUMMARY"; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); fi
	if [ -n "${EVIDENCE_DIR:-}" ]; then
		mkdir -p "$EVIDENCE_DIR/$MODE-$name"
		for f in hostapd.log wpa_supplicant.log wpa_supplicant2.log sta-ctrl.log ap-ctrl.log \
			 sta-status.txt sta-status-driver.txt ap-status-driver.txt ap-all-sta.txt RESULT; do
			[ -f "$RUNBASE/$MODE-$name/$f" ] && cp "$RUNBASE/$MODE-$name/$f" "$EVIDENCE_DIR/$MODE-$name/"
		done
	fi
}
T=${SCENARIO_TIMEOUT:-20}
[ "$MODE" = valgrind ] && T=60
S=$([ "$MODE" = valgrind ] && echo 4 || echo 2)

# --- Core handshakes -------------------------------------------------------
run open        "$CONF/ap-open.conf"      "$CONF/sta-open.conf"     --timeout $T --post-sleep $S \
	--sta-cmds "status; signal_poll; sleep 0.5"
run wpa2-psk    "$CONF/ap-wpa2-psk.conf"  "$CONF/sta-wpa2-psk.conf" --timeout $T --post-sleep 8 \
	--sta-cmds "status; sleep 1"   # 8 s post-sleep covers PTK (3 s) and GTK (4 s) rekeys
run wpa3-sae    "$CONF/ap-wpa3-sae.conf"  "$CONF/sta-wpa3-sae.conf" --timeout $T --post-sleep $S \
	--sta-cmds "status; sleep 0.5"
run owe         "$CONF/ap-owe.conf"       "$CONF/sta-owe.conf"      --timeout $T --post-sleep $S
run wpa2-eap    "$CONF/ap-wpa2-eap.conf"  "$CONF/sta-wpa2-eap.conf" --timeout $T --post-sleep 7 \
	--sta-cmds "status; sleep 1"   # eap_reauth_period=5 forces an EAP re-authentication
run wpa2-eap-radius "$CONF/ap-wpa2-eap-radius.conf" "$CONF/sta-wpa2-eap-radius.conf" \
	--ap2 "$CONF/radius-server.conf" --timeout $T --post-sleep $S
run wpa3-enterprise "$CONF/ap-wpa3-enterprise.conf" "$CONF/sta-wpa3-enterprise.conf" --timeout $T --post-sleep $S
run ft-psk      "$CONF/ap-ft-psk.conf"    "$CONF/sta-ft-psk.conf"   --timeout $T --post-sleep 1 \
	--sta-cmds "status; roam 02:00:00:00:02:00; sleep 1; status; ft_ds 02:00:00:00:01:00; sleep 1; status; roam 02:00:00:00:02:00; sleep 1; status"
run fils        "$CONF/ap-fils.conf"      "$CONF/sta-fils.conf" --ap2 "$CONF/radius-server.conf" \
	--timeout $T --post-sleep 1 --sta-cmds "status; disconnect; sleep 0.5; reconnect; sleep 2; status"

# --- Wi-Fi 5/6/7 configuration and element paths ---------------------------
run 5ghz-vht-he "$CONF/ap-5ghz-vht-he.conf" "$CONF/sta-5ghz-vht-he.conf" --timeout $T --post-sleep $S
run 6ghz-he-eht "$CONF/ap-6ghz-he-eht.conf" "$CONF/sta-6ghz-he-eht.conf" --timeout $T --post-sleep $S
run eht-2g      "$CONF/ap-eht-2g.conf"    "$CONF/sta-eht-2g.conf"   --timeout $T --post-sleep $S
run mld         "$CONF/ap-mld-link0.conf" "$CONF/sta-mld.conf" --ap2 "$CONF/ap-mld-link1.conf" \
	--timeout $T --post-sleep $S --sta-cmds "status; disconnect; sleep 1; reconnect; sleep 3; status"
run mld-single-link "$CONF/ap-mld-link0.conf" "$CONF/sta-mld-single-link.conf" --ap2 "$CONF/ap-mld-link1.conf" \
	--timeout $T --post-sleep $S --sta-cmds "status; sleep 0.5"

# --- Disconnection, timeouts, recovery, concurrency -------------------------
run ap-deauth   "$CONF/ap-wpa2-psk.conf"  "$CONF/sta-wpa2-psk.conf" --timeout $T --post-sleep 1 \
	--ap-cmds "deauthenticate 02:40:61:c2:f3:b7; sleep 1.5; all_sta" --sta-cmds "status" \
	--expect "CTRL-EVENT-CONNECTED"
run ap-disassoc "$CONF/ap-wpa3-sae.conf"  "$CONF/sta-wpa3-sae.conf" --timeout $T --post-sleep 1 \
	--ap-cmds "disassociate 02:40:61:c2:f3:b7; sleep 1.5; all_sta"
run sta-reconnect "$CONF/ap-wpa2-psk.conf" "$CONF/sta-wpa2-psk.conf" --timeout $T --post-sleep 1 \
	--sta-cmds "disconnect; sleep 0.5; reconnect; sleep 1.5; status; reassociate; sleep 1.5; status"
run two-stas    "$CONF/ap-wpa3-sae.conf"  "$CONF/sta-wpa3-sae.conf" --sta2 "$CONF/sta-wpa3-sae.conf" \
	--timeout $T --post-sleep 3 --ap-cmds "all_sta"
run wrong-psk   "$CONF/ap-wpa2-psk.conf"  "$CONF/sta-wrong-psk.conf" --timeout $T --post-sleep 1 \
	--expect "CTRL-EVENT-DISCONNECTED.*reason=(2|15)|4-Way Handshake failed|WRONG_KEY"
run wrong-sae   "$CONF/ap-wpa3-sae.conf"  "$CONF/sta-wrong-sae.conf" --timeout $T --post-sleep 1 \
	--expect "CTRL-EVENT-AUTH-REJECT|CTRL-EVENT-SSID-TEMP-DISABLED|status_code=1"
run no-ap        "$CONF/ap-open.conf"      "$CONF/sta-timeout.conf"  --timeout 8 --post-sleep 1 \
	--expect "No suitable network found"
run auth-timeout "$CONF/ap-ignore-auth.conf" "$CONF/sta-fast-timers.conf" --timeout 8 --post-sleep 1 \
	--expect "SME: Authentication timed out"
run assoc-timeout "$CONF/ap-ignore-assoc.conf" "$CONF/sta-fast-timers.conf" --timeout 8 --post-sleep 1 \
	--expect "SME: Association timed out"
run udp-transport "$CONF/ap-udp.conf"     "$CONF/sta-udp.conf"      --timeout $T --post-sleep $S
run test-dir    "$CONF/ap-dir.conf"       "$CONF/sta-dir.conf"      --timeout $T --post-sleep $S

if [ $QUICK -eq 0 ] && [ -z "$ONLY" ] || [ "$ONLY" = ap-loss ]; then
	# Peer disappearance: kill the AP while connected and expect the local
	# deauthentication generated by the keepalive probe.
	RUNDIR=$RUNBASE/$MODE-ap-loss bash "$HERE/ap-loss-scenario.sh" ap-loss "$CONF/ap-wpa2-psk.conf" \
		"$CONF/sta-wpa2-psk.conf" 2>&1 | tail -n 1 | tee -a "$SUMMARY"
	if grep -q "^\[ap-loss\] PASS" "$SUMMARY"; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); fi
	if [ -n "${EVIDENCE_DIR:-}" ]; then
		mkdir -p "$EVIDENCE_DIR/$MODE-ap-loss"
		cp "$RUNBASE/$MODE-ap-loss"/*.log "$RUNBASE/$MODE-ap-loss"/RESULT "$EVIDENCE_DIR/$MODE-ap-loss/" 2>/dev/null
	fi
fi

echo "==== $MODE: $PASS passed, $FAIL failed ====" | tee -a "$SUMMARY"
[ -n "${EVIDENCE_DIR:-}" ] && cp "$SUMMARY" "$EVIDENCE_DIR/"
[ $FAIL -eq 0 ]
