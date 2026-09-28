#!/usr/bin/env bash
# Valgrind (memcheck) run of a scenario subset with the normal (gcc) build.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
export HOSTAP_SRC=${HOSTAP_SRC:-/tmp/work/hostap}
export RUNBASE=${RUNBASE:-/tmp/driver-test-run}
export WRAP="valgrind -q --error-exitcode=99 --leak-check=full --errors-for-leak-kinds=definite --show-leak-kinds=definite --track-origins=yes"
export SCENARIO_TIMEOUT=90
SUMMARY=$RUNBASE/summary-valgrind.txt; : > "$SUMMARY"
C=$HERE/driver-test-configs
run() { local n=$1; shift; RUNDIR=$RUNBASE/valgrind-$n bash "$HERE/run-scenario.sh" "$n" "$@" 2>&1 | tail -n 1 | tee -a "$SUMMARY"; }
run open      "$C/ap-open.conf"     "$C/sta-open.conf"     --timeout 90 --post-sleep 4
run wpa2-psk  "$C/ap-wpa2-psk.conf" "$C/sta-wpa2-psk.conf" --timeout 90 --post-sleep 10
run wpa3-sae  "$C/ap-wpa3-sae.conf" "$C/sta-wpa3-sae.conf" --timeout 90 --post-sleep 4 --sta-cmds "status; disconnect; sleep 2; reconnect; sleep 6"
run ft-psk    "$C/ap-ft-psk.conf"   "$C/sta-ft-psk.conf"   --timeout 90 --post-sleep 4 --sta-cmds "sleep 2; roam 02:00:00:00:02:00; sleep 4; ft_ds 02:00:00:00:01:00; sleep 4"
run mld       "$C/ap-mld-link0.conf" "$C/sta-mld.conf" --ap2 "$C/ap-mld-link1.conf" --timeout 90 --post-sleep 6
run udp-transport "$C/ap-udp.conf"  "$C/sta-udp.conf"      --timeout 90 --post-sleep 4
for n in open wpa2-psk wpa3-sae ft-psk mld udp-transport; do
	echo "--- valgrind findings in $n:"; grep -hE "ERROR SUMMARY|definitely lost|Invalid (read|write)|uninitialised|Conditional jump" $RUNBASE/valgrind-$n/*.log | sort | uniq -c | head -5
done | tee -a "$SUMMARY"
if [ -n "${EVIDENCE_DIR:-}" ]; then cp "$SUMMARY" "$EVIDENCE_DIR/"; for n in open wpa2-psk wpa3-sae ft-psk mld udp-transport; do mkdir -p "$EVIDENCE_DIR/valgrind-$n"; cp $RUNBASE/valgrind-$n/*.log $RUNBASE/valgrind-$n/RESULT "$EVIDENCE_DIR/valgrind-$n/" 2>/dev/null; done; fi
