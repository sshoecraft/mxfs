#!/bin/bash
# suite_tcp_clean.sh (sess49 ccloop 4cb2d0a2) — reboot-clean FULL tcp suite run
# for the "1/2/4/8 node tcp dlm test 100%" criterion.  virsh destroy+start the N
# nodes, wait for SSH+settle, then run the FULL `./run.sh N tcp` suite and print
# the per-test PASS/FAIL aggregate.
#
# Usage: tests/suite_tcp_clean.sh <N> [TEST_TIMEOUT] [modargs] [test ...]
#   e.g. tests/suite_tcp_clean.sh 8 480
#        tests/suite_tcp_clean.sh 8 480 "" cache_coherency zero_silent_loss
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd); cd "$REPO"
N="${1:?usage: suite_tcp_clean.sh <N> [TEST_TIMEOUT] [modargs] [test...]}"
TMO="${2:-480}"; MODARGS="${3:-}"; shift 3 2>/dev/null || shift $#
ONLY="$*"
SSH=tools/mxfs_sshpass.sh; PASS=/tmp/.mxfs_pass
ALL="test1 test2 test3 test4 test5 test6 test7 test8 test9 test10 test11 test12 test13 test14 test15 test16"
NODES=$(echo $ALL | tr ' ' '\n' | head -n "$N" | tr '\n' ' ')
echo "########## SUITE CLEAN N=$N tcp TEST_TIMEOUT=$TMO modargs=[$MODARGS] only=[$ONLY] @ $(date -u +%T) ##########"
for d in $NODES; do virsh -c qemu:///system destroy $d >/dev/null 2>&1; done
sleep 3
for d in $NODES; do virsh -c qemu:///system start $d >/dev/null 2>&1; done
for t in $(seq 1 60); do
  ok=1; for n in $NODES; do timeout 6 $SSH $n $PASS true 2>/dev/null || ok=0; done
  [ $ok = 1 ] && break; sleep 3
done
sleep 20
echo "--- nodes up, launching full suite @ $(date -u +%T) ---"
OUT=$(env MXFS_EXTRA_MODARGS="$MODARGS" TEST_TIMEOUT="$TMO" ./run.sh "$N" tcp $ONLY 2>&1)
echo "$OUT" | grep -E '  (PASS|FAIL)  '
echo "===== AGGREGATE ====="
echo "$OUT" | grep -E 'PASS|FAIL' | grep -cE '  PASS  ' | sed 's/^/PASS_tests=/'
echo "$OUT" | grep -E 'PASS|FAIL' | grep -cE '  FAIL  ' | sed 's/^/FAIL_tests=/'
echo "--- FAILED tests ---"; echo "$OUT" | grep -E '  FAIL  '
echo "########## suite done @ $(date -u +%T) ##########"
