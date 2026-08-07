#!/bin/bash
# tests/reap_midlist_repro.sh — deterministic repro for
# D-REAP-IFREE-EFSCORRUPTED-SHUTDOWN-372.
#
# Mechanism (run2 ring forensics, sess47): unlink N files on UNL while OPN
# holds them open -> B6 defers destructive inactivation (P87), zombies parked
# on UNL's slot bucket (depth N chain).  Reclaim UNL's in-core shells
# (drop_caches) -> i_prev_unlinked/i_next_unlinked chain state destroyed.
# OPN closes -> UNL's reap worker igets fresh shells (restores bucket +
# LOCAL_UNLINK only, NOT chain state) and reaps in ADD order = tail-first.
# A non-head zombie takes the mid-list branch of xfs_iunlink_remove_inode
# with prev=0 -> xfs_iunlink_lookup(0)=NULL -> silent -EFSCORRUPTED ->
# xfs_ifree -117 -> forced shutdown + cluster withdrawal.
#
# Probes (0.11.374): P-UNLREM-INCOMPLETE (mechanism), P-UNLREM-NOPREV (the
# silent exit).  DEFECT REPRODUCED if either fires with error -117; FIXED
# when all inos reach P89-REAP-DONE with no -117 / no shutdown.
#
# RULE 0 budget: setup 10s + defer<=20s + reclaim 10s + close/retire<=40s +
# reap<=40s + free-verify<=40s => 160s hard cap, no I/O-bound phases.
#
# usage: reap_midlist_repro.sh [UNL=test2] [OPN=test1] [NFILES=4]
set -u
UNL="${1:-test2}"
OPN="${2:-test1}"
NF="${3:-4}"
SSH=tools/mxfs_sshpass.sh
RUNID="rml_$(date +%s)_$$"
D="/mnt/shared/.${RUNID}"
FAIL=0

say() { echo "[$(date +%H:%M:%S)] $*"; }
mark() { $SSH "$1" "echo ${RUNID}-$2 > /dev/kmsg" >/dev/null 2>&1; }
since() { $SSH "$1" "dmesg | sed -n \"/${RUNID}-$2/,\\\$p\" | grep -cE '$3'" 2>/dev/null | tr -d ' \r\n'; }
wait_cnt() { # node tag ere want timeout -> 0 ok
  local t=0 n
  while [ $t -lt "$5" ]; do
    n=$(since "$1" "$2" "$3"); [ "${n:-0}" -ge "$4" ] && return 0
    sleep 3; t=$((t+3))
  done
  return 1
}

say "1/6 setup: $NF files in one dir on $UNL"
$SSH "$UNL" "mkdir -p $D && for i in \$(seq 1 $NF); do head -c 16384 /dev/urandom > $D/f\$i; done && sync" || { echo "RESULT: SKIP (setup failed)"; exit 2; }
INOS=$($SSH "$UNL" "stat -c %i $D/f* | tr '\n' ' '")
say "   inos: $INOS"

say "2/6 open+hold all $NF on $OPN"
HPID=$($SSH "$OPN" "nohup bash -c 'for f in $D/f*; do exec {fd}<\"\$f\"; done; sleep 300' >/dev/null 2>&1 & echo \$!")
sleep 2
# holder must actually have the fds before the rm
NOPEN=$($SSH "$OPN" "ls /proc/$HPID/fd 2>/dev/null | wc -l")
[ "${NOPEN:-0}" -lt "$NF" ] && { echo "RESULT: SKIP (holder has $NOPEN fds)"; exit 2; }

mark "$UNL" rm
say "3/6 rm all on $UNL -> expect $NF x P87-OPEN-DEFER"
$SSH "$UNL" "rm -f $D/f1 $D/f2 $D/f3 $D/f4 $D/f5 $D/f6 $D/f7 $D/f8 2>/dev/null; true"
if ! wait_cnt "$UNL" rm "P87-OPEN-DEFER ino=" "$NF" 30; then
  n=$(since "$UNL" rm "P87-OPEN-DEFER ino="); echo "RESULT: SKIP (only $n/$NF deferred — opener bits not visible)"; exit 2
fi

say "4/6 reclaim shells on $UNL (drop_caches=2 x2)"
mark "$UNL" rc
$SSH "$UNL" "sync; echo 2 > /proc/sys/vm/drop_caches; sleep 2; echo 2 > /proc/sys/vm/drop_caches"
sleep 3
RCL=$(since "$UNL" rc "P140-RECLAIM-COMMIT")
say "   reclaim commits since rm: ${RCL:-0} (need the $NF zombies among them)"

say "5/6 close on $OPN -> retire cadence -> $UNL reap"
mark "$UNL" reap
$SSH "$OPN" "kill $HPID 2>/dev/null; true"
# defect fires at first post-close reap pass; fixed path emits P89-REAP-DONE per ino
DEADLINE=$((SECONDS+110)); VERDICT=""
while [ $SECONDS -lt $DEADLINE ]; do
  BAD=$(since "$UNL" reap "P-UNLREM-NOPREV|error -117|Metadata I/O Error")
  if [ "${BAD:-0}" -gt 0 ]; then VERDICT=REPRODUCED; break; fi
  DONE=$(since "$UNL" reap "P89-REAP-DONE")
  if [ "${DONE:-0}" -ge "$NF" ]; then VERDICT=CLEAN; break; fi
  sleep 5
done

say "6/6 verdict + forensics"
INC=$(since "$UNL" reap "P-UNLREM-INCOMPLETE")
$SSH "$UNL" "dmesg | sed -n \"/${RUNID}-reap/,\\\$p\" | grep -E 'P-UNLREM|P-UNLPRE|P88-REAP-RETRY|P89-REAP-DONE|error -117|P87-OPEN-DEFER|Metadata I/O' | tail -25"
case "$VERDICT" in
  REPRODUCED) echo "RESULT: REPRODUCED (defect fired; P-UNLREM-INCOMPLETE=$INC)"; exit 1 ;;
  CLEAN)      echo "RESULT: CLEAN ($NF reaped; P-UNLREM-INCOMPLETE=$INC)" ;;
  *)          echo "RESULT: INCONCLUSIVE (no shutdown, $(since "$UNL" reap "P89-REAP-DONE")/$NF reaped, P-UNLREM-INCOMPLETE=$INC)"; exit 3 ;;
esac

# ── Scenario B: predecessor VFS-LIVE (local fd) => igrab pin arm ──────────
# tail F1 peer-open + reclaimed; head F2 held open by a LOCAL fd on UNL
# (VFS-live zombie).  Reap of F1 must pin F2 via igrab, remove mid-list,
# then F2's own last-close inactivation completes the chain.
say "B1: setup 2 files"
DB="/mnt/shared/.${RUNID}B"
$SSH "$UNL" "mkdir -p $DB && head -c 16384 /dev/urandom > $DB/f1 && head -c 16384 /dev/urandom > $DB/f2 && sync"
BPID=$($SSH "$OPN" "nohup bash -c 'exec 9<$DB/f1; sleep 300' >/dev/null 2>&1 & echo \$!")
LPID=$($SSH "$UNL" "nohup bash -c 'exec 9<$DB/f2; sleep 300' >/dev/null 2>&1 & echo \$!")
sleep 2
mark "$UNL" b
say "B2: rm f1 (peer-open, tail) then f2 (local-open, head); reclaim; close peer"
$SSH "$UNL" "rm -f $DB/f1; sleep 1; rm -f $DB/f2; sync; echo 2 > /proc/sys/vm/drop_caches; sleep 2; echo 2 > /proc/sys/vm/drop_caches"
$SSH "$OPN" "kill $BPID 2>/dev/null; true"
DEADLINE=$((SECONDS+110)); BV=""
while [ $SECONDS -lt $DEADLINE ]; do
  BAD=$(since "$UNL" b "P-UNLREM-NOPREV|error -117|Metadata I/O Error")
  [ "${BAD:-0}" -gt 0 ] && { BV=REPRODUCED; break; }
  D1=$(since "$UNL" b "P89-REAP-DONE")
  [ "${D1:-0}" -ge 1 ] && { BV=CLEAN; break; }
  sleep 5
done
say "B3: close local fd; f2 frees on its own inactivation"
$SSH "$UNL" "kill $LPID 2>/dev/null; true"
sleep 8
$SSH "$UNL" "dmesg | sed -n \"/${RUNID}-b/,\\\$p\" | grep -E 'P-UNLPRE|P-UNLREM|P89-REAP-DONE|error -117' | tail -12"
PINNED=$(since "$UNL" b "P-UNLPRE-RECOVERED")
case "$BV" in
  CLEAN) echo "RESULT-B: CLEAN (recovered=$PINNED)"; exit 0 ;;
  REPRODUCED) echo "RESULT-B: REPRODUCED"; exit 1 ;;
  *) echo "RESULT-B: INCONCLUSIVE (recovered=$PINNED)"; exit 3 ;;
esac
