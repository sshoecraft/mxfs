#!/bin/bash
#
# release_after_queue.sh — wait for a lap queue to finish and, only when every
# lap of it passed, run the release verification on the module the queue ran.
#
# WHY.  The laps that verify a fix and the release chain both need the whole
# rig, the chain runs for hours, and its boards are not worth those hours on a
# module the laps have just failed.  tests/release_gate_chain.sh is this gate
# for the quiesce-and-remount laps; this is the same gate for a queue of
# tests/lap_queue.sh, whose last line carries the count the gate reads:
#
#     QUEUE DONE laps=<n> pass=<m> wall=<s>s <utc>
#
# WHAT IT DOES
#  1. waits for that line in <queue-log>, newer than the newest QUEUE START
#     (the log is appended to across runs of one label), for at most
#     <bound-s> seconds: the sum of that queue's own lap bounds, the longest
#     it can run.  Reaching the bound is a refusal, never a start.
#  2. requires pass == laps.  Anything else ends here with
#     GATE verdict=FAIL and the rig left alone.
#  3. requires the tree's mxfs.ko to be the module the fleet runs (the
#     srcversion node 1 reports): a module rebuilt since the laps is not the
#     module they verified.
#  4. runs tests/release_verify_chain.sh <version> with CLAIM, LAPS, FULL,
#     LOWER, POWER and PLATFORM_GROUPS as this script was given them.
#
# Log: tests/evidence/release_after_queue_<version>.log
#
# Usage: nohup setsid env CLAIM=8 POWER=1 \
#            PLATFORM_GROUPS="pve9,debian13 rhel9,ubuntu2404" \
#            tests/release_after_queue.sh <queue-log> <bound-s> <version> \
#            > tests/evidence/release_after_queue_<version>.out 2>&1 &
#
set -u
QLOG=${1:?the log of the queue to wait for, tests/evidence/lapq_LABEL.log}
BOUND=${2:?the sum of the lap bounds of that queue, in seconds}
V=${3:?the version to verify}
HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE" || exit 1
L="$HERE/tests/evidence/release_after_queue_$V.log"
SSH="$HERE/tools/mxfs_sshpass.sh"
say() { echo "$(date -u +%FT%TZ) $*" | tee -a "$L"; }
case $BOUND in ''|*[!0-9]*) echo "the bound must be a number of seconds: [$BOUND]" >&2; exit 2 ;; esac
[ -x tests/release_verify_chain.sh ] || { say "chain defect: tests/release_verify_chain.sh is not executable; nothing run"; exit 2; }
[ "$(cat VERSION)" = "$V" ] || { say "the tree is at $(cat VERSION), not $V; nothing run"; exit 2; }

done_line() {  # the QUEUE DONE line, if it is newer than the newest QUEUE START
    awk '/^QUEUE START/ { d = "" } /^QUEUE DONE/ { d = $0 } END { print d }' "$QLOG" 2>/dev/null
}
say "waiting for $QLOG to finish (bound ${BOUND}s), then CLAIM=${CLAIM:-4} release verification of $V"
w0=$(date +%s)
until [ -n "$(done_line)" ]; do
    if [ $(( $(date +%s) - w0 )) -ge "$BOUND" ]; then
        say "GATE verdict=REFUSED: no QUEUE DONE in ${BOUND}s, the longest that queue can run; the fleet may still be in use, nothing started"
        exit 2
    fi
    sleep 30
done
d=$(done_line)
laps=$(echo "$d" | sed -n 's/.* laps=\([0-9]*\) .*/\1/p')
pass=$(echo "$d" | sed -n 's/.* pass=\([0-9]*\) .*/\1/p')
say "queue ended: $d"
if [ -z "$laps" ] || [ "$laps" != "$pass" ]; then
    say "GATE verdict=FAIL: ${pass:-?} of ${laps:-?} laps passed; the release verification is not run on a module its laps failed"
    exit 1
fi
want=$(modinfo -F srcversion mxfs.ko 2>/dev/null)
got=$(timeout 30 "$SSH" test1 'cat /sys/module/mxfs/srcversion 2>/dev/null' </dev/null 2>/dev/null | tr -d '\r\n ')
if [ -z "$want" ] || [ "$want" != "$got" ]; then
    say "GATE verdict=FAIL: the tree's module is ${want:-unreadable} and the fleet ran ${got:-unreadable}; the laps did not verify the module the chain would build"
    exit 1
fi
say "GATE verdict=PASS: $pass of $laps laps, module $want; starting the release verification"
exec tests/release_verify_chain.sh "$V"
