#!/bin/bash
#
# alloclist_tail_pin.sh — after a create burst stops, the log tail must catch
# up with the head: no fresh inode chunk's cluster buffers may stay unwritten
# on their AG's alloc buflist pinning the AIL minimum.
#
# The defect (D-LAZY-AG-UNLOCK-PINNED-ALLOCLIST-LEFTOVERS-PIN-LOG-TAIL-UNTIL-
# NEXT-UNLOCK): the lazy unlock's non-waiting drain skips a buffer still pinned
# in the CIL and puts it back on the list "for the next unlock cycle"; xfsaild
# cannot write a buffer queued there; an AG this node stops using has no next
# cycle, so the last chunk's two cluster buffers sat unwritten for nine
# minutes at 4/net/mesh/direct, holding the log tail at their sequence.  0.90.16 forces
# the log and re-drains such an AG from a delayed work.
#
# Measure: A (with B mounted alongside, so the AG lock protocol is the
# multi-node one) creates FILES files in a fresh directory of its own, syncs,
# and stops.  Then A's log_tail_lsn and log_head_lsn (the filesystem's sysfs
# log attributes; the tail is the AIL minimum) are read every 5 s.  PASS when
# the tail reaches or passes the head recorded at the end of the burst within
# IDLE_S: everything the burst logged has then been written.  The default
# 120 s is two ticks of the 30 s log worker that covers an idle log, doubled.
# A tail that has not moved at all in that time is the pinned tail of the
# defect and FAILs.  The tail and the head are never equal on a covered idle
# log — the tail is the START of the last record written and the head its
# END, three blocks apart here — so "tail equals head" was an unattainable
# criterion: measured on 0.90.16 (evidence 20260929T020119Z) the tail passed
# the burst-end head 25 s after the burst, then both marks moved together
# through the two covering records and sat three blocks apart for the rest of
# the window, which the first version of this script called a FAIL.
#
# Usage: [FILES=3000] [IDLE_S=120] tests/alloclist_tail_pin.sh [A] [B]
#   A and B default to test1 test2 and must be mounted by
#   MXFS_FORCE_PREP=1 ./run.sh 2/net/mesh/direct prep_cluster (module loaded, LUN
#   formatted, MXFS_DEV / MXFS_MOUNT as run.sh).
#   Evidence: tests/evidence/alloclist_tail_pin/<stamp>/.  Exit 0 only on PASS.
#
set -u

HERE="$(cd "$(dirname "$0")/.." && pwd)"
A="${1:-test1}"
B="${2:-test2}"
FILES="${FILES:-3000}"
IDLE_S="${IDLE_S:-120}"
DEV="${MXFS_DEV:-/dev/disk/by-path/ip-192.168.120.1:3260-iscsi-iqn.2026-05.local.mxfs:shared-lun-0}"
MNT="${MXFS_MOUNT:-/mnt/shared}"
SSH="$HERE/tools/mxfs_sshpass.sh"
EV="$HERE/tests/evidence/alloclist_tail_pin/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$EV"
exec > >(tee -a "$EV/run.log") 2>&1
say() { echo "[$(date -u +%T)] $*"; }
on() {  # <node> <timeout-s> <cmd>
    local n=$1 t=$2; shift 2
    timeout "$t" "$SSH" "$n" "$@" </dev/null 2>&1 | grep --line-buffered -v -E "^Warning: Permanently|^$|Unauthorized access|authorized user, disconnect"
    return "${PIPESTATUS[0]}"
}

say "A=$A B=$B files=$FILES idle_s=$IDLE_S dev=$DEV mnt=$MNT evidence=$EV"
for n in "$A" "$B"; do
    on "$n" 30 "grep -q ' $MNT mxfs ' /proc/mounts && echo mounted; cat /sys/module/mxfs/srcversion" > "$EV/pre_$n.log"
    grep -q mounted "$EV/pre_$n.log" || { say "RESULT FAIL: $MNT is not an MXFS mount on $n (prep the 2-node cluster first)"; exit 1; }
    say "$n srcversion=$(tail -1 "$EV/pre_$n.log")"
done
# the sysfs log directory of A's mount: /sys/fs/<xfs|mxfs>/<kernel device name>/log
SYS=$(on "$A" 20 "d=\$(basename \$(readlink -f $DEV)); for k in /sys/fs/xfs /sys/fs/mxfs; do [ -d \$k/\$d/log ] && { echo \$k/\$d/log; break; }; done")
[ -n "$SYS" ] || { say "RESULT FAIL: no sysfs log directory for $DEV on $A"; exit 1; }
say "log attributes: $A:$SYS"
lsn() { on "$A" 20 "echo tail=\$(cat $SYS/log_tail_lsn) head=\$(cat $SYS/log_head_lsn)"; }

# the burst, then a sync (a pinned leftover survives a sync: xfsaild cannot
# write it, and the pre-0.90.16 code retried it only at the AG's next unlock).
# Bound: 2 x the 37 s measured wall (0.90.16, 2/net/mesh/direct; 25 s at 4/net/mesh/direct on
# 0.90.17); the first version's 300 s was a wedge bound.
t0=$(date +%s)
on "$A" 74 "d=$MNT/tailpin.\$\$; mkdir -p \$d && cd \$d && for i in \$(seq 1 $FILES); do : > f\$i; done; sync; echo created=\$(ls | wc -l) dir=\$d" > "$EV/burst.log"
grep -q "created=$FILES" "$EV/burst.log" || { say "RESULT FAIL: the burst did not create $FILES files ($(tail -1 "$EV/burst.log"))"; exit 1; }
say "burst: $(tail -1 "$EV/burst.log") in $(( $(date +%s) - t0 )) s"
first=$(lsn); say "after the burst: $first"
tail0=${first#tail=}; tail0=${tail0%% *}
head0=${first#*head=}
lsn_ge() {  # <a> <b>: true iff log sequence a (cycle:block) is at or past b
    local ac=${1%%:*} ab=${1#*:} bc=${2%%:*} bb=${2#*:}
    [ "$ac" -gt "$bc" ] || { [ "$ac" -eq "$bc" ] && [ "$ab" -ge "$bb" ]; }
}

caught=0; last=""
for ((t = 0; t <= IDLE_S; t += 5)); do
    last=$(lsn)
    echo "t=${t}s $last" >> "$EV/samples.log"
    tl=${last#tail=}; tl=${tl%% *}
    if lsn_ge "$tl" "$head0"; then caught=1; break; fi
    sleep 5
done
say "after ${t}s idle: $last (at burst end: tail $tail0, head $head0)"
tl=${last#tail=}; tl=${tl%% *}
if [ "$caught" = 1 ]; then
    say "RESULT PASS (the tail reached the burst-end head $head0 after ${t}s idle: everything the burst logged is written; samples in $EV/samples.log)"
    exit 0
elif [ "$tl" = "$tail0" ]; then
    say "RESULT FAIL (the log tail did not move in ${IDLE_S}s of idle: pinned at $tail0 — the AIL minimum is stuck; on 0.90.16 that is a leftover the retry did not write)"
    exit 1
else
    say "RESULT FAIL (the tail moved to $tl but did not reach the burst-end head $head0 within ${IDLE_S}s; samples in $EV/samples.log)"
    exit 1
fi
