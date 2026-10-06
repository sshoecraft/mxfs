#!/bin/bash
# tests/mkdir_mutex_storm.sh — every node takes and releases one directory as
# a mutex (mkdir / create inside / list / unlink / rmdir) and churns files
# beside it, all at once, for a fixed time.
#
# Why: on 4/disk/caw/mpath (path_answer_lost, 2026-10-04T23:07Z) one mkdir of
# the load's lock directory returned ESTALE.  The lookup had read the name's
# entry, a peer removed the directory and freed its inode, the number went
# file -> directory -> file -> free inside 110 ms, and the lookup's type
# resolver ended on a free inode and failed the walk
# (P201-TYPEFLIP-UNRESOLVED-FAIL incore_mode=00 p_stale=1) instead of reading
# the parent again.  The path rows reach that once in dozens of runs; this
# drives the same shape with nothing else in the loop and counts.
#
# Verdict: no operation on any node returned an error other than the two the
# workload makes itself (mkdir "exists", churn unlink "not found"), no double
# grant, and no node logged a shutdown.  Reported beside it: how many times a
# lookup met a freed inode and read the parent again (P201-RELOOKUP), and how
# many ended unresolved (P201-TYPEFLIP-UNRESOLVED-FAIL).  A run with neither
# line did not reach the window and says nothing about it.
#
# Usage (cluster formed and mounted, e.g. after ./run.sh <config> --group <g> prep_cluster):
#   MXFS_NODE_LIST=test3,test4,test5,test6 tests/mkdir_mutex_storm.sh [seconds]
#     seconds  default 120
# Env: MXFS_MNT (default /mnt/shared); PROBES=all for every probe (see below)
#
# derived time budget: seconds + 30 s of start, collection and ssh.
set -u
cd "$(dirname "$0")/.." || exit 2
. tests/lib/rig.sh
SECS=${1:-120}
NODES=${MXFS_NODE_LIST:?MXFS_NODE_LIST}
NODES=${NODES//,/ }
MNT=${MXFS_MNT:-/mnt/shared}
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUT=tests/evidence/mkdir_mutex_storm_$STAMP
mkdir -p "$OUT"
DIR=$MNT/mutex_storm_$STAMP
K=/run/mutex_storm_$STAMP
# The lines counted are probes (dynamic debug, off by default).  PROBES=all
# turns every probe on, as the path rows run and as the measured failure ran:
# about 2000 lines a second per node, which is itself part of the timing.
# The default turns on only the lines this harness counts.
DD=/proc/dynamic_debug/control
if [ "${PROBES:-counted}" = all ]; then
    PROBE_ON="echo 'module mxfs +p' > $DD"
    PROBE_OFF="echo 'module mxfs -p' > $DD"
else
    PROBE_ON="for f in P201- P95B-TYPEFLIP-WAIT P116-ZOMBIE-ADOPT P-LKERR; do echo \"module mxfs format \$f +p\" > $DD; done"
    PROBE_OFF="for f in P201- P95B-TYPEFLIP-WAIT P116-ZOMBIE-ADOPT P-LKERR; do echo \"module mxfs format \$f -p\" > $DD; done"
fi
for n in $NODES; do
    # the kernel lines of interest are kept as they are printed: a node's
    # ring holds about two minutes under this load
    rsx 20 "$n" "$PROBE_ON; rm -f $K.kmsg; nohup dmesg --follow < /dev/null > $K.kmsg 2>/dev/null & echo \$! > $K.pid
        sleep 0.5; echo armed" > "$OUT/arm_$n.txt" 2>&1
done
for n in $NODES; do
    ( rsx $((SECS + 30)) "$n" "python3 /src/mxfs/tests/mpath/mutex_storm.py $DIR $n $SECS" > "$OUT/storm_$n.txt" 2>&1 ) &
done
wait
bad=0; relook=0; unres=0
for n in $NODES; do
    rsx 30 "$n" "sleep 1; $PROBE_OFF; kill \$(cat $K.pid) 2>/dev/null; echo relookup=\$(grep -ac P201-RELOOKUP $K.kmsg) unresolved=\$(grep -ac P201-TYPEFLIP-UNRESOLVED-FAIL $K.kmsg) shutdown=\$(grep -ac 'hutting down filesystem' $K.kmsg) lkerr=\$(grep -ac P-LKERR $K.kmsg) flipwaits=\$(grep -ac P95B-TYPEFLIP-WAIT $K.kmsg) flip_unresolved=\$(grep -a P95B-TYPEFLIP-WAIT $K.kmsg | grep -ac 'resolved=0') freed_adopts=\$(grep -ac P116-ZOMBIE-ADOPT $K.kmsg); grep -a 'P201-\|resolved=0\|P-LKERR\|hutting' $K.kmsg | head -c 20000; rm -f $K.kmsg $K.pid" > "$OUT/kern_$n.txt" 2>&1
    l=$(grep -a '^STORM ' "$OUT/storm_$n.txt" | tail -1)
    k=$(grep -a '^relookup=' "$OUT/kern_$n.txt" | tail -1)
    echo "$n: ${l:-NO STORM LINE} | ${k:-no kernel counts}"
    [ -n "$l" ] || { bad=$((bad + 1)); continue; }
    e=$(sed -n 's/.* err=\([0-9]*\).*/\1/p' <<<"$l"); d=$(sed -n 's/.* double_grant=\([0-9]*\).*/\1/p' <<<"$l")
    s=$(sed -n 's/.*shutdown=\([0-9]*\).*/\1/p' <<<"$k")
    [ "${e:-1}" = 0 ] && [ "${d:-1}" = 0 ] && [ "${s:-1}" = 0 ] || bad=$((bad + 1))
    relook=$((relook + $(sed -n 's/^relookup=\([0-9]*\).*/\1/p' <<<"$k" | grep -a . || echo 0)))
    unres=$((unres + $(sed -n 's/^relookup=[0-9]* unresolved=\([0-9]*\).*/\1/p' <<<"$k" | grep -a . || echo 0)))
done
echo "RESULT: seconds=$SECS nodes_bad=$bad relookups=$relook unresolved=$unres evidence=$OUT"
[ "$bad" = 0 ]
