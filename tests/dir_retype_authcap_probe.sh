#!/bin/bash
# dir_retype_authcap_probe.sh — the PRODUCER side of the classless directory
# image, measured on a live cluster with nobody killed.
#
# Why: on the two-node TCP rig, the foreign replay of a dead node's slice was
# terminally refused — 'P227-FR-TORN-UNPUBLISHED slot 1: replay refused 1
# committed unauthorized image(s)', AG quarantined, both mounts then dead on the
# root inode (tests/evidence/20260909T153444Z_ghost_s571a).  The two offending
# tokens were 'P227-TOKEN blkno=4332056 len=8 blft=13 v=3 class=0 st=4' and the
# same at blkno=4332064 blft=11 — DIR_LEAF1 and DIR_DATA, class NONE, status 4
# (MISLABELLED).  That status is written by pal/linux/xfs_buf_item.c
# mxfs_auth_classify's `!auth && ge` arm when the inode arm underneath it did
# not come back DURABLE, and it FLATTENS the specific outcome, so the replayer
# cannot say why.  The producer names it: P239-OWNAUTH-NONDUR carries the
# outcome, the owner inode, the dlm mode and the comm.
#
# This needs no death and no crash.  A directory that grows past shortform and
# then past one block re-types the same buffers inside a transaction, which is
# where the capture instant lands.  Run the growth, read the producer's probes.
#
# the budget rule (derived): the same 300-file create the cross-grant workload does takes
# ~5 s per node (measured 2026-09-09: test1 5660 ms, test2 5330 ms).  Growth to
# leaf needs no more.  Budget: 60 s per node stage, 180 s whole probe.
#
# Usage: tests/dir_retype_authcap_probe.sh <label> [COUNT=400]
# Env:   MXFS_NODE_LIST (default test1,test2), MNT (default /mnt/shared)
set -u
LABEL=${1:?label}
COUNT=${2:-400}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
A=${MXFS_NODE_LIST%%,*}
B=${MXFS_NODE_LIST##*,}
SSH=tools/mxfs_sshpass.sh
MNT=${MNT:-/mnt/shared}
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_authcap_$LABEL
mkdir -p "$OUT"
fails=0
ck() { if [ "$2" = "$3" ]; then echo "  PASS $1 ($2)"; else echo "  FAIL $1 got=$2 want=$3"; fails=$((fails+1)); fi; }
# rs/rsx/measure/capture_require/value_now_into/window_into (tests/lib/rig.sh):
# every capture a verdict is taken from crosses the boundary in the parent
# shell first; a failed acquisition is an ABORT, never a count of zero or an
# empty value.
. "$(dirname "$0")/lib/rig.sh"
SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
echo "=== dir_retype_authcap_probe label=$LABEL A=$A B=$B count=$COUNT sv=$SV $(date -u +%FT%TZ) ==="
echo "=== evidence $OUT"

# PREP=1: a FRESH filesystem is part of the shape.  The captures this probe
# hunts appeared in the first workload after a mkfs — at blocks 80 and 88, the
# first directory blocks the filesystem ever allocated — and a warm cluster that
# has already run several workloads does not produce them (runs s573 and s576,
# 400 concurrent creates per node each, zero directory-buffer captures).
if [ "${PREP:-0}" = 1 ]; then
    t0=$(date +%s)
    MXFS_FORCE_PREP=1 timeout 300 ./run.sh 2 tcp prep_cluster > "$OUT/prep.log" 2>&1
    rc=$?
    echo "STAGE prep rc=$rc wall=$(( $(date +%s) - t0 ))s  $(grep -am1 'prep_cluster OK\|FAIL' "$OUT/prep.log" | cut -c1-140)"
    [ $rc = 0 ] || { echo "RESULT: FAIL label=$LABEL stage=prep evidence=$OUT"; exit 2; }
fi

for n in $A $B; do
    value_now_into m "$n" 30 "$OUT/rv_m_1.txt" '^(MOUNTED|NOT_MOUNTED)$' "m on $n" "mountpoint -q $MNT && echo MOUNTED || echo NOT_MOUNTED"
    ck "$n mounted" "$m" "MOUNTED"
done
[ $fails = 0 ] || { echo "RESULT: FAIL label=$LABEL precondition"; exit 2; }

DIR=$MNT/authcap_$LABEL
MARK=$(date +%s)
# CONCURRENTLY, each node in its own subdirectory of one parent — the exact
# shape of tests/cross_grant_workload.sh, which is the workload whose slices got
# refused.  Sequential growth does NOT reproduce it: run s573 grew a directory
# one node at a time and every conversion re-proved cleanly
# (P-AUTHCAP-RETYPE-OK class=3).  What the failing laps add is a peer hammering
# the same allocation group while the conversion runs, which is when the
# converting node's authority for its own directory inode can be anything but
# durably held.
t0=$(date +%s)
if [ "${REPEAT:-0}" -gt 0 ] 2>/dev/null; then
    # The capture is intermittent — one whole-cluster-restart lap in six carried
    # it, and a single workload never has.  P239-OWNAUTH-NONDUR's print budget is
    # PER OUTCOME (48 each, per module load), so the inode-cluster NOOWNER
    # population saturating does not hide a rarer directory outcome.  Repeating
    # the workload on one mount is ~10 s a lap against ~250 s for a restart lap,
    # so this is where to spend the laps.
    i=1
    while [ $i -le "${REPEAT}" ]; do
        timeout 150 tests/cross_grant_workload.sh "${LABEL}w$i" "$COUNT" > "$OUT/work$i.log" 2>&1
        r=$?
        hit=0
        for n in $A $B; do
            c=$(rs 30 "$n" "journalctl -k --since @$MARK --no-pager 2>/dev/null | grep -a 'P239-OWNAUTH-NONDUR' | grep -ac 'blft=1[0-4] '")
            [ "${c:-0}" = 0 ] || hit=$((hit + c))
        done
        echo "STAGE repeat $i/$REPEAT rc=$r $(grep -aom1 'XGRANT-MEASURE.*wall_s=[0-9]*' "$OUT/work$i.log") dir_captures=$hit"
        [ "$hit" = 0 ] || { echo "STAGE repeat: directory-buffer capture SEEN at iteration $i — harvesting"; break; }
        i=$((i + 1))
    done
    echo "STAGE repeat wall=$(( $(date +%s) - t0 ))s"
elif [ "${WORKLOAD:-0}" = 1 ]; then
    # The real thing.  Neither this probe's own create loop nor a warm cluster
    # reproduces the capture (runs s573, s576, s577 — 400 concurrent creates per
    # node, one of them straight off a fresh mkfs — all zero); the workload whose
    # slices were refused writes file CONTENT and then has each node stat every
    # one of the peer's files, which is what moves a directory's authority
    # between the two nodes.  Run it verbatim rather than approximating it.
    timeout 150 tests/cross_grant_workload.sh "${LABEL}w" "$COUNT" > "$OUT/work.log" 2>&1
    echo "STAGE workload rc=$? wall=$(( $(date +%s) - t0 ))s"
    grep -a 'PASS\|FAIL\|XGRANT-MEASURE' "$OUT/work.log" | sed 's/^/    /'
else
    for n in $A $B; do
        rs 120 "$n" "mkdir -p $DIR/$n && cd $DIR/$n && i=0; while [ \$i -lt $COUNT ]; do : > f\$i || echo CREATE_ERR i=\$i; i=\$((i+1)); done; sync -f $MNT; echo CREATED=\$? node=$n files=\$(ls -1 $DIR/$n | wc -l)" > "$OUT/create_$n.txt" &
    done
    wait
    for n in $A $B; do echo "STAGE create $(grep -a 'CREATED=' "$OUT/create_$n.txt")"; done
    echo "STAGE create wall=$(( $(date +%s) - t0 ))s"
fi

for n in $A $B; do
    t=$([ "$n" = "$A" ] && echo A || echo B)
    rs 45 "$n" "journalctl -k --since @$MARK --no-pager 2>/dev/null | cut -c1-500" > "$OUT/${t}_journal.txt"
    echo "--- $n ($t)"
    for pat in 'P239-OWNAUTH-NONDUR' 'P241-AUTHTRY' 'P-AUTHCAP-VOID' 'P-AUTHCAP-RETYPE-OK' 'P-AUTHCAP-RETYPE-MIXED' 'P-IUNLINK-AGCLASS'; do
        printf '    %-24s %s\n' "$pat" "$(grep -ac "$pat" "$OUT/${t}_journal.txt")"
    done
    echo "    NONDUR by blft/outcome:"
    grep -ao 'P239-OWNAUTH-NONDUR[^—]*' "$OUT/${t}_journal.txt" |
        sed 's/.*blft=\([0-9]*\) outcome=\([0-9-]*\).*/      blft=\1 outcome=\2/' |
        sort | uniq -c | sed 's/^/    /'
    echo "    NONDUR lines for the directory buffer types (blft 10-14), first 8:"
    grep -a 'P239-OWNAUTH-NONDUR' "$OUT/${t}_journal.txt" |
        grep -a 'blft=1[0-4] ' | head -8 | sed 's/^/      /' | cut -c1-260
    # outcome x dlm mode is the discriminating cross-tab: a non-durable
    # authority taken while this node holds a WRITING mode is a publication /
    # recorder ordering gap; taken WITHOUT one it is an unauthorized mutation,
    # which is a live coherency defect and not a recovery one.
    echo "    directory-buffer NONDUR by outcome x mode:"
    grep -a 'P239-OWNAUTH-NONDUR' "$OUT/${t}_journal.txt" | grep -a 'blft=1[0-4] ' |
        sed 's/.*outcome=\([0-9-]*\).*mode=\([0-9]*\).*/      outcome=\1 mode=\2/' |
        sort | uniq -c | sed 's/^/    /'
    ck "$n: zero non-durable authority captures on a directory buffer" \
       "$(grep -a 'P239-OWNAUTH-NONDUR' "$OUT/${t}_journal.txt" | grep -ac 'blft=1[0-4] ')" "0"
done

if [ $fails = 0 ]; then echo "RESULT: PASS label=$LABEL evidence=$OUT"; else echo "RESULT: FAIL label=$LABEL fails=$fails evidence=$OUT"; fi
exit $fails
