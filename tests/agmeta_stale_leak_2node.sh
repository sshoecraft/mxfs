#!/bin/bash
# agmeta_stale_leak_2node.sh — an allocation-group release must not wait on
# freed btree blocks.  Two-node TCP rig.
#
# Every AG-metadata buffer (AGF/AGI/bnobt/cntbt/inobt/finobt block) logged on
# a node takes a track hold and a per-AG pending count that the release
# pipeline waits on (Phase 3, bounded at 2 s) before the AG grant is handed
# to a peer.  The count is returned at write completion.  A btree block that
# is FREED after being logged (a leaf merge or a root collapse invalidates it
# with xfs_trans_binval) never writes back: its log item is freed through the
# stale completion path.  If that path does not return the track hold, the
# pending count stays above zero for the life of the mount and EVERY later
# release of that AG on that node waits the full 2 s bound
# (P55-STUCKMETA pending=N write_inflight=0), which is what expired the peer's
# 1 s DLM request deadline in lap s542e.
#
# A grows and collapses the free-space btrees of one AG: fallocate an 8 MiB
# file, punch every other block (1024 free-space records — more than one
# 4 KiB bnobt/cntbt leaf holds, so both trees split), then rm the file (the
# fragments coalesce, both trees collapse, the split blocks are freed).  B
# then allocates in that AG twice, each a cross-node AG hand-off.  A's
# release stage timings (P12-AGREL-STAGES) and the stuck-metadata probe are
# the verdict.
#
# the budget rule (derived): punch loop 1024 x ~3 ms = 3 s; rm + sync 1 s; two B
# allocations at <= 100 ms each healthy (2 s each when the leak is present);
# four dmesg captures ~4 s.  Healthy wall ~10 s, leaking wall ~14 s.  Bounds:
# punch 30 s, each B op 10 s.  NOPREP=1 reuses the mount (default here: the
# leak needs no fresh filesystem).
#
# Usage: tests/agmeta_stale_leak_2node.sh <label> [PUNCHES=1024]
# Env:   MXFS_NODE_LIST (default test1,test2; A grows/collapses, B requests),
#        PREP=1 to run prep_cluster first.
set -u
LABEL=${1:?label}
PUNCHES=${2:-1024}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
# the device under test by identity, not by path: the LUN this rig declares
# (data/rigs.json), verified by its WWID on the node, and the node's live mxfs
# mount when it has one; MXFS_DEV names a candidate that must be that LUN.
# mxfs_dev_resolve (tests/lib/rig.sh) ABORTs on anything else, never defaults
. "$(dirname "$0")/lib/rig.sh"
mxfs_dev_resolve "${MXFS_NODE_LIST%%,*}"; export MXFS_DEV=$MXFS_DEV_RESOLVED
A=${MXFS_NODE_LIST%%,*}
B=${MXFS_NODE_LIST##*,}
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
D=$MNT/agleak_$LABEL
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_agleak_$LABEL
mkdir -p "$OUT"
fails=0
# ck: tests/lib/rig.sh (sourced above) provides it, and its version ABORTs on an EMPTY value instead of printing a FAIL about MXFS
filt() { grep -av '^Unauthorized\|^Warning:\|^If you\|^$'; }
# rs: tests/lib/rig.sh (sourced above) provides the same helper; a local copy would shadow it
HEALTH='corruption\|shutting down\|shut down\|BUG:\|Oops\|P95-OPEN-PROTECT\|P-INODE-WEDGE\|P-WITHDRAW\|P277-\|unrecoverable\|lock request failed'
NOISE='P-TAUTH-PREPARED\|P-TAUTH-ACTIVATE\|PAGE-MINE\|HANDOFF\|TAKEOVER-RETIRE\|bdev_io'

echo "=== agmeta_stale_leak_2node label=$LABEL A=$A B=$B punches=$PUNCHES sv=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p') $(date -u +%FT%TZ) ==="
s=$(date +%s)
if [ -n "${PREP:-}" ]; then
    MXFS_FORCE_PREP=1 timeout 300 ./run.sh 2 tcp prep_cluster > "$OUT/prep.log" 2>&1
    prc=$?
    echo "STAGE prep rc=$prc wall=$(( $(date +%s) - s ))s"
    if [ $prc != 0 ]; then echo "RESULT: FAIL label=$LABEL prep rc=$prc"; exit 2; fi
fi
for n in $A $B; do
    echo "  INFO $n $(rs 20 "$n" "echo sv=\$(cat /sys/module/mxfs/srcversion) mounted=\$(grep -c ' $MNT mxfs ' /proc/mounts) ft=\$(cat /sys/module/mxfs/parameters/force_transport)" | tr -d '\n')"
done
ck "both nodes mounted" "$(for n in $A $B; do rs 20 "$n" "grep -c ' $MNT mxfs ' /proc/mounts"; done | tr -d '\n')" "11"
MK="AGLEAK-$LABEL"
for n in $A $B; do rs 15 "$n" "echo '$MK' > /dev/kmsg" >/dev/null; done

# Stage 1 (A): grow the free-space btrees of one AG, then collapse them.
# h1/h2/a1 are one-block files in the same AG (they follow the directory's
# AG); B's unlinks of h1/h2 and A's unlink of a1 are forced requests for
# THAT AG later — a create would be steered to an uncontended AG instead.
rs 40 "$A" "mkdir -p $D && for h in h1 h2 a1; do dd if=/dev/zero of=$D/\$h bs=4096 count=1 conv=fsync status=none; done && fallocate -l 8M $D/f && sync -f $MNT && s=\$(date +%s%N); i=0; while [ \$i -lt $PUNCHES ]; do fallocate -p -o \$(( i * 8192 )) -l 4096 $D/f || echo PUNCH_ERR i=\$i; i=\$((i+1)); done; sync -f $MNT; e=\$(date +%s%N); echo A_PUNCH done n=\$i wall_ms=\$(( (e - s) / 1000000 )) ino=\$(stat -c %i $D/f) h1_ino=\$(stat -c %i $D/h1)" > "$OUT/punch_$A.txt"
echo "  INFO $(tr '\n' ' ' < "$OUT/punch_$A.txt")"
rs 30 "$A" "s=\$(date +%s%N); rm $D/f; sync -f $MNT; e=\$(date +%s%N); echo A_RM done wall_ms=\$(( (e - s) / 1000000 ))" > "$OUT/rm_$A.txt"
echo "  INFO $(tr '\n' ' ' < "$OUT/rm_$A.txt")"
rs 30 "$A" "dmesg | sed -n '/$MK/,\$p' | grep -a 'mxfs' | grep -av '$NOISE'" > "$OUT/dmesg_grow_$A.txt"
# The AG under test is the one A's dd-created files landed in (h1/h2/a1
# follow the directory's AG; f's blocks do too).  P150-ALLOC-FIN is printed
# per inode allocation; P145-FREE is capped and can be silent by now.
agno=$(grep -a 'comm=dd' "$OUT/dmesg_grow_$A.txt" | grep -ao 'agno=[0-9]*' | cut -d= -f2 | sort | uniq -c | sort -rn | head -1 | awk '{print $2}')
[ -z "$agno" ] && agno=$(grep -ao 'P145-FREE agno=[0-9]*' "$OUT/dmesg_grow_$A.txt" | cut -d= -f2 | sort | uniq -c | sort -rn | head -1 | awk '{print $2}')
frees=$(grep -ac 'P145-FREE' "$OUT/dmesg_grow_$A.txt")
lvl1=$(grep -ac "P144-WR \(bnobt\|cntbt\) agno=${agno:-X} .* lvl=1" "$OUT/dmesg_grow_$A.txt")
echo "  INFO A free-space frees=$frees dominant agno=${agno:-?} level-1 root writes seen=$lvl1"
ck "the punch+rm freed extents in one AG (agno resolved)" "$( [ -n "$agno" ] && echo 1 || echo 0)" "1"

# Stage 2: B unlinks h1 (inode + block free in the AG = forced AG hand-off
# A -> B), A unlinks a1 (A re-acquires the AG), B unlinks h2 (second hand-off
# A -> B).  Each B unlink is one cross-node release by A.
for k in 1 2; do
    rs 15 "$B" "s=\$(date +%s%N); rm $D/h$k; rc=\$?; sync -f $MNT; e=\$(date +%s%N); echo B_ALLOC k=$k rc=\$rc wall_ms=\$(( (e - s) / 1000000 ))" > "$OUT/alloc${k}_$B.txt"
    echo "  INFO $(tr '\n' ' ' < "$OUT/alloc${k}_$B.txt")"
    sleep 0.3
    if [ $k = 1 ]; then
        rs 15 "$A" "s=\$(date +%s%N); rm $D/a1; rc=\$?; sync -f $MNT; e=\$(date +%s%N); echo A_REACQ rc=\$rc wall_ms=\$(( (e - s) / 1000000 ))" > "$OUT/reacq_$A.txt"
        echo "  INFO $(tr '\n' ' ' < "$OUT/reacq_$A.txt")"
        sleep 0.3
    fi
done
for n in $A $B; do
    rs 40 "$n" "dmesg | sed -n '/$MK/,\$p' | grep -a 'mxfs' | grep -av '$NOISE'" > "$OUT/dmesg_full_$n.txt"
done
rel=$(grep -a "P12-AGREL-STAGES ag=${agno:-X} " "$OUT/dmesg_full_$A.txt")
nrel=$(printf '%s\n' "$rel" | grep -ac 'P12-AGREL')
p3max=$(printf '%s\n' "$rel" | grep -ao 'p3=[0-9]*' | cut -d= -f2 | sort -n | tail -1)
totmax=$(printf '%s\n' "$rel" | grep -ao 'total=[0-9]*' | cut -d= -f2 | sort -n | tail -1)
stuck=$(grep -ac 'P55-STUCKMETA' "$OUT/dmesg_full_$A.txt")
stuckline=$(grep -a 'P55-STUCKMETA' "$OUT/dmesg_full_$A.txt" | tail -1 | cut -c1-200)
reclaim=$(grep -ac 'P-AGMETA-RECLAIM' "$OUT/dmesg_full_$A.txt")
stale_clean=$(grep -ac 'P117-AGMETA-STALE-CLEAN' "$OUT/dmesg_full_$A.txt")
lkto=$(cat "$OUT/dmesg_full_$A.txt" "$OUT/dmesg_full_$B.txt" | grep -ac 'P-LKTIMEOUT')
b1=$(grep -ao 'wall_ms=[0-9]*' "$OUT/alloc1_$B.txt" | cut -d= -f2)
b2=$(grep -ao 'wall_ms=[0-9]*' "$OUT/alloc2_$B.txt" | cut -d= -f2)
bmax=$(printf '%s\n' "${b1:-99999}" "${b2:-99999}" | sort -n | tail -1)
echo "  AGLEAK-MEASURE $LABEL agno=${agno:-?} releases=$nrel p3_max_us=${p3max:-?} total_max_us=${totmax:-?} B_alloc_ms=${b1:-?}/${b2:-?} stuckmeta=$stuck reclaim_lines=$reclaim stale_clean_lines=$stale_clean lock_timeouts=$lkto"
[ -n "$stuckline" ] && echo "  INFO $stuckline"
ck "A released the AG to B at least twice" "$( [ "${nrel:-0}" -ge 2 ] && echo 1 || echo 0)" "1"
ck "B's unlinks both returned rc=0" "$(cat "$OUT"/alloc[12]_$B.txt | grep -ac 'rc=0')" "2"
ck "pace: every AG release stage-3 wait under 100 ms (no wait on freed btree blocks)" "$( [ "${p3max:-999999999}" -le 100000 ] && echo 1 || echo 0)" "1"
ck "pace: every B unlink behind A's AG inside 300 ms" "$( [ "$bmax" -le 300 ] && echo 1 || echo 0)" "1"
ck "no stuck-metadata timeout on A" "$stuck" "0"
ck "no DLM request deadline expired on either node" "$lkto" "0"
health=$(cat "$OUT/dmesg_full_$A.txt" "$OUT/dmesg_full_$B.txt" | grep -aic "$HEALTH")
ck "kernel health A+B (full window)" "$health" "0"
ck "both nodes still mounted" "$(for n in $A $B; do rs 20 "$n" "grep -c ' $MNT mxfs ' /proc/mounts"; done | tr -d '\n')" "11"
rs 20 "$B" "rmdir $D" >/dev/null
wall=$(( $(date +%s) - s ))
if [ $fails = 0 ]; then echo "RESULT: PASS label=$LABEL wall=${wall}s evidence=$OUT"; else echo "RESULT: FAIL label=$LABEL fails=$fails wall=${wall}s evidence=$OUT"; fi
exit $fails
