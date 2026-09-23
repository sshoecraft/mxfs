#!/bin/bash
# dir_node_middle_free_2node.sh — a peer's cached view of a node-format
# directory must survive the owner freeing a MIDDLE data block.  Two-node TCP.
#
# The leaf-format removename path refuses to free an emptied middle data
# block under multi-node (dir_keep_middle_block): the freed extent leaves a
# hole in the data region while a peer's stale leaf/free-index image may
# still point a create at that block (the sess49b DABUF_MAP_HOLE shutdown).
# The NODE-format path (xfs_dir2_leafn_remove) has no such gate, so any
# directory past ~500 entries frees middle blocks.  The P-IFLUSH-GAP-DETECT
# line on test2 (2026-09-08 20:25:41Z, a 2000-entry private directory under
# rm) was exactly that hole.  This probe asks whether it is HARMFUL across
# nodes: A builds a node-format directory, B caches a view of it (readdir,
# lookups), A empties one middle data block, then B reads, looks up and
# CREATES in the directory — the create is the operation that consults the
# free index and would read the freed block through a stale map.
#
# the budget rule (derived): A's ENTRIES creates at ~7 ms = 9 s for 1200; B's prime
# ~2 s; A's 300 unlinks ~1 s; B's post ops ~1 s; captures 4 s.  ~20 s.
# Per-command bounds: creates 40 s, unlinks 20 s, each B step 20 s.
#
# Usage: tests/dir_node_middle_free_2node.sh <label> [ENTRIES=1200] [RM_FROM=100] [RM_TO=400]
# Env:   MXFS_NODE_LIST (default test1,test2; A owns, B is the peer), PREP=1.
set -u
LABEL=${1:?label}
ENTRIES=${2:-1200}
RM_FROM=${3:-100}
RM_TO=${4:-400}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
# MXFS_DEV: the caller's, else prep_cluster's per-transport rig default
# (no other rig's device path is assumed here)
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-tcp}
A=${MXFS_NODE_LIST%%,*}
B=${MXFS_NODE_LIST##*,}
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
D=$MNT/nodemid_$LABEL
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_nodemid_$LABEL
mkdir -p "$OUT"
fails=0
ck() { if [ "$2" = "$3" ]; then echo "  PASS $1 ($2)"; else echo "  FAIL $1 got=$2 want=$3"; fails=$((fails+1)); fi; }
# rs/rsx/measure/capture_require (tests/lib/rig.sh): every capture a verdict
# is counted from crosses the boundary in the parent shell first; a failed
# acquisition is an ABORT, never a count of zero.
. "$(dirname "$0")/lib/rig.sh"
HEALTH='corruption\|shutting down\|shut down\|BUG:\|Oops\|P95-OPEN-PROTECT\|P-INODE-WEDGE\|P-WITHDRAW\|P277-\|unrecoverable\|lock request failed\|DABUF_MAP_HOLE\|P-HOLE'
NOISE='P-TAUTH-PREPARED\|P-TAUTH-ACTIVATE\|PAGE-MINE\|HANDOFF\|TAKEOVER-RETIRE\|bdev_io'
NREM=$(( RM_TO - RM_FROM + 1 ))
EXPECT=$(( ENTRIES - NREM ))

echo "=== dir_node_middle_free_2node label=$LABEL A=$A B=$B entries=$ENTRIES rm=f$RM_FROM..f$RM_TO sv=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p') $(date -u +%FT%TZ) ==="
s=$(date +%s)
if [ -n "${PREP:-}" ]; then
    MXFS_FORCE_PREP=1 timeout 300 ./run.sh 2 tcp prep_cluster > "$OUT/prep.log" 2>&1
    prc=$?
    echo "STAGE prep rc=$prc wall=$(( $(date +%s) - s ))s"
    if [ $prc != 0 ]; then echo "RESULT: FAIL label=$LABEL prep rc=$prc"; exit 2; fi
fi
for n in $A $B; do
    measure "$n" 20 "$OUT/${n}_mounted.txt" '^[0-9]+$' "the mount count on $n" "grep -c ' $MNT mxfs ' /proc/mounts || true"
done
ck "both nodes mounted" "$(cat "$OUT/${A}_mounted.txt" "$OUT/${B}_mounted.txt" | tr -d '\n')" "11"
MK="NODEMID-$LABEL"
for n in $A $B; do rs 15 "$n" "echo '$MK' > /dev/kmsg" >/dev/null; done

# Stage 1 (A): a node-format directory.
measure "$A" 60 "$OUT/create_$A.txt" '^A_CREATE done ' "the directory build on $A" "mkdir -p $D && cd $D && s=\$(date +%s%N); i=0; while [ \$i -lt $ENTRIES ]; do : > \$(printf f%04d \$i) || echo CREATE_ERR i=\$i; i=\$((i+1)); done; sync -f $MNT; e=\$(date +%s%N); echo A_CREATE done n=\$i wall_ms=\$(( (e - s) / 1000000 )) ino=\$(stat -c %i $D) size=\$(stat -c %s $D) blocks=\$(stat -c %b $D)"
echo "  INFO $(tr '\n' ' ' < "$OUT/create_$A.txt")"
ck "A created $ENTRIES entries" "$(grep -ac "A_CREATE done n=$ENTRIES" "$OUT/create_$A.txt")" "1"
ck "A's directory is past leaf format (more than one 4 KiB data block)" "$( [ "$(grep -ao 'size=[0-9]*' "$OUT/create_$A.txt" | cut -d= -f2)" -gt 4096 ] 2>/dev/null && echo 1 || echo 0)" "1"

# Stage 2 (B): cache a view — readdir, lookups on entries in every block.
measure "$B" 30 "$OUT/prime_$B.txt" '^B_PRIME n=[0-9]+$' "B's primed readdir" "n=\$(ls $D | wc -l); stat -c %i $D/f0000 $D/f0150 $D/f0250 $D/f0350 $D/f0600 $D/f1100 > /dev/null; echo B_PRIME n=\$n"
echo "  INFO $(tr '\n' ' ' < "$OUT/prime_$B.txt")"
ck "B's primed readdir saw every entry" "$(grep -ao 'B_PRIME n=[0-9]*' "$OUT/prime_$B.txt" | cut -d= -f2)" "$ENTRIES"

# Stage 3 (A): empty a middle data block (entries f$RM_FROM..f$RM_TO cover
# at least one whole 168-entry block that is neither the first nor the last).
measure "$A" 30 "$OUT/rm_$A.txt" '^A_RM done ' "the middle-block removal on $A" "cd $D && s=\$(date +%s%N); i=$RM_FROM; while [ \$i -le $RM_TO ]; do rm \$(printf f%04d \$i) || echo RM_ERR i=\$i; i=\$((i+1)); done; sync -f $MNT; e=\$(date +%s%N); echo A_RM done n=$NREM wall_ms=\$(( (e - s) / 1000000 )) size=\$(stat -c %s $D) blocks=\$(stat -c %b $D) nextents_probe=\$(dmesg | grep -a 'P32-IFLUSH-NXSHRINK ino='\$(stat -c %i $D)' ' | tail -1 | grep -ao 'incore_nx=[0-9]* disk_nx=[0-9]*')"
echo "  INFO $(tr '\n' ' ' < "$OUT/rm_$A.txt")"
ck "A removed the $NREM entries" "$(grep -ac "A_RM done n=$NREM" "$OUT/rm_$A.txt")" "1"

# Stage 4 (B): read, look up, and CREATE through the possibly-stale view.
measure "$B" 30 "$OUT/post_$B.txt" '^B_POST n=' "B's read, lookups and creates through its view" "n=\$(ls $D | wc -l); m=0; for f in f0000 f0150 f0250 f0350 f0600 f1100; do stat -c %i $D/\$f > /dev/null 2>&1 && m=\$((m+1)); done; s=\$(date +%s%N); : > $D/from_B_1 && : > $D/from_B_2 && : > $D/from_B_3; rc=\$?; e=\$(date +%s%N); sync -f $MNT; echo B_POST n=\$n present=\$m create_rc=\$rc create_ms=\$(( (e - s) / 1000000 )) n2=\$(ls $D | wc -l)"
echo "  INFO $(tr '\n' ' ' < "$OUT/post_$B.txt")"
v() { grep -ao " $1=[^ ]*" "$OUT/post_$B.txt" | head -1 | cut -d= -f2; }
ck "B's readdir after the middle-block free shows exactly the surviving entries" "$(grep -ao 'B_POST n=[0-9]*' "$OUT/post_$B.txt" | cut -d= -f2)" "$EXPECT"
ck "B's lookups: the 3 survivors present, the 3 removed absent" "$(v present)" "3"
ck "B's creates into the directory succeeded" "$(v create_rc)" "0"
ck "B's readdir includes its own 3 creates" "$(v n2)" "$(( EXPECT + 3 ))"
# Stage 5 (A): sees B's creates; both views agree.
measure "$A" 30 "$OUT/view_$A.txt" '^A_VIEW n=' "A's view after B's creates" "echo A_VIEW n=\$(ls $D | wc -l) fromB=\$(ls $D | grep -c from_B_)"
echo "  INFO $(tr '\n' ' ' < "$OUT/view_$A.txt")"
ck "A's view: surviving entries + B's 3 creates" "$(grep -ao 'A_VIEW n=[0-9]*' "$OUT/view_$A.txt" | cut -d= -f2)" "$(( EXPECT + 3 ))"
for n in $A $B; do
    measure "$n" 40 "$OUT/dmesg_full_$n.txt" '^DMESG_END$' "the kernel log on $n from the lap marker" "dmesg | sed -n '/$MK/,\$p' | grep -a 'mxfs' | grep -av '$NOISE'; echo DMESG_END"
done
capture_require "$OUT/dmesg_full_$A.txt" '^DMESG_END$' "the kernel log on $A"
capture_require "$OUT/dmesg_full_$B.txt" '^DMESG_END$' "the kernel log on $B"
# The P-IFLUSH-GAP-DETECT report names DABUF_MAP_HOLE in its own wording; the
# first lap (s543i) counted its three report lines as three map-hole FAULTS.
# A fault is a DABUF_MAP_HOLE / P-HOLE line that is not the detector talking.
gap=$(cat "$OUT/dmesg_full_$A.txt" "$OUT/dmesg_full_$B.txt" | grep -ac 'GAP-DETECT')
hole=$(cat "$OUT/dmesg_full_$A.txt" "$OUT/dmesg_full_$B.txt" | grep -av 'GAP-DETECT' | grep -ac 'DABUF_MAP_HOLE\|P-HOLE')
lkto=$(cat "$OUT/dmesg_full_$A.txt" "$OUT/dmesg_full_$B.txt" | grep -ac 'P-LKTIMEOUT')
echo "  NODEMID-MEASURE $LABEL entries=$ENTRIES removed=$NREM gap_detect_lines=$gap map_hole_lines=$hole lock_timeouts=$lkto B_create_ms=$(v create_ms)"
ck "no directory map-hole fault on either node" "$hole" "0"
# 0.75.63: a hole punched by this node's own middle-block shrink, or adopted
# from a holey canonical disk image, is a known origin and the detector stays
# silent; a report here means a hole with NO known origin (the tear signature).
ck "no hole report of unknown origin from the flush-time detector" "$gap" "0"
ck "no DLM request deadline expired on either node" "$lkto" "0"
health=$(cat "$OUT/dmesg_full_$A.txt" "$OUT/dmesg_full_$B.txt" | grep -av 'GAP-DETECT' | grep -aic "$HEALTH")
ck "kernel health A+B (full window)" "$health" "0"
ck "both nodes still mounted" "$(for n in $A $B; do rs 20 "$n" "grep -c ' $MNT mxfs ' /proc/mounts"; done | tr -d '\n')" "11"
rs 60 "$A" "rm -rf $D" >/dev/null
wall=$(( $(date +%s) - s ))
if [ $fails = 0 ]; then echo "RESULT: PASS label=$LABEL wall=${wall}s evidence=$OUT"; else echo "RESULT: FAIL label=$LABEL fails=$fails wall=${wall}s evidence=$OUT"; fi
exit $fails
