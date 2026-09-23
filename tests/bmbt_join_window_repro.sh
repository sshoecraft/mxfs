#!/bin/bash
# tests/bmbt_join_window_repro.sh <label> [delay_ms] [mode 1|2]
#
# mode 1 (the hazard): read, then reclaim — the tenure ends inside the window.
# mode 2 (positive control): reclaim, then read — the extent list is reloaded
# from its bmbt blocks inside the window and the tenure is still open at the
# census, which must then show bmbt_cached > 0 with orphans=0.  Measured s169d:
# reading alone reloads nothing (the in-core extent tree was loaded before the
# freeze), so only a reclaim-then-read puts bmbt blocks in the cache at all.
# Without mode 2 a CLEAN mode-1 run cannot be told apart from drop_caches
# having shrunk the buffers along with the inode, or from a blind census.
#
# Directed exerciser for D-BMBT-TENURE-END-EVICT-SKIP-WINDOW-BETWEEN-JOIN-DROP-AND-FLIP.
#
# The question: on the first join of a mount that has never had a peer, can a
# clean cached extent-tree (bmbt) block outlive the tenure that read it?  The
# join's prepare (under freeze_super) drops every clean cached block, but the
# freeze stops writers, not readers or inode reclaim, and until the view flips
# the node is alone, so mxfs_bmbt_tenure_end_evict skips.  A block read after
# the drop whose inode is reclaimed before the flip would survive into
# multi-node with no grant behind it.
#
# Shape: A mounts alone and writes a file fragmented past the inline extent
# list (a btree-format data fork).  dbg_join_flip_delay_ms on A widens the
# window between prepare's drop and the flip.  B mounts (the join); while A
# sits in that window a loop on A reads the file (caching its bmbt blocks
# under a tenure) and drops caches (the shrinker reclaims the inode, ending
# the tenure while A is still alone).  At the join commit the module counts
# clean cached bmbt blocks whose owner holds no grant (P-JOIN-BMBT-CENSUS).
#
# Verdicts: REPRODUCED orphans>0; CLEAN census ran with bmbt blocks read in
# the window and orphans=0; VACUOUS no census line, or the window loop never
# ran inside the delay.
#
# derived time budgets: two unmounts and two mounts at ~5 s each (d0959
# harness measurement), the fragmented file's 400 single-block writes ~3 s,
# B's join mount = its ordinary mount plus the injected delay, the evidence
# pull 30 s; every ssh step is bounded at the number beside it.
set -u
LABEL=${1:?label}
DELAY=${2:-4000}
MODE=${3:-1}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
A=${MXFS_NODE_LIST%%,*}
B=${MXFS_NODE_LIST##*,}
MNT=/mnt/shared
. "$(dirname "$0")/lib/rig.sh"
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_bmbtjw_$LABEL
mkdir -p "$OUT"
SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
echo "=== bmbt_join_window label=$LABEL delay_ms=$DELAY mode=$MODE sv=$SV out=$OUT $(date -u +%FT%TZ) ==="

timeout 400 ./run.sh 2 tcp prep_cluster > "$OUT/prep.log" 2>&1 \
    || { echo "RESULT: ABORT label=$LABEL stage=prep evidence=$OUT"; exit 2; }
mxfs_dev_resolve "$A"; DEV=$MXFS_DEV_RESOLVED

echo "  LEAVE B=$(rs 120 "$B" "umount $MNT; echo rc=\$?" | tr '\n' ' ') A=$(rs 120 "$A" "umount $MNT; echo rc=\$?" | tr '\n' ' ')"
amt=$(rs 120 "$A" "mount -t mxfs $DEV $MNT; echo A_SOLO_MOUNT_RC=\$?")
case "$amt" in *A_SOLO_MOUNT_RC=0*) ;; *) echo "RESULT: ABORT label=$LABEL $A could not mount alone: $amt"; exit 2 ;; esac

F=$MNT/bmbtjw_$LABEL
# Written then hole-punched every other block: extending writes into holes
# are coalesced by speculative preallocation (s169a: 6 extents), a punched
# written file cannot be.  ~400 extents is far past the inline extent list.
# Counted as filefrag -v's extent records: its summary line merges records
# whose physical gap equals the logical one and reads 1 for this file.
mk=$(rs 120 "$A" "rm -f $F; dd if=/dev/zero of=$F bs=4k count=800 conv=fsync status=none; for i in \$(seq 1 2 799); do fallocate -p -o \$((i * 4096)) -l 4096 $F; done; sync -f $MNT; echo FILE_EXTENTS=\$(filefrag -v $F 2>/dev/null | grep -c '^ *[0-9][0-9]*:')")
echo "  $mk"
case "$mk" in *FILE_EXTENTS=[1-9][0-9][0-9]*) ;; *) echo "RESULT: ABORT label=$LABEL the file is not fragmented enough for a btree fork: $mk evidence=$OUT"; exit 2 ;; esac

MK="BMBTJW-MARK-$LABEL-$$"
# The window loop runs on A from a script in the evidence directory (the tree
# is NFS-mounted on the nodes); it reads the kernel log only after its mark,
# so the join census prep's own join printed cannot end it early.
cat > "$OUT/window_loop.sh" <<EOF
r=0; w=0; end=\$((\$(date +%s) + 120))
while [ \$(date +%s) -lt \$end ]; do
    win=\$(dmesg | sed -n '/$MK/,\$p')
    if printf '%s' "\$win" | grep -aq P-JOIN-FLIP-DELAY; then
        if [ $MODE = 2 ]; then
            echo 2 > /proc/sys/vm/drop_caches; cat $F > /dev/null
        else
            cat $F > /dev/null; echo 2 > /proc/sys/vm/drop_caches
        fi
        w=\$((w + 1))
    fi
    printf '%s' "\$win" | grep -aq P-JOIN-BMBT-CENSUS && break
    r=\$((r + 1))
done
echo WINDOW_LOOP rounds=\$r in_window=\$w
EOF
rs 30 "$A" "echo $DELAY > /sys/module/mxfs/parameters/dbg_join_flip_delay_ms; echo $MK > /dev/kmsg; nohup bash $PWD/$OUT/window_loop.sh > /tmp/bmbtjw_loop.txt 2>&1 &" > /dev/null

bmt=$(rs $((180 + DELAY / 1000)) "$B" "mount -t mxfs $DEV $MNT; echo B_JOIN_MOUNT_RC=\$?")
echo "  JOIN $bmt"
sleep 3
rs 30 "$A" "echo 0 > /sys/module/mxfs/parameters/dbg_join_flip_delay_ms; for i in \$(seq 1 20); do grep -q WINDOW_LOOP /tmp/bmbtjw_loop.txt && break; sleep 1; done; cat /tmp/bmbtjw_loop.txt; dmesg | sed -n '/$MK/,\$p'" > "$OUT/A_window.txt" 2>/dev/null
grep -a 'WINDOW_LOOP\|P-JOIN-FLIP-DELAY\|P-JOIN-BMBT-CENSUS\|P-JOIN-BMBT-ORPHAN\|P-JOIN-FREEZE\|P-JOIN-THAW' "$OUT/A_window.txt" | cut -c1-230 | head -14
rs 30 "$A" "rm -f $F" > /dev/null

census=$(grep -a 'P-JOIN-BMBT-CENSUS' "$OUT/A_window.txt" | tail -1)
inw=$(grep -ao 'in_window=[0-9]*' "$OUT/A_window.txt" | tail -1 | cut -d= -f2)
orph=$(printf '%s' "$census" | grep -ao 'orphans=[0-9]*' | cut -d= -f2)
if [ -z "$census" ]; then echo "RESULT: VACUOUS label=$LABEL — no join census on $A (did the freeze-ordered join run?) evidence=$OUT"; exit 1; fi
if [ "${orph:-0}" -gt 0 ]; then echo "RESULT: REPRODUCED label=$LABEL orphans=$orph in_window=${inw:-0} evidence=$OUT"; exit 1; fi
if [ "${inw:-0}" = 0 ]; then echo "RESULT: VACUOUS label=$LABEL — the read+reclaim loop never ran inside the window evidence=$OUT"; exit 1; fi
cached=$(printf '%s' "$census" | grep -ao 'bmbt_cached=[0-9]*' | cut -d= -f2)
if [ "$MODE" = 2 ]; then
    [ "${cached:-0}" -gt 0 ] && { echo "RESULT: CONTROL-OK label=$LABEL bmbt_cached=$cached orphans=0 — the census sees blocks read in the window evidence=$OUT"; exit 0; }
    echo "RESULT: CONTROL-FAIL label=$LABEL bmbt_cached=0 — a reload inside the window left no cached bmbt block for the census to see evidence=$OUT"; exit 1
fi
echo "RESULT: CLEAN label=$LABEL in_window=$inw orphans=0 evidence=$OUT"; exit 0
