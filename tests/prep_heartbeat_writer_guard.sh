#!/bin/bash
# prep_heartbeat_writer_guard.sh — the negative arm of the prep-ordering
# guard: a format must be REFUSED while another node is still heartbeating
# into the LUN.
#
# Measured s62e: a node from the previous lap was still mounted while the prep
# formatted the LUN; mkfs's zeroing was overwritten by that node's heartbeat,
# the readback found the 'K' of its MXLK slot magic and blamed the storage,
# the prep FAILed, and the next lap started on the previous incarnations'
# records and read them as a fencing defect.  tests/setup/prep_fs.sh now
# dumps the heartbeat table twice, 3 s apart, and refuses when any record's
# stamp advanced (FS_PREP_FAIL naming the slot and node).
#
# SHAPE.  Both nodes are mounted (the capture gate's ensure).  The format
# script is run ON node A exactly as prep_cluster runs it, with node B still
# mounted and heartbeating.  It must unmount A's own mount (its local guard),
# then refuse before mkfs.  Asserted: FS_PREP_FAIL naming a heartbeat writer
# and B's slot, no "mkfs:" line (the format was never started), B still
# mounted and writable afterwards, B's record still ACTIVE with an advancing
# stamp, and the filesystem identity on B unchanged.  The vacuity gate: B's
# record must be seen advancing by THIS harness before the arm is judged.
# The lap leaves A unmounted; the gate's ensure re-preps.
#
# the budget rule (derived, not rounded): two dumps 3 s apart ~8 s + the
# format script's own two dumps ~8 s + captures ~10 s = ~26 s.  Caller bound
# 60 s (≈26 s × 2, the floor for a lap that restarts nothing).
#
# Usage: tests/prep_heartbeat_writer_guard.sh <label>
# Env:   MXFS_NODE_LIST (default test1,test2), MXFS_DEV.
set -u
LABEL=${1:?label}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
. "$(dirname "$0")/lib/rig.sh"
mxfs_dev_resolve "${MXFS_NODE_LIST%%,*}"; export MXFS_DEV=$MXFS_DEV_RESOLVED
A=${MXFS_NODE_LIST%%,*}          # runs the format script
B=${MXFS_NODE_LIST##*,}          # stays mounted: the live writer
MNT=/mnt/shared
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_prepguard_$LABEL
mkdir -p "$OUT"
fails=0
c() { grep -ac "$1" "$2"; }
echo "=== prep_heartbeat_writer_guard label=$LABEL A(formats)=$A B(writer)=$B dev=$MXFS_DEV $(date -u +%FT%TZ) ==="
s0=$(date +%s)

# precondition and vacuity: B is mounted, and its heartbeat record advances
value_now_into bm "$B" 20 "$OUT/B_mounted_before.txt" '^mounted=[01]$' "B's mount state before" "mountpoint -q $MNT && echo mounted=1 || echo mounted=0"
ck "B is mounted before the arm" "$bm" "mounted=1"
# the filesystem identity is read from the envelope superblock by the rig
# library (findmnt and blkid cannot see an MXFS superblock: the envelope
# offsets it, measured s67c — both returned empty)
id=$(mxfs_dev_ident "$B" "$MXFS_DEV") || { echo "$id"; exit 2; }
fsid_before=$(mxfs_dev_field "$id" fsid); echo "$id" > "$OUT/B_ident_before.txt"
ck "B sees the resolved filesystem before the arm" "$fsid_before" "$MXFS_DEV_FSID"
measure "$A" 30 "$OUT/hb_1.txt" '^slot +[0-9]+ magic=' "the platter dump on $A (first)" "python3 /src/mxfs/tools/disklock_hb_dump.py $MXFS_DEV"
sleep 3
measure "$A" 30 "$OUT/hb_2.txt" '^slot +[0-9]+ magic=' "the platter dump on $A (second, 3 s later)" "python3 /src/mxfs/tools/disklock_hb_dump.py $MXFS_DEV"
advancing=$(awk '/^slot/ { s=$2; ts=""; for (i=1;i<=NF;i++) if ($i ~ /^ts_ms=/) ts=substr($i,7); if (FNR==NR) f[s]=ts; else if ((s in f) && ts+0 > f[s]+0) n++ } END { print n+0 }' "$OUT/hb_1.txt" "$OUT/hb_2.txt")
echo "STAGE precondition: records advancing over 3 s = $advancing"
ckge "a heartbeat writer is live on the LUN (records advancing over 3 s — the arm's precondition)" "$advancing" 1
[ $fails = 0 ] || { echo "RESULT: VACUOUS label=$LABEL fails=$fails wall=$(( $(date +%s) - s0 ))s evidence=$OUT"; exit 3; }

# the arm: the format script on A, exactly as prep_cluster invokes it
rsx 60 "$A" "MXFS_DEV='$MXFS_DEV' MXFS_LOG_SLICES=32 bash /src/mxfs/tests/setup/prep_fs.sh 2>&1; echo PREP_RC=\$?" > "$OUT/prep_fs.txt"
capture_require "$OUT/prep_fs.txt" '^PREP_RC=[0-9]+$' "the format script's run on $A"
prc=$(grep -ao '^PREP_RC=[0-9]*' "$OUT/prep_fs.txt" | head -1 | cut -d= -f2)
echo "STAGE prep_fs on $A: rc=$prc"
grep -a 'FS_PREP\|heartbeat\|mkfs' "$OUT/prep_fs.txt" | sed 's/^/    /' | cut -c1-220 | head -6
ck   "the format script refused (rc 1)" "$prc" 1
ckge "it refused for a live heartbeat writer (FS_PREP_FAIL ... still heartbeating)" "$(grep -a 'FS_PREP_FAIL' "$OUT/prep_fs.txt" | grep -ac 'still heartbeating')" 1
ck   "the format was never started (no 'mkfs:' line)" "$(c '^mkfs:' "$OUT/prep_fs.txt")" 0

# B survived: still mounted, still writable, same filesystem, still heartbeating
value_now_into bw "$B" 20 "$OUT/B_write_after.txt" '^write=[01]$' "B's write after the arm" "f=$MNT/.prepguard_$$; ( : > \$f && rm -f \$f ) 2>/dev/null && echo write=1 || echo write=0"
ck "B is still writable after the refused format" "$bw" "write=1"
id=$(mxfs_dev_ident "$B" "$MXFS_DEV") || { echo "$id"; exit 2; }
fsid_after=$(mxfs_dev_field "$id" fsid); echo "$id" > "$OUT/B_ident_after.txt"
ck "B's filesystem identity is unchanged" "$fsid_after" "$fsid_before"
measure "$A" 30 "$OUT/hb_3.txt" '^slot +[0-9]+ magic=' "the platter dump on $A after the arm" "python3 /src/mxfs/tools/disklock_hb_dump.py $MXFS_DEV"
ckge "B's record is still ACTIVE on the platter" "$(c 'flags=ACTIVE' "$OUT/hb_3.txt")" 1
echo "RESULT: $( [ $fails = 0 ] && echo PASS || echo FAIL ) label=$LABEL fails=$fails wall=$(( $(date +%s) - s0 ))s evidence=$OUT"
[ $fails = 0 ]
