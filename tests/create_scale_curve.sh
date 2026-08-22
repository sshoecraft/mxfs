#!/bin/bash
# create_scale_curve.sh [files_per_node] [dlm_label]
#
# WHY THIS EXISTS (ccloop c7ee71c6 sess24)
# ----------------------------------------
# tests/shared_dir_pace.sh established, on the live 32-node mount:
#
#   arm                              p50    mean    p95   node wall
#   native local fs                   2ms   2.6ms    6ms      26ms
#   A  mxfs 1 node, fresh dir         5ms   5.6ms   12ms      51ms
#   C  32 nodes, ONE shared dir      11ms   255ms 2400ms    2187ms
#   D  32 nodes, PRIVATE dir each     6ms   118ms  967ms    1370ms
#
# Arm D is the important one: with NO shared directory and no shared dirent
# block, per-create cost still degrades 20x under 32-way load.  So the dominant
# O(N) term in D-DIR-REUSE-COHERENCY-32-FLAKY / D-CRASH-CONSISTENCY-32-BUDGET is
# NOT dirent/leaf serialisation -- it is something global to the mount (AG-DLM
# inode allocation, log/journal, or CAW transport bandwidth).
#
# This harness varies ONLY THE NUMBER OF PARTICIPANTS on the already-prepped
# cluster (no re-prep, no marker change, no run.sh flock) and reports the
# per-create cost curve for both shapes.  A curve that is flat in N exonerates
# the transport; a curve that grows ~linearly in N localises the serialising
# resource, and the SHARED-vs-PRIVATE delta separates dirent contention from it.
#
# Every arm writes the same TOTAL number of files (participants * F is NOT held
# constant -- per-node F is, which is what the criterion does), and per-create
# latency is reported, so the comparison is per-operation cost, not wall.
set -u
REPO=/src/mxfs
SSH="$REPO/tools/mxfs_sshpass.sh"
F="${1:-8}"
LBL="${2:-caw}"
MNT=/mnt/shared
STAMP=$(date -u +%H%M%S)
OUT=$(mktemp -d)
LADDER="${LADDER:-1 2 4 8 16 32}"

W=$(cat <<'EOS'
set -u
D="$1"; F="$2"; TAG="$3"; R="$4"
# sess380: the caller pre-creates BOTH shapes' directories from one node, so
# this must NOT mkdir -- doing so put a 32-way EX acquire of the shared parent
# inside the measured window and destroyed the private arm as a control.
[ -d "$D" ] || { echo "MISSING_DIR $D"; exit 1; }
line="CSC $TAG r$R"$'\n'
s="$line"; while [ "${#s}" -lt 4096 ]; do s="$s$s"; done
pat="${s:0:4096}"
prev=$(date +%s%N); start=$prev
for i in $(seq 1 "$F"); do
    printf '%s' "$pat" > "$D/n${R}_${TAG}_$i"
    now=$(date +%s%N)
    echo "OP $i $(( (now - prev) / 1000000 ))"
    prev=$now
done
echo "WALL $(( ($(date +%s%N) - start) / 1000000 ))"
EOS
)

# arm <participants> <shape:shared|private> -> one result line
arm() {
    local P="$1" shape="$2" i dirbase d
    local lab="${shape}_P${P}"
    local od="$OUT/$lab"; mkdir -p "$od"
    dirbase="$MNT/.csc_${STAMP}_${lab}"
    # Pre-create the directories from rank 1 so no mkdir is part of the measured
    # window (otherwise P=1 pays a mkdir the others do not).
    #
    # sess380 CORRECTION — THE `private` ARM WAS NOT AN UNCONTENDED CONTROL.
    # Only the shared arm used to be pre-created, so in the private arm every
    # one of the P nodes ran `mkdir -p $dirbase/r$i` INSIDE the measured window,
    # which takes the SAME parent directory inode EX P times.  Both arms
    # therefore contended on one shared directory and the shared-vs-private
    # ratio measured nothing about contention.  That is very likely why this
    # entry's own history contains two irreconcilable private-arm numbers
    # (D-32NODE-SHARED-DIR-CREATE-PACE: "wall 33..41ms, FLAT in N" against
    # "mean 5.2..191.8ms, 37x in N", from the same harness).  Pre-create BOTH
    # shapes from one node, so the private arm shares nothing but the mount.
    "$SSH" test1 "mkdir -p '$dirbase'" >/dev/null 2>&1
    if [ "$shape" != shared ]; then
        "$SSH" test1 "for i in \$(seq 1 $P); do mkdir -p '$dirbase'/r\$i; done" \
            >/dev/null 2>&1
    fi
    for i in $(seq 1 "$P"); do
        if [ "$shape" = shared ]; then d="$dirbase"; else d="$dirbase/r$i"; fi
        ( "$SSH" "test$i" "bash -s '$d' '$F' '$lab' '$i'" <<< "$W" \
            > "$od/n$i.txt" 2>&1 ) &
    done
    wait
    python3 - "$od" "$P" "$shape" <<'PY'
import sys, os, statistics, glob
od, P, shape = sys.argv[1], int(sys.argv[2]), sys.argv[3]
ops, walls = [], []
for p in sorted(glob.glob(os.path.join(od, "n*.txt"))):
    for ln in open(p, errors='replace'):
        f = ln.split()
        if len(f) == 3 and f[0] == 'OP':   ops.append(int(f[2]))
        elif len(f) == 2 and f[0] == 'WALL': walls.append(int(f[1]))
if not ops:
    print(f"{shape:8s} P={P:3d}  NO SAMPLES"); sys.exit(0)
ops.sort(); walls.sort()
print(f"{shape:8s} P={P:3d} creates={len(ops):5d}  "
      f"mean={statistics.fmean(ops):8.1f}  p50={ops[len(ops)//2]:6d}  "
      f"p95={ops[min(len(ops)-1,int(len(ops)*.95))]:6d}  max={max(ops):6d}  "
      f"wall_p50={walls[len(walls)//2]:6d}  (ms)")
PY
}

echo "=== create_scale_curve: F=$F/node dlm=$LBL ladder=[$LADDER] stamp=$STAMP ==="
echo "--- PRIVATE dir per node (no shared dirent block) ---"
for p in $LADDER; do arm "$p" private; done
echo "--- SHARED dir, all participants (the criterion's shape) ---"
for p in $LADDER; do arm "$p" shared; done

echo "=== cleanup ==="
"$SSH" test1 "for d in /mnt/shared/.csc_${STAMP}_*; do rm -rf \"\$d\"; done" >/dev/null 2>&1
echo "=== raw samples in $OUT ==="
