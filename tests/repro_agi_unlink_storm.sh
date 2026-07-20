#!/bin/bash
# repro_agi_unlink_storm.sh — concentrated reproducer for the AGI unlinked-list
# INSERT stale-head shutdown (xfs_remove -> xfs_iunlink_insert_inode -> reload
# returns ENOENT because the bucket head names a now-free inode -> dirty trans
# cancel -> forced FS shutdown, seen as "xfs_trans_cancel at line 1060").
#
# Mechanism (sess53 run14d): under a 16-node concurrent create+delete storm in
# shared parent dirs, the AGI unlinked-list buckets see cross-node insert/remove
# of reused inodes; a node's cached AGI bucket head goes stale and names an
# inode a peer has already freed.  The rmdir path (xfs_droplink -> xfs_iunlink)
# then chains onto that free inode and shuts the FS down.
#
# Usage: tests/repro_agi_unlink_storm.sh [N] [ROUNDS]
#   N       node count (default 16; test1..testN)
#   ROUNDS  create+delete rounds (default 4)
# Requires the cluster already mounted (run tests/reset4.sh N first).
set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
N="${1:-16}"
ROUNDS="${2:-4}"
PASS="${MXFS_PASS:-/tmp/.mxfs_pass}"
SSH="${SCRIPT_DIR}/../tools/mxfs_sshpass.sh"
MNT="/mnt/shared"
ROOT="$MNT/.mxfs_test/agi_storm"
DIRS_PER_NODE="${DIRS_PER_NODE:-40}"
FILES_PER_DIR="${FILES_PER_DIR:-8}"

run() { timeout 60 "$SSH" "test$1" "$PASS" "$2" 2>&1 | \
        grep -vE "Permanently added|Unauthorized access|disconnect immediately|^$"; }

echo "=== repro_agi_unlink_storm N=$N ROUNDS=$ROUNDS dpn=$DIRS_PER_NODE fpd=$FILES_PER_DIR $(date -u +%T) ==="
# Clean slate + shared parent dirs.  Use a handful of shared parents so multiple
# nodes' inodes land in the same AGs / AGI buckets (cross-node contention).
run 1 "rm -rf $ROOT; mkdir -p $ROOT/p0 $ROOT/p1 $ROOT/p2 $ROOT/p3; sync"

for r in $(seq 1 "$ROUNDS"); do
    echo "--- round $r: create $(date -u +%T) ---"
    # Each node creates DIRS_PER_NODE dirs (with files) spread across the 4
    # shared parents, then deletes them.  All N nodes run concurrently.
    for h in $(seq 1 "$N"); do
        run "$h" "
          for d in \$(seq 1 $DIRS_PER_NODE); do
            p=\$(( (d + $h) % 4 ))
            dir=$ROOT/p\$p/n${h}_r${r}_d\${d}
            mkdir -p \$dir 2>/dev/null || true
            for f in \$(seq 1 $FILES_PER_DIR); do echo x > \$dir/f\$f 2>/dev/null; done
          done" &
    done
    wait
    echo "--- round $r: delete $(date -u +%T) ---"
    for h in $(seq 1 "$N"); do
        run "$h" "
          for d in \$(seq 1 $DIRS_PER_NODE); do
            p=\$(( (d + $h) % 4 ))
            rm -rf $ROOT/p\$p/n${h}_r${r}_d\${d} 2>/dev/null || true
          done" &
    done
    wait
    # Health check: any node shut down this round?
    DOWN=0
    for h in $(seq 1 "$N"); do
        S=$(run "$h" "ls $MNT >/dev/null 2>&1 && echo OK || echo DOWN")
        if echo "$S" | grep -q DOWN; then echo "!!! test$h SHUTDOWN after round $r"; DOWN=1; fi
    done
    [ "$DOWN" = 1 ] && { echo "REPRO_HIT round=$r"; break; }
done

echo "=== scan dmesg for P-INS-STALE / shutdown across $N nodes ==="
for h in $(seq 1 "$N"); do
    R=$(run "$h" "dmesg 2>/dev/null | grep -iE 'P-INS-STALE|xfs_trans_cancel at line 1060|Shutting down filesystem|P71-INSTR' | tail -6")
    [ -n "$R" ] && { echo "--- test$h ---"; echo "$R"; }
done
echo "=== done $(date -u +%T) ==="
