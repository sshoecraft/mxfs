#!/bin/bash
# rsync_paired — each node rsyncs a generated source tree into the shared FS
# (its own subdir) concurrently, then verifies the copy is complete + correct
# (file count + content checksums) and finished within the time budget.
#
# This is the multi-node metadata-heavy workload (many small files = the rsync
# create/stat/rename pattern).  PASS iff every node's tree transfers with zero
# rsync errors, the destination matches the source exactly, and it completes
# inside the budget (RULE 0: a clustered FS that can't keep up is a FAIL).
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/lib.sh"

R="$RANK"; T="$NODES"
D="$MNT/.rsync_paired/node${R}"
SRC="/tmp/rsync_paired_src.$$"
mkdir -p "$D" "$SRC" 2>/dev/null
trap 'rm -rf "$SRC" 2>/dev/null' EXIT

NFILES="${RSYNC_NFILES:-400}"
WINDOW="${RSYNC_WINDOW:-90}"

command -v rsync >/dev/null 2>&1 || { echo "RESULT: FAIL | test=rsync_paired | nodes=$T | measured=setup | reason=rsync not installed"; exit 1; }

# Build a deterministic source tree (nested dirs + small files w/ known content).
for d in $(seq 1 10); do
    mkdir -p "$SRC/d$d"
    for f in $(seq 1 $((NFILES / 10))); do
        printf 'node%s-d%s-f%s-payload-%s\n' "$R" "$d" "$f" "$(seq 1 20)" > "$SRC/d$d/file$f"
    done
done
src_count=$(find "$SRC" -type f | wc -l | tr -d ' ')
src_sum=$(find "$SRC" -type f -exec md5sum {} \; | awk '{print $1}' | sort | md5sum | awk '{print $1}')

ck "rsync barrier ready" coord_barrier "rs_ready"

t0=$(date +%s.%N)
rsync -a --no-compress "$SRC/" "$D/" 2>/dev/null
rc=$?
sync
t1=$(date +%s.%N)
elapsed=$(awk "BEGIN{e=$t1-$t0; print (e>0)?e:0.001}")

dst_count=$(find "$D" -type f | wc -l | tr -d ' ')
dst_sum=$(find "$D" -type f -exec md5sum {} \; | awk '{print $1}' | sort | md5sum | awk '{print $1}')

echo "RSYNC: node$R files=$dst_count/$src_count elapsed=${elapsed}s rc=$rc" >&2
ckeq "rsync node${R} rc"          0 "$rc"
ckeq "rsync node${R} file count"  "$src_count" "$dst_count"
ckeq "rsync node${R} content sum" "$src_sum"   "$dst_sum"
ck   "rsync node${R} within window" awk "BEGIN{exit !($elapsed <= $WINDOW)}"

ck "rsync barrier done" coord_barrier "rs_done"
coord_done "$([ "$FAIL_N" -eq 0 ] && echo PASS || echo FAIL)"
finish
