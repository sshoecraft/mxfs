#!/bin/bash
# drc_orphan_watch.sh — capture the dir_reuse@32/caw orphaned-EX-bit forensic
# (P-ORPH-FORENSIC + the P12-DLMTR transition ring) from every test node the
# moment it appears, before the FS-shutdown cascade floods/rotates the kernel
# ring.  Polls each node's dmesg on a short interval and APPENDS any matching
# lines to a per-node file (sort -u at analysis time dedups).  ccloop a864 sess3.
#
# Usage: tests/drc_orphan_watch.sh <N> <outdir> [interval_s]
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
N="${1:-32}"
OUT="${2:-$REPO/tests/tcp/drc_cap/orph}"
IV="${3:-20}"
SSH="$REPO/tools/mxfs_sshpass.sh"
PASS="${MXFS_PASS:-/tmp/.mxfs_pass}"
PAT='P-ORPH-FORENSIC|P72-SWALLOW-DEAD|P72-ORPHAN-FORCEREL|P-ACQ-STUCK|P135-HELD-MISS|P135-ORPHAN-RELEASE|P135-GRANTWIN|P70-BP|P6ZC-REL|P6G-REL-STALE|CAW-FORCE-REL|P138-BAST'
mkdir -p "$OUT"
echo "drc_orphan_watch: N=$N out=$OUT iv=${IV}s pat=$PAT"
while true; do
    for i in $(seq 1 "$N"); do
        timeout 8 "$SSH" "test$i" "$PASS" \
            "dmesg 2>/dev/null | grep -aE '$PAT'" 2>/dev/null \
            >> "$OUT/node${i}.txt"
    done
    # compact each file in place (dedup) so it doesn't grow unbounded
    for f in "$OUT"/node*.txt; do
        [ -s "$f" ] || continue
        sort -u "$f" -o "$f" 2>/dev/null
    done
    sleep "$IV"
done
