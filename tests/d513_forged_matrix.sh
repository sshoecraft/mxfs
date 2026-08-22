#!/bin/bash
# d513_forged_matrix.sh — run the whole forged-record matrix and summarise.
#
# Each shape is one call to tests/d513_forged_record_checks.sh: forge an
# adversarial recovery-outcome record into an unused heartbeat slot, cycle ONE
# node's mount, and assert the mount disposition, the byte-preservation of the
# refused sector, the quarantine expectation, and that nothing shut down.  The
# other N-1 nodes stay mounted throughout, so this is safe to run against a
# live rig and needs no re-prep.
#
# Usage: tests/d513_forged_matrix.sh [slot] [target_node] [shape ...]
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SLOT="${1:-40}"
TARGET="${2:-test32}"
shift 2 2>/dev/null || true

SHAPES=("$@")
if [ "${#SHAPES[@]}" -eq 0 ]; then
    SHAPES=(desc-crc ident badcrc-oc badkind badreason agmask0 slotmismatch
            desc-slot-oc agmask-oob fswide-mask legacy valid late-valid
            late-fswide ghost ghost-fswide ghost-badkind)
fi

# RULE 0: measured 2026-08-20, every shape completes in 13-20 s (the mount
# either aborts on its first classification or admits normally).  Anything
# past 60 s for one shape is a wedge, not a slow success.
PER_SHAPE="${PER_SHAPE:-60}"

LOG=$(mktemp -d)
npass=0; nfail=0
declare -a failed=()

for s in "${SHAPES[@]}"; do
    printf '%-14s ' "$s"
    if timeout "$PER_SHAPE" "$REPO/tests/d513_forged_record_checks.sh" \
            "$s" "$SLOT" "$TARGET" > "$LOG/$s.log" 2>&1; then
        npass=$((npass + 1))
        echo "PASS   $(grep -m1 'mount rc=' "$LOG/$s.log" | sed 's/^\[[^]]*\] //')"
    else
        nfail=$((nfail + 1)); failed+=("$s")
        echo "FAIL   $(grep -m1 '^FAIL' "$LOG/$s.log")"
    fi
done

echo
echo "=== d513 forged-record matrix: $npass PASS, $nfail FAIL of ${#SHAPES[@]} ==="
if [ "$nfail" -gt 0 ]; then
    echo "failing shapes: ${failed[*]}"
    for s in "${failed[@]}"; do
        echo "--- $s ---"
        grep -E "^FAIL|P241-RECOV|P240-QUAR|mount rc=|foreign replay slot=" "$LOG/$s.log" | tail -12
    done
fi
echo "logs kept in $LOG"
[ "$nfail" -eq 0 ]
