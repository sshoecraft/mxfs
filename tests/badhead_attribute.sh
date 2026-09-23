#!/bin/bash
# badhead_attribute.sh — attribute every peer-reported
#   P86-AGI-UNLINKED-BADHEAD (a bucket head that reads LINKED on the medium,
#   NOT in the auditing node's cache, "we did not create it")
# to the node that OWNS that bucket, and pull that owner's own history for the
# agino.  Per-slot buckets: xfs_iunlink_pick_bucket() returns
# m_mxfs_node_slot % 64, so bucket == owner's disklock/journal slot.
#
# sess396 (D-AGI-UNLINKED-CROSSNODE-RECOVERY-SHUTDOWN residual): on the
# 0.23.4 fossil-injection treatment laps 7 of 32 nodes reported one BADHEAD
# each, all in OTHER nodes' buckets, 5 of them inside the 8 s window in which
# test31's AIL was frozen (D-NOINO-RELFENCE-AIL-FREEZE-474).  A node whose
# inode items cannot flush publishes every unlinked head it inserts as a
# SPLIT (AGI head durable, dinode nlink=0 not) — this script is how that
# attribution gets measured instead of guessed.
#
# Usage: tests/badhead_attribute.sh [nodes=32] [max_lines_per_owner=24]
# Output: one block per BADHEAD: the report line, the owner node, and the
# owner's dmesg lines naming that agino/ino (P82-ADD/REM, P86-PUBLISH, P87,
# P88, P119, P-AILMIN, P-IUNL-*), bounded.  Evidence only; no verdicts.
#
# the unkillable-wedge rule: every remote call is `timeout`-bounded; no pgrep -f; per-node rc.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO"
N="${1:-32}"
MAXL="${2:-24}"
SSH=tools/mxfs_sshpass.sh
D=$(mktemp -d)

# 1. fleet sweep: slot + BADHEAD lines, per node, parallel, bounded.
for i in $(seq 1 "$N"); do
    (
        rc=0
        timeout 45 "$SSH" "test$i" \
            "echo SLOT=\$(dmesg | grep -oE 'claimed slot [0-9]+' | tail -1 | awk '{print \$3}'); dmesg -T | grep -aE 'P86-AGI-UNLINKED-BADHEAD' | cut -c1-400" \
            > "$D/n$i.raw" 2>&1 || rc=$?
        echo "$rc" > "$D/n$i.rc"
        grep -avE 'authorized|Permanently added|^Warning' "$D/n$i.raw" > "$D/n$i.out"
    ) &
done
wait

declare -A SLOT2NODE
for i in $(seq 1 "$N"); do
    s=$(grep -a '^SLOT=' "$D/n$i.out" | head -1 | cut -d= -f2)
    [ -n "$s" ] && SLOT2NODE[$s]="test$i"
    echo "test$i rc=$(cat "$D/n$i.rc") slot=${s:-?} badheads=$(grep -ac 'P86-AGI-UNLINKED-BADHEAD' "$D/n$i.out")"
done
echo "--- slot->node: $(for k in $(printf '%s\n' "${!SLOT2NODE[@]}" | sort -n); do printf '%s=%s ' "$k" "${SLOT2NODE[$k]}"; done)"

# 2. per BADHEAD: owner pull.
total=0
for i in $(seq 1 "$N"); do
    grep -a 'P86-AGI-UNLINKED-BADHEAD' "$D/n$i.out" | while read -r line; do
        total=$((total+1))
        ag=$(grep -oE ' ag=[0-9]+' <<<"$line" | head -1 | cut -d= -f2)
        bucket=$(grep -oE 'bucket=[0-9]+' <<<"$line" | head -1 | cut -d= -f2)
        agino=$(grep -oE 'agino=0x[0-9a-f]+' <<<"$line" | head -1 | cut -d= -f2)
        ino=$(grep -oE ' ino=[0-9]+' <<<"$line" | head -1 | cut -d= -f2)
        owner="${SLOT2NODE[$bucket]:-UNKNOWN}"
        echo
        echo "=== BADHEAD reported by test$i: ag=$ag bucket=$bucket agino=$agino ino=$ino owner=$owner"
        echo "    $line"
        [ "$owner" = "UNKNOWN" ] && continue
        timeout 60 "$SSH" "$owner" \
            "dmesg -T | grep -aE \"(agino=$agino([^0-9a-f]|\$).*(agno=$ag|ag=$ag|bucket=$bucket))|((agno=$ag|ag=$ag|bucket=$bucket).*agino=$agino([^0-9a-f]|\$))|ino=$ino([^0-9]|\$)|tgt_ino=$ino([^0-9]|\$)\" | grep -aE 'P82-|P86-|P87-|P88-|P119|P-AILMIN|P-IUNL|P84-|P53-|P9-NLEDGE|P129-FLUSHING|P-NOINO' | head -$MAXL | cut -c1-330" 2>/dev/null \
            | grep -avE 'authorized|Permanently added|^Warning' | sed 's/^/    /'
    done
done
echo
echo "evidence raw: $D"
