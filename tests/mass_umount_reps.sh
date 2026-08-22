#!/bin/bash
# mass_umount_reps.sh — repeat the sess379 mass-unmount storm N times and print
# one line per rep, so a change can be judged against the DISTRIBUTION rather
# than a single sample.
#
# Why this exists: the storm is highly variable run to run (measured 0.15.3:
# 27/28 nodes over budget in one rep, 1/28 in the very next), so a single run
# proves nothing about a fix.  Between reps it REMOUNTS rather than re-prepping,
# which is both faster and necessary — a re-prep re-mkfs's and changes the CAW
# slot mapping, so the hot LBA moves and cross-rep evidence stops lining up.
#
# Usage: tests/mass_umount_reps.sh [N] [DEPART_N] [REPS] [BUDGET_S]
# Leaves the departing nodes UNMOUNTED after the last rep.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"
N="${1:-32}"; DEP="${2:-28}"; REPS="${3:-3}"; BUDGET_S="${4:-5}"
MNT=/mnt/shared
DEV="${MXFS_DEV_MOUNT:-/dev/mapper/mpatha}"

echo "=== mass_umount_reps: N=$N depart=$DEP reps=$REPS budget=${BUDGET_S}s ==="
for r in $(seq 1 "$REPS"); do
    # (Re)mount every departing node.  Idempotent: already-mounted is fine.
    for i in $(seq 1 "$DEP"); do
        "$SSH" "test$i" "mountpoint -q $MNT || mount -t mxfs $DEV $MNT" >/dev/null 2>&1 &
    done
    wait
    up=0
    for i in $(seq 1 "$DEP"); do
        m=$("$SSH" "test$i" "mountpoint -q $MNT && echo Y" 2>/dev/null | tr -d ' \r\n')
        [ "$m" = "Y" ] && up=$((up+1))
    done
    if [ "$up" -ne "$DEP" ]; then
        echo "rep $r: ABORT — only $up/$DEP mounted"
        exit 2
    fi
    sleep 5   # let membership settle before measuring

    d=$(mktemp -d)
    for i in $(seq 1 "$DEP"); do
        ( "$SSH" "test$i" "s=\$(date +%s.%N); timeout 250 umount $MNT; e=\$(date +%s.%N); echo \"WALL \$(echo \"\$e - \$s\" | bc)\"" \
            > "$d/u$i" 2>&1 ) &
    done
    wait
    : > "$d/w"
    for i in $(seq 1 "$DEP"); do
        w=$(grep -o 'WALL [0-9.]*' "$d/u$i" 2>/dev/null | awk '{print $2}')
        echo "${w:--1}" >> "$d/w"
    done
    printf 'rep %d: ' "$r"
    sort -gr "$d/w" | awk -v b="$BUDGET_S" '
        { if ($1 > b) over++; if (NR == 1) mx = $1; s += $1 }
        END { printf "max=%7.2fs mean=%6.2fs over_budget=%d/%d\n", mx, s/NR, over+0, NR }'
    rm -rf "$d"
done
