#!/bin/bash
# inode_reuse_typeflip.sh — targeted reproducer for D-DIRENT-INODE-TYPE-MISMATCH.
#
# HYPOTHESIS UNDER TEST (ccloop c7ee71c6 sess23)
#   The captured corruption is a REGULAR-FILE dirent resolving to an inode
#   whose on-disk core reads mode=040755 size=6 nlink=2 — i.e. a *pristine
#   empty MXFS directory*.  That is not "a dirent gone bad": it is the shape of
#   a DIRECTORY INODE THAT WAS FREED AND REUSED, whose stale directory core
#   reached the platter AFTER the new regular-file core was written there.
#   Cross-node inode reuse plus MXFS's unaccounted in-flight write ordering
#   across a grant handoff (open item 4 / D-RELEASE-BARRIER-OPEN) is exactly
#   the mechanism that would produce it.
#
# WHAT THIS DRIVES
#   Half the nodes CHURN directories inside one shared parent (mkdir then
#   rmdir, continuously) so DIR inode numbers are returned to the free pool at
#   a high rate.  The other half CREATE REGULAR FILES in that same parent, so
#   their allocations draw from precisely those just-freed DIR inodes.  Both
#   groups run concurrently in the same AGs for the whole run.
#
# THE ORACLE
#   Every regular file created by a writer node must, on EVERY node, be a
#   REGULAR FILE with its exact content.  A file that stats as a directory (or
#   as anything but a regular file) is the defect.  For any such file the
#   harness records stat output on every node plus `find -inum` so the question
#   "is some other name also bound to this inode?" is answered in the capture
#   rather than guessed at later:
#     - another name owns it  -> genuine inode reuse with a surviving dirent
#     - no other name owns it -> a directory core was written to an inode slot
#                                that no directory was ever created at
#
# USAGE
#   tests/inode_reuse_typeflip.sh <rounds> [nodes] [slot_seconds] [per_node]
#
# EXIT: 0 = every file correct on every node.  1 = defect reproduced.
#       2 = INFRASTRUCTURE failure (a node did not complete its work).
#
# RULE 0 budget: a round is per_node creates + per_node dir churn cycles in one
# directory; native XFS does that in milliseconds.  Total wall =
# 10s setup + rounds*slot + ~25s verify.
set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd -- "$SCRIPT_DIR/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"

ROUNDS="${1:?usage: inode_reuse_typeflip.sh <rounds> [nodes] [slot_seconds] [per_node]}"
N="${2:-32}"
SLOT="${3:-2}"
M="${4:-8}"
MNT="${MXFS_MNT:-/mnt/shared}"
BASE="$MNT/.irtf_$(date -u +%H%M%S)"

STAMP=$(date -u +%Y%m%d_%H%M%S)
OUT="$REPO/tests/logs/irtf_$STAMP"
mkdir -p "$OUT"

timeout 120 "$SSH" test1 "mkdir -p '$BASE'; sync" > "$OUT/setup.log" 2>&1 \
    || { echo "BASE CREATE FAILED — see $OUT/setup.log"; exit 2; }

for r in $(seq 1 "$N"); do
    ( timeout 30 "$SSH" "test$r" "dmesg -C" >/dev/null 2>&1 ) &
done
wait

START=$(( $(date +%s) + 10 ))
{
    echo "start=$START"; echo "slot=$SLOT"; echo "rounds=$ROUNDS"
    echo "nodes=$N"; echo "per_node=$M"; echo "base=$BASE"
} > "$OUT/meta.txt"

echo "=== inode_reuse_typeflip: rounds=$ROUNDS nodes=$N slot=${SLOT}s per_node=$M out=$OUT ==="
echo "    base=$BASE"

# Odd ranks WRITE regular files; even ranks CHURN directories.  Rank 1 always
# writes so there is at least one writer at N=1.
body() {
    cat <<EOF
set -u
R=\$1
ROLE=\$(( R % 2 ))            # 1 = writer, 0 = churner
mkdir -p "$BASE" 2>/dev/null || true

for K in \$(seq 1 $ROUNDS); do
    T=\$(( $START + (K - 1) * $SLOT ))
    now=\$(date +%s)
    [ "\$now" -lt "\$T" ] && sleep \$(( T - now ))
    d="$BASE/r\$K"
    mkdir -p "\$d" 2>/dev/null || true
    if [ "\$ROLE" = "1" ]; then
        for m in \$(seq 1 $M); do
            printf 'content_%s_%s_%s\n' "\$R" "\$K" "\$m" > "\$d/f_\${R}_\${m}" \\
                || echo "WRITE-RC K=\$K m=\$m rc=\$?"
        done
    else
        # churn: allocate and immediately free directory inodes in the same
        # parent the writers are allocating from.
        for m in \$(seq 1 $M); do
            mkdir "\$d/c_\${R}_\${m}" 2>/dev/null && rmdir "\$d/c_\${R}_\${m}" 2>/dev/null
        done
        for m in \$(seq 1 $M); do
            mkdir "\$d/c2_\${R}_\${m}" 2>/dev/null && rmdir "\$d/c2_\${R}_\${m}" 2>/dev/null
        done
    fi
done
sync
echo "NODE \$R DONE role=\$ROLE"
EOF
}

for r in $(seq 1 "$N"); do
    ( timeout $(( ROUNDS * SLOT + 180 )) "$SSH" "test$r" "bash -s $r" <<< "$(body)" \
        > "$OUT/node$r.log" 2>&1 ) &
done
wait

infra=0
for r in $(seq 1 "$N"); do
    grep -q "NODE $r DONE" "$OUT/node$r.log" || { echo "INFRA-FAIL: test$r did not finish"; infra=1; }
done

echo "=== settling ==="
for r in $(seq 1 "$N"); do ( timeout 60 "$SSH" "test$r" "sync" >/dev/null 2>&1 ) & done
wait
sleep 5

# ---- oracle: every writer file must be a REGULAR FILE with exact content on
# ---- EVERY node.
census() {
    cat <<EOF
set -u
R=\$1
bad=0
for K in \$(seq 1 $ROUNDS); do
    d="$BASE/r\$K"
    [ -d "\$d" ] || continue
    for w in \$(seq 1 $N); do
        [ \$(( w % 2 )) -eq 1 ] || continue
        for m in \$(seq 1 $M); do
            f="\$d/f_\${w}_\${m}"
            [ -e "\$f" ] || { echo "MISSING \$f"; bad=1; continue; }
            t=\$(stat -c '%F' "\$f" 2>/dev/null)
            if [ "\$t" != "regular file" ]; then
                ino=\$(stat -c '%i' "\$f" 2>/dev/null)
                echo "TYPEBAD file=\$f type=\$t \$(stat -c 'ino=%i mode=%f nlink=%h size=%s' "\$f" 2>/dev/null)"
                echo "TYPEBAD-ALIAS ino=\$ino names=[\$(find $MNT -inum \$ino 2>/dev/null | tr '\n' ' ')]"
                bad=1
                continue
            fi
            c=\$(cat "\$f" 2>/dev/null)
            exp="content_\${w}_\${K}_\${m}"
            [ "\$c" = "\$exp" ] || { echo "CONTENTBAD \$f exp=\$exp got=\$c"; bad=1; }
        done
    done
done
echo "CENSUS \$R bad=\$bad"
EOF
}

for r in $(seq 1 "$N"); do
    ( timeout 300 "$SSH" "test$r" "bash -s $r" <<< "$(census)" > "$OUT/census$r.log" 2>&1 ) &
done
wait

typebad=$(cat "$OUT"/census*.log 2>/dev/null | grep -c '^TYPEBAD ' || true)
contbad=$(cat "$OUT"/census*.log 2>/dev/null | grep -c '^CONTENTBAD ' || true)
missing=$(cat "$OUT"/census*.log 2>/dev/null | grep -c '^MISSING ' || true)

echo "=== RESULT: typebad=$typebad contentbad=$contbad missing=$missing infra=$infra ==="
if [ "$typebad" -gt 0 ]; then
    echo "--- TYPE MISMATCHES (the defect) ---"
    grep -h '^TYPEBAD' "$OUT"/census*.log | sort -u | head -40
    for r in $(seq 1 "$N"); do
        ( timeout 60 "$SSH" "test$r" "dmesg" > "$OUT/dmesg$r.log" 2>&1 ) &
    done
    wait
    echo "    dmesg harvested to $OUT"
fi
[ "$missing" -gt 0 ] && { echo "--- MISSING ---"; grep -h '^MISSING' "$OUT"/census*.log | sort -u | head -20; }
[ "$contbad" -gt 0 ] && { echo "--- CONTENT ---"; grep -h '^CONTENTBAD' "$OUT"/census*.log | sort -u | head -20; }

echo "    logs: $OUT"
[ "$infra" = "1" ] && exit 2
[ "$typebad" -gt 0 ] || [ "$contbad" -gt 0 ] || [ "$missing" -gt 0 ] && exit 1
echo "=== inode_reuse_typeflip PASS: all writer files are regular with correct content on all $N nodes ==="
exit 0
