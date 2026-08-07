#!/bin/bash
# typeflip_ab.sh — paired A/B for D-DIRENT-INODE-TYPE-MISMATCH on ONE build.
#
# THE DEFECT, ROOTED (ccloop c7ee71c6 sess27)
#   RELOAD-TYPEFLIP-STALE-SKIP kept the in-core inode whenever
#   disk_gen <= incore_gen.  XFS generations are RANDOM, so on a genuine
#   inode-number reuse that comparison is a coin flip; when it lost, the node
#   kept a DEAD incarnation and its release drain PUBLISHED that corpse over
#   the peer's live inode.  Captured end to end for ino 10485888 / node15.txt.
#   mxfs.typeflip_skip_same_incarn: 1 = require the same incarnation (fix),
#   0 = legacy <= (negative control).
#
# THE REPRODUCER (found sess27, 3 for 3 before the fix)
#   prep -> dirent_durability -> cache_coherency.  dirent_durability's 30-round
#   mkdir/rmdir storm is the AGING pass that drives cross-node inode-number
#   reuse; cache_coherency then creates regular files that land on the reused
#   numbers.  Running cache_coherency FIRST (manifest order, on a fresh mount)
#   does NOT reproduce it -- which is why the board showed it green.
#
# Each arm starts from a fresh mkfs: the corruption is DURABLE, so a arm that
# inherits a corrupt name from the previous arm measures nothing.
#
# USAGE  tests/typeflip_ab.sh [iters] [nodecount]
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO"

ITERS="${1:-1}"
N="${2:-32}"

set_knob() {   # <value> — set on every node, verify, abort if any node differs
    local v="$1" i n d bad=0
    d=$(mktemp -d)
    for i in $(seq 1 "$N"); do
        n="test$i"
        timeout "$ARM_SSH_BUDGET" tools/mxfs_sshpass.sh "$n" \
            "echo $v > /sys/module/mxfs/parameters/typeflip_skip_same_incarn; \
             cat /sys/module/mxfs/parameters/typeflip_skip_same_incarn" \
            2>/dev/null | tr -dc '0-9\n' | grep -qx "$v" \
            && echo ok > "$d/$n" || echo bad > "$d/$n" &
        while [ "$(jobs -rp | wc -l)" -ge 10 ]; do wait -n; done
    done
    wait
    for i in $(seq 1 "$N"); do
        grep -qx ok "$d/test$i" 2>/dev/null || { echo "  !! test$i did not take knob=$v"; bad=1; }
    done
    [ "$bad" = 0 ] || { echo "ABORT: knob not uniform across the cluster — an A/B with mixed arms measures nothing"; return 1; }
    echo "  knob typeflip_skip_same_incarn=$v verified on all $N nodes"
}

census() {     # <label> — windowed per-node probe counts, cluster totals only
    #
    # ONE ssh per node that counts every probe, not one per (probe,node): the
    # naive nesting is 6*32 = 192 sessions per arm at ~1s each, which costs more
    # wall than the workload it is measuring.
    local label="$1" i n d
    d=$(mktemp -d)
    echo "  --- probe census ($label), scoped to each node's LAST window ---"
    for i in $(seq 1 "$N"); do
        n="test$i"
        timeout "$ARM_SSH_BUDGET" tools/mxfs_sshpass.sh "$n" '
            L=$(dmesg | grep -n MXFS_DIRENT_WINDOW | tail -1 | cut -d: -f1)
            if [ -n "$L" ]; then dmesg | tail -n +$((L+1)) > /tmp/tfw.txt
            else dmesg > /tmp/tfw.txt; fi
            for p in P208-TYPEFLIP-REUSE RELOAD-TYPEFLIP-STALE-SKIP \
                     RELOAD-TYPEFLIP-DIRENT-OK P95B-TYPEFLIP-WAIT \
                     P201-TYPEFLIP-UNRESOLVED-FAIL P207-COHERENT-TRUTH; do
                echo "$p $(grep -c "$p" /tmp/tfw.txt)"
            done' 2>/dev/null | grep -E '^P[0-9]|^RELOAD' > "$d/$n" &
        while [ "$(jobs -rp | wc -l)" -ge 8 ]; do wait -n; done
    done
    wait
    awk '{s[$1]+=$2} END{for (p in s) printf "      %-32s %s\n", p, s[p]}' \
        "$d"/* 2>/dev/null | sort
}

# RULE 0: every timeout below is the criterion's own recorded budget from
# tests/suite/manifest -- not a round number and not "whatever fits the tool
# cap".  A blanket outer timeout was the original sin here: it hid the fact that
# prep(300) + dd(240) + cc(60) + ti(60) + ssh(100) = 760s exceeds the 600s
# foreground cap, so the arm is SPLIT into prep and measure.  Measured walls
# this session: prep 118-133, dd 114-123, cc 28-48, ti 3-8, census 10-15.
# run.sh ITSELF enforces each criterion's manifest budget and flips PASS->FAIL on
# overrun -- that is the RULE 0 assertion.  The timeouts here are OUTER
# backstops on the whole run.sh invocation, so each must be the criterion budget
# PLUS harness overhead (flock, prep-marker check, coord-broker hygiene, 32-node
# dispatch and aggregation).  Setting the outer value EQUAL to the budget killed
# ARM B's cache_coherency mid-flight and silently dropped its result line.
# Measured overhead this session: ~10-25s per invocation.
ARM_OVERHEAD=40
ARM_PREP_BUDGET=$((300 + ARM_OVERHEAD))
ARM_DD_BUDGET=$((240 + ARM_OVERHEAD))
ARM_CC_BUDGET=$((60 + ARM_OVERHEAD))
ARM_TI_BUDGET=$((60 + ARM_OVERHEAD))
ARM_SSH_BUDGET=60

arm_prep() {   # <knobval>
    local v="$1"
    MXFS_FORCE_PREP=1 timeout "$ARM_PREP_BUDGET" ./run.sh "$N" caw prep_cluster 2>&1 | tail -1
    set_knob "$v"
}

arm_measure() {  # <label>
    local label="$1"
    timeout "$ARM_DD_BUDGET" ./run.sh "$N" caw dirent_durability 2>&1 | grep -E "  (PASS|FAIL|BLOCK)"
    timeout "$ARM_CC_BUDGET" ./run.sh "$N" caw cache_coherency 2>&1 | grep -E "  (PASS|FAIL|BLOCK)"
    timeout "$ARM_TI_BUDGET" ./run.sh "$N" caw dirent_type_integrity 2>&1 | grep -E "  (PASS|FAIL|BLOCK)"
    census "$label"
}

run_arm() {    # <knobval> <label>
    local v="$1" label="$2"
    echo "=== ARM $label (typeflip_skip_same_incarn=$v) ==="
    arm_prep "$v" || return 1
    arm_measure "$label"
}

# One full iteration is ~11 min of wall, past the 10-min foreground cap, so the
# arms are individually invocable:  tests/typeflip_ab.sh arm <0|1> [N]
case "${1:-}" in
arm|arm-prep|arm-measure)
    V="${2:?usage: typeflip_ab.sh arm|arm-prep|arm-measure <0|1> [nodecount]}"
    N="${3:-32}"
    case "$V" in 0) L="A-control-legacy-<=" ;; 1) L="B-fix-same-incarnation" ;;
        *) echo "arm must be 0 or 1"; exit 2 ;; esac
    echo "=== ARM $L (typeflip_skip_same_incarn=$V) step=$1 ==="
    case "$1" in
        arm-prep)    arm_prep "$V" ;;
        arm-measure) arm_measure "$L" ;;
        arm)         run_arm "$V" "$L" ;;
    esac
    exit $?
    ;;
esac

for k in $(seq 1 "$ITERS"); do
    echo "########## iteration $k of $ITERS ##########"
    run_arm 0 "A-control-legacy-<=" || exit 1
    run_arm 1 "B-fix-same-incarnation" || exit 1
done
