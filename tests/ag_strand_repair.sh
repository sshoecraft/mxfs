#!/bin/bash
# ag_strand_repair.sh — EXERCISE and VERIFY the stranded-AG repair path.
#
# WHY THIS EXISTS
#   `mxfs.ag_strand_repair` (sess20) fixes a PROVEN defect: a CAW AG whose
#   holder bit survives in the on-disk slot table while this node has no
#   in-core tenure at all.  The BAST schedule gate requires pag_dlm_cached, so
#   no peer BAST can ever schedule that AG's release.  Captured consequence
#   (2026-07-28 15:01, tests/logs/wedge_ino138_20260728_1501/): AG 8 stranded
#   on test1 -> test26 waited 240 s on it while holding dir ino=138 EX ->
#   all 31 peers starved -> force-shutdown -> 21 of 32 filesystems dead.
#
#   The fix then NEVER RAN — no strand recurred after it landed.  RULE 6 will
#   not accept that: "cannot reproduce" is not a disposition, and a recovery
#   path that has never executed is not a verified fix.  So the strand is
#   created on purpose and the recovery is measured.
#
# HOW THE STRAND IS CREATED
#   `mxfs.ag_strand_inject=-1` makes the NEXT AG this node releases skip its
#   wire unlock exactly once (one-shot, self-clearing), leaving our holder bit
#   on the platter with no in-core tenure — the exact stranded state.
#
#   ARM EVERY NODE, and use the mkdir storm as the load.  Both matter, and both
#   were learned by failing:
#     * Arming only test1 produced ZERO strands across a 400-mkdir single-node
#       workload AND a full 32-node storm — test1 is never BAST'd off an AG in
#       those, so no release path runs on it at all.
#     * The injection also has to sit on ALL THREE real release paths
#       (bast_work_fn, release_work_fn, ag_meta_iodone).  Arming just one, then
#       just another, produced 0 strands twice.
#
# WHAT COUNTS AS PASS (all four, per RULE 6)
#   1. P200-STRAND-INJECT fires  — the strand was really created
#   2. P5N ... disk_held=1 repair=1 fires, and no (node, AG) that was DECLINED
#      (repair=0) goes on without a repair.  A bare repair=0 is legitimate --
#      the arm declines while a release is already in flight -- so the test is
#      "declined and never subsequently repaired on that node", not the raw
#      count.  Convicting on the raw count failed a healthy run once.
#   3. every node can still write afterwards — the AG was actually RELEASED,
#      not merely re-adopted
#   4. zero kernel faults cluster-wide — the repair did not trade a strand for
#      a crash
#
#   EXPECT ~2 repair lines per strand.  That is not a loop: measured on the
#   validation run, all 32 nodes read exactly strand=1 repair=2 on exactly one
#   AG each, and no AG ever needed a third.  A genuine re-adopt-without-release
#   loop would show that AG's count climbing for the rest of the run.
#
# USAGE
#   tests/ag_strand_repair.sh [nodes] [storm_rounds]
#     Assumes the cluster is already prepped with the build under test.
#
# RULE 0 budget: the injected strands must be repaired and released inside the
# storm that follows.  A 15-round storm is ~60 s of workload; the cap below is
# sized for that plus harvest, and a run that needs more is a wedge, not a slow
# pass.
set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd -- "$SCRIPT_DIR/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"

N="${1:-32}"
ROUNDS="${2:-15}"
STAMP=$(date -u +%Y%m%d_%H%M%S)
OUT="$REPO/tests/logs/agstrand_$STAMP"
mkdir -p "$OUT"

echo "=== ag_strand_repair: nodes=$N storm_rounds=$ROUNDS out=$OUT ==="

# Clear rings and arm every node.  One-shot per node => exactly N strands.
armfail=""
for r in $(seq 1 "$N"); do
    ( timeout 30 "$SSH" "test$r" \
        "dmesg -C; echo -1 > /sys/module/mxfs/parameters/ag_strand_inject" \
        >/dev/null 2>&1 ) &
done
wait
for r in $(seq 1 "$N"); do
    v=$(timeout 20 "$SSH" "test$r" "cat /sys/module/mxfs/parameters/ag_strand_inject" 2>/dev/null | tr -dc '0-9-')
    [ "$v" = "-1" ] || armfail="$armfail test$r"
done
if [ -n "$armfail" ]; then
    echo "=== ag_strand_repair INFRA-FAIL: could not arm on:$armfail ==="
    echo "    (build lacks mxfs.ag_strand_inject, or the node is unreachable)"
    exit 2
fi
echo "--- armed ag_strand_inject=-1 on all $N nodes ---"

# The storm is the load generator: it is the workload that actually drives
# cross-node AG contention, which is what makes any node release an AG at all.
"$SCRIPT_DIR/sf_mkdir_storm.sh" "$ROUNDS" "$N" 2 1 > "$OUT/storm.log" 2>&1
echo "--- storm complete (rc=$?) — see $OUT/storm.log ---"

for r in $(seq 1 "$N"); do
    ( timeout 40 "$SSH" "test$r" "dmesg" > "$OUT/dmesg_test$r.log" 2>&1 ) &
done
wait

# Liveness: can every node still do real filesystem work?  A repaired-but-never-
# released AG shows up here, not in the probe counts.
wok=0
for r in $(seq 1 "$N"); do
    ( timeout 40 "$SSH" "test$r" \
        "mkdir -p /mnt/shared/.agstrand_live && touch /mnt/shared/.agstrand_live/n$r && echo WRITE_OK" \
        > "$OUT/live_test$r.log" 2>&1 ) &
done
wait
dead=""
for r in $(seq 1 "$N"); do
    if grep -q WRITE_OK "$OUT/live_test$r.log" 2>/dev/null; then
        wok=$(( wok + 1 ))
    else
        dead="$dead test$r"
    fi
done

inject=$(grep -hc "P200-STRAND-INJECT" "$OUT"/dmesg_test*.log 2>/dev/null | awk '{s+=$1} END{print s+0}')
repair=$(cat "$OUT"/dmesg_test*.log 2>/dev/null | grep -c "disk_held=1 repair=1")
#
# A `disk_held=1 repair=0` is NOT automatically an abandoned strand.  The
# repair arm deliberately declines while pag_dlm_demoting / release_pending is
# set, because a release already in flight owns the grant and will unlock it —
# the code comment says so explicitly.  Measured: run agstrand_20260729_122129
# produced 2 such lines (test27 ag=20, test8 ag=2) and BOTH AGs were repaired
# on a later BAST (repair=1 x2 each).  Convicting on the raw count would have
# failed a healthy run.
#
# So the real predicate is per (node, AG): a decline that is NEVER followed by
# a repair on that same node.  That still catches a genuinely abandoned strand
# — it just stops flagging the transient the design intends.
abandon=0
abandon_detail=""
for r in $(seq 1 "$N"); do
    f="$OUT/dmesg_test$r.log"
    [ -s "$f" ] || continue
    for ag in $(grep 'disk_held=1 repair=0' "$f" 2>/dev/null | grep -o 'ag=[0-9]*' | sort -u); do
        if [ "$(grep 'disk_held=1 repair=1' "$f" 2>/dev/null | grep -c "$ag ")" = 0 ]; then
            abandon=$(( abandon + 1 ))
            abandon_detail="$abandon_detail test$r/$ag"
        fi
    done
done
declines=$(cat "$OUT"/dmesg_test*.log 2>/dev/null | grep -c "disk_held=1 repair=0")
faults=$(grep -hcE "BUG:|Oops|soft lockup|scheduling while atomic|rcu_preempt detected|WARNING:|Shutting down filesystem" \
         "$OUT"/dmesg_test*.log 2>/dev/null | awk '{s+=$1} END{print s+0}')

echo "--- measured ---"
echo "  P200-STRAND-INJECT (strands created)          : $inject"
echo "  P5N disk_held=1 repair=1 (repair fired)       : $repair"
echo "  P5N disk_held=1 repair=0 (declined; transient OK): $declines"
echo "  strands NEVER repaired on that node (ABANDONED) : $abandon${abandon_detail:+ [$abandon_detail ]}"
echo "  nodes that can still write                    : $wok / $N"
echo "  kernel faults cluster-wide                    : $faults"

st=PASS; why=""
[ "$inject" -ge 1 ] || { st=FAIL; why="$why; no strand was created (P200 absent) — the injection did not take, so this run proves NOTHING about the repair"; }
[ "$repair" -ge 1 ] || { st=FAIL; why="$why; the repair NEVER FIRED (no P5N disk_held=1 repair=1)"; }
[ "$abandon" = 0 ]  || { st=FAIL; why="$why; $abandon strand(s) detected and NEVER repaired on that node:$abandon_detail"; }
[ -z "$dead" ]      || { st=FAIL; why="$why; nodes unable to write after the strands:$dead"; }
[ "$faults" = 0 ]   || { st=FAIL; why="$why; $faults kernel fault line(s) cluster-wide"; }

# Disarm every node.  A one-shot that did not fire stays armed, and would then
# strand an AG in whatever unrelated test runs next — an injected fault leaking
# into another criterion is exactly the kind of phantom that costs a session.
for r in $(seq 1 "$N"); do
    ( timeout 20 "$SSH" "test$r" "echo 0 > /sys/module/mxfs/parameters/ag_strand_inject" >/dev/null 2>&1 ) &
done
wait

echo "RESULT: $st | test=ag_strand_repair | nodes=$N | measured=strands=$inject repaired=$repair declined=$declines abandoned=$abandon write_ok=$wok/$N faults=$faults | reason=${why#; }"
echo "    evidence: $OUT"
[ "$st" = PASS ] && exit 0 || exit 1
