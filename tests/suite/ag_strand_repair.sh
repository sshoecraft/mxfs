#!/bin/bash
# ag_strand_repair — a STRANDED AG must be DETECTED and REPAIRED.
#
# THE DEFECT (PROVEN, ccloop c7ee71c6 sess20)
#   A CAW AG whose holder bit survives in the on-disk slot table while this
#   node has no in-core tenure at all.  The BAST schedule gate requires
#   pag_dlm_cached, so no peer BAST can ever schedule that AG's release — it is
#   stranded forever.  Captured consequence
#   (tests/logs/wedge_ino138_20260728_1501/): AG 8 stranded on test1 -> test26
#   waited 240 s on it while holding dir ino=138 EX -> all 31 peers starved ->
#   force-shutdown -> 21 of 32 filesystems dead.
#
# WHY THIS CRITERION INJECTS A FAULT INSTEAD OF WATCHING FOR ONE
#   `mxfs.ag_strand_repair` was written to recover that state, and the state
#   then never recurred — so the repair path NEVER EXECUTED.  RULE 6 does not
#   accept "cannot reproduce" as a disposition, and a recovery path that has
#   never run is not a verified fix.  A criterion that merely watched for a
#   natural strand would sit green forever while proving nothing about the
#   thing it claims to cover.
#
#   So each node CREATES the strand: `mxfs.ag_strand_inject=-1` makes the NEXT
#   AG this node releases skip its wire unlock exactly once (test-only,
#   one-shot, self-clearing, default off), leaving our holder bit on the platter
#   with no in-core tenure — the exact stranded state, by construction.
#
# TWO THINGS THAT MAKE OR BREAK THIS, both learned by failing:
#   * EVERY node must arm.  Arming one node produced ZERO strands across a
#     400-mkdir single-node workload AND a full 32-node storm: that node is
#     never BAST'd off an AG in those, so no release path runs on it at all.
#   * The load must be CONCURRENT cross-node allocation.  A node only releases
#     an AG when a peer wants it.  Hence the shared-parent mkdir burst below,
#     on a wall-clock slot so every node allocates at once.
#
# WHAT PASSES (all four)
#   1. this node created a strand (P200-STRAND-INJECT), or no release happened
#      here at all — in which case this node has nothing to judge and says so
#      rather than passing vacuously;
#   2. every strand this node created was repaired: for any AG we DECLINED to
#      repair (P5N disk_held=1 repair=0) there is a later repair=1 for that AG.
#      A bare decline is legitimate — the arm deliberately declines while a
#      release is already in flight — so the raw decline count is NOT the test.
#      Measured: 2 declines in one run, both AGs repaired on a later BAST;
#      convicting on the raw count would have failed a healthy run.
#   3. this node can still write afterwards — proving the AG was actually
#      RELEASED, not merely re-adopted;
#   4. no kernel fault on this node — the repair must not trade a strand for a
#      crash.
#
#   Expect ~2 repair lines per strand.  That is not a loop: measured across 32
#   nodes, every one read exactly strand=1 repair=2 on exactly one AG, and no
#   AG ever needed a third.  A real re-adopt-without-release loop would show
#   that AG's count climbing for the rest of the run.
SUITE_TEST_NAME=ag_strand_repair
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/lib.sh"

R="$RANK"; T="$NODES"
PARAM=/sys/module/mxfs/parameters/ag_strand_inject
BURST="${AGSTRAND_BURST:-120}"

# The lever is test-only and must exist in the build under test.  Absence is
# NOT a pass: it means the repair cannot be exercised at all, and an
# unverifiable criterion must never read green.
if [ ! -e "$PARAM" ]; then
    echo "RESULT: FAIL | test=ag_strand_repair | nodes=$T | measured=lever=absent | reason=mxfs.ag_strand_inject not present in this build — the stranded-AG repair cannot be exercised, and unverifiable is not a pass"
    exit 1
fi

RUNTAG=$(printf '%s' "${MXFS_COORD_PREFIX:-norun}" | md5sum | cut -c1-8)
BASE="$MNT/.agstrand.$RUNTAG"
[ "$R" = 1 ] && mkdir -p "$BASE" 2>/dev/null

# Scope the dmesg scan to THIS run.  An unscoped scan re-reports an hour-old
# strand on every subsequent run, so the cell could never go green again even
# after the repair is working.
echo "MXFS_AGSTRAND_WINDOW" > /dev/kmsg 2>/dev/null

echo -1 > "$PARAM" 2>/dev/null
armed=$(cat "$PARAM" 2>/dev/null | tr -dc '0-9-')
if [ "$armed" != "-1" ]; then
    echo "RESULT: FAIL | test=ag_strand_repair | nodes=$T | measured=armed=$armed | reason=could not arm mxfs.ag_strand_inject — the strand was never created, so this run proves nothing about the repair"
    exit 1
fi

# WORKLOAD — mirror the mkdir storm's shape, because that is what actually
# makes a node release an AG.
#
# Two weaker shapes were tried and BOTH produced strands=0 on every node at 8
# nodes (criterion green, repair never exercised):
#   * a per-node burst into the node's own directory — no peer wants those AGs;
#   * all nodes bursting into ONE shared directory — the children still spread
#     into each node's own AGs.
# What works is MANY FRESH SHARED PARENTS with every node racing into each one:
# a fresh parent forces a fresh AG allocation that all N nodes then contend for,
# so the grant must change hands.  Measured with that shape via the host harness
# at 8 nodes: 7 strands, 14 repairs.  Same rounds/slot model as the storm —
# wall-clock slots, not barriers, so the tenures are not serialised.
# sess34: 16 rounds under-covers at 32 nodes — 5 of 32 nodes saw no AG
# release across the whole workload (strands=0 -> honest FAIL, 2/2 on
# 293/294 + the 292-era 3-of-5 history, same all-zeros signature).  One
# fresh parent per round lands in ONE AG; with 32 contenders the grant
# visits only a subset within the 2s slot, and a ~5-node tail never
# gets BAST'd off anything.  Scale rounds with node count so every node
# statistically sees at least one hand-off; wall at 32 stays ~90-110s
# against the 240s budget.
ROUNDS_W="${AGSTRAND_ROUNDS:-$(( T > 16 ? T : 16 ))}"
SLOT_W="${AGSTRAND_SLOT:-2}"
ck "agstrand start" coord_barrier "as_start"
START=$(( $(date +%s) + 3 ))
for K in $(seq 1 "$ROUNDS_W"); do
    target=$(( START + (K - 1) * SLOT_W ))
    while [ "$(date +%s)" -lt "$target" ]; do sleep 0.05; done
    mkdir -p "$BASE/d$K" 2>/dev/null
    mkdir "$BASE/d$K/n${R}" 2>/dev/null
    # Teardown drives AG FREES, which is half of what makes a peer want an AG
    # we hold.  Without it, 10 rounds at 8 nodes still produced strands=0.
    # Detached so it never eats a slot; rank 1 only, so exactly one remover.
    if [ "$R" = 1 ] && [ "$K" -gt 3 ]; then
        ( rm -rf "$BASE/d$(( K - 3 ))" 2>/dev/null ) &
    fi
done
sync

# Let the strands be noticed and repaired.  A peer BAST is what triggers the
# detection, and the burst above is what produces the BASTs.
sleep 5
ck "agstrand done" coord_barrier "as_done"
sleep 3

# Disarm: a one-shot that did not fire stays armed and would strand an AG in
# whatever unrelated test runs next.  An injected fault leaking into another
# criterion is exactly the kind of phantom that costs a session.
echo 0 > "$PARAM" 2>/dev/null

WINDOW=$(dmesg 2>/dev/null | awk '/MXFS_AGSTRAND_WINDOW/{seen=1; buf=""; next} seen{buf=buf $0 "\n"} END{printf "%s", buf}')
strands=$(printf '%s' "$WINDOW" | grep -c 'P200-STRAND-INJECT')
repairs=$(printf '%s' "$WINDOW" | grep -c 'disk_held=1 repair=1')
declines=$(printf '%s' "$WINDOW" | grep -c 'disk_held=1 repair=0')
faults=$(printf '%s' "$WINDOW" | grep -cE 'BUG:|Oops|soft lockup|scheduling while atomic|rcu_preempt detected|Shutting down filesystem')

# A decline convicts only when that same AG is never repaired here afterwards.
abandoned=0; abandon_ag=""
for ag in $(printf '%s' "$WINDOW" | grep 'disk_held=1 repair=0' | grep -o 'ag=[0-9]*' | sort -u); do
    if [ "$(printf '%s' "$WINDOW" | grep 'disk_held=1 repair=1' | grep -c "$ag ")" = 0 ]; then
        abandoned=$(( abandoned + 1 )); abandon_ag="$abandon_ag $ag"
    fi
done

wok=0
mkdir -p "$BASE/live" 2>/dev/null && touch "$BASE/live/n$R" 2>/dev/null && wok=1

st=PASS; reason=""
if [ "$strands" = 0 ]; then
    # NOT a pass.  A green cell must mean the repair was EXERCISED.  If this
    # node never released an AG even through the shared-directory phase above,
    # the injection never fired here and this criterion verified nothing —
    # which is indistinguishable, from the board, from a working repair.
    # Measured at 8 nodes before the shared phase existed: strands=0 on all 8,
    # criterion green, repair never run.
    st=FAIL
    reason="no AG release occurred on this node, so no strand was created and the repair was NEVER EXERCISED — an unverified criterion must not read green"
fi
[ "$strands" -gt 0 ] && [ "$repairs" = 0 ] && { st=FAIL; reason="created $strands strand(s) and the repair NEVER FIRED (no P5N disk_held=1 repair=1)"; }
[ "$abandoned" = 0 ] || { st=FAIL; reason="$abandoned stranded AG(s) declined and never repaired:$abandon_ag"; }
[ "$wok" = 1 ]      || { st=FAIL; reason="${reason:+$reason; }cannot write after the strand — the AG was not actually released"; }
[ "$faults" = 0 ]   || { st=FAIL; reason="${reason:+$reason; }$faults kernel fault line(s) on this node"; }

echo "RESULT: $st | test=ag_strand_repair | nodes=$T | measured=strands=$strands repaired=$repairs declined=$declines abandoned=$abandoned write_ok=$wok faults=$faults | reason=$reason"
[ "$st" = PASS ]
