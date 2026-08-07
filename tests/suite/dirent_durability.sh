#!/bin/bash
# dirent_durability — a mkdir(2) that returns SUCCESS must produce a directory
# entry that exists on EVERY node.  Zero silent namespace loss.
#
# WHY THIS EXISTS (ccloop c7ee71c6 sess21)
#   tests/sf_mkdir_storm.sh has been the reproducer for this family for many
#   sessions but was never a CRITERION, so the board read 20/20 green while a
#   proven silent loss was open.  Measured byte-exact (sfstorm_20260728_201959,
#   ROUND 29, pino=46137485):
#
#       nlink=33 visible=31 expected=32 missing=[ node24_1 ]   on ALL 32 nodes
#       zero MKDIR-RC lines cluster-wide  =>  every mkdir(2) returned 0
#
#   mkdir returned success; the entry existed nowhere.  Deterministic precursor
#   in dmesg: P195-STALE-BASE-ALREADY-DIRTY (~1 per storm run).
#
# WHAT IT DOES
#   All N nodes mkdir their own uniquely-named child into ONE shared parent,
#   simultaneously, for R rounds.  The parent crosses the shortform->block
#   conversion boundary partway through, which is the window the loss lives in.
#
# LATE vs LOST — the distinction that makes this trustworthy
#   sess20 proved the original harness OVER-REPORTED: a name that has not
#   propagated to this node YET is indistinguishable from one that is gone, and
#   a bare "check immediately" flagged 70 rounds of which ZERO were still wrong
#   after settling.  Measured propagation for 32 concurrent mkdirs into one
#   directory: min 24 ms, p50 810 ms, p90 1382 ms, max 1573 ms.  So this test
#   RE-CHECKS a missing name until SETTLE_MS before convicting.  Only a name
#   still absent after that is DURABLE loss.  Do not weaken this; do not
#   shorten SETTLE_MS to make a run pass.
SUITE_TEST_NAME=dirent_durability
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/lib.sh"

R="$RANK"; T="$NODES"
ROUNDS="${DIRENT_ROUNDS:-30}"
# 4 s of re-checking is ~2.5x the measured worst-case propagation (1573 ms),
# so a PASS means "durably present", not "we waited long enough to be lucky".
SETTLE_MS="${DIRENT_SETTLE_MS:-4000}"

# Slot cadence.  The storm proved that WALL-CLOCK slots, not barriers, are the
# right synchroniser here: a barrier per round costs a broker round-trip per
# node per round (30 of them at 32 nodes blew a 240 s budget outright), and it
# also serialises the tenures, which removes the very race being tested.  Node
# clocks are UTC-synced (see CLAUDE.md), so a shared epoch + fixed slot gives
# true simultaneity for free.
SLOT="${DIRENT_SLOT:-2}"

# Per-RUN working directory, derived from the coordination prefix (which the
# harness makes unique per run and identical across nodes).  This deliberately
# does NO cleanup of prior runs:
#   * an inline `rm -rf` of a leftover tree runs BEFORE the rendezvous, so if it
#     is slow every other node sits in the barrier until COORD_TIMEOUT and the
#     test dies with NO_TERMINAL_RECORD on all N nodes;
#   * doing it detached instead just leaves N concurrent `rm -rf`s hammering the
#     shared mount, which then makes the NEXT run slower still — measured: three
#     failed runs in a row each left one, and 10 rounds at 32 nodes then blew a
#     240 s budget that 3 rounds at 2 nodes had cleared in seconds.
# prep_cluster wipes the filesystem, so stale trees are not our problem to
# solve here.
# Stamp a window marker so dirent_publish_integrity (which runs later, at P8)
# can scope its dmesg scan to THIS workload.  Without it that criterion scans
# the whole ring and reports a defect from an hour-old run as if it were
# current — a permanently-red cell is as useless as a permanently-green one.
echo "MXFS_DIRENT_WINDOW" > /dev/kmsg 2>/dev/null
# ccloop c7ee71c6 sess24 — THE KMSG MARKER ALONE IS NOT DURABLE EVIDENCE.
# dmesg is a RING, and its retention varies enormously between nodes in the same
# cluster.  Measured immediately after this criterion PASSED 32/32 (rounds=30,
# 118s wall):
#
#     test19   1964 ring lines spanning  109s   <- marker already rotated out
#     test1  123109 ring lines spanning  709s
#     test25 136966 ring lines spanning 1107s
#
# On test19 the window START scrolled out before the P8 scanners ran, so
# dirent_type_integrity reported FAIL on 5 of 32 nodes with the reason "the
# workload has not run in this boot" -- measurably false, the workload had just
# passed on that very node.  Same class of board lie as the sess23
# reconvergence-beacon bug (also a ring-rotation false red).
#
# So record the window START as a kernel-monotonic timestamp in a file too.  A
# scanner can then scope the ring BY TIMESTAMP even after the marker line itself
# is gone, and can tell whether the ring still reaches back that far instead of
# silently under-counting.  /proc/uptime is the same clock dmesg prints.
{ cut -d' ' -f1 /proc/uptime; } > /run/mxfs_dirent_window_start 2>/dev/null || \
    { cut -d' ' -f1 /proc/uptime; } > /tmp/mxfs_dirent_window_start 2>/dev/null
RUNTAG=$(printf '%s' "${MXFS_COORD_PREFIX:-norun}" | md5sum | cut -c1-8)
BASE="$MNT/.dirent_durability.$RUNTAG"
[ "$R" = 1 ] && mkdir -p "$BASE" 2>/dev/null
# ONE barrier for the whole test, to agree on the start epoch.
ck "dd base ready" coord_barrier "dd_base"
START=$(( $(date +%s) + 3 ))

lost_rounds=""
late_total=0
mkdir_rc_fail=0
pending=""          # "K:node<n> ..." rounds flagged but not yet convicted

# Verify one round.  Returns 0 = every node's entry present; sets MISSING.
#
# ONE readdir, not T lookups.  The obvious `for n in 1..T; do [ -d ... ]` form
# costs T path lookups per call, and this is called for every still-pending
# round on every round — 30 rounds x ~10 pending x 32 nodes = ~9600 lookups,
# which measured out at ~190 s and blew the budget on a cluster where the real
# work takes seconds.  A single `ls` answers the same question for one readdir.
verify_round() {
    local K="$1" D="$BASE/r$K" n present missing=""
    present=$(ls -1 "$D" 2>/dev/null)
    for n in $(seq 1 "$T"); do
        case "
$present" in
            *"
node$n"*) ;;
            *) missing="$missing node$n" ;;
        esac
    done
    # COMMA-separated, never space-separated: `pending` is a space-separated
    # list of "round:missing" tokens, so a MISSING containing spaces splits
    # into extra entries whose "round" is actually a node name.  Those can
    # never verify, so they stay pending forever, and every subsequent round
    # re-readdirs for each of them — the list grows without bound and the test
    # blows its budget (measured: late_ok=1195 for THREE rounds).
    MISSING=$(printf '%s' "${missing# }" | tr ' ' ',')
    [ -z "$MISSING" ]
}

for K in $(seq 1 "$ROUNDS"); do
    # Fire this round at its wall-clock slot, so all N nodes mkdir into the
    # same parent at the same instant.  That simultaneity IS the trigger.
    target=$(( START + (K - 1) * SLOT ))
    while [ "$(date +%s)" -lt "$target" ]; do sleep 0.05; done

    D="$BASE/r$K"
    # Every node mkdir -p's the round dir; exactly one wins, the rest get
    # EEXIST.  The WINNER is the node whose in-core image is dirty and
    # epoch-0 — the state the loss needs.
    mkdir -p "$D" 2>/dev/null
    if mkdir "$D/node$R" 2>/dev/null; then :; else
        rc=$?
        # A REPORTED failure is a different (and far less severe) defect than a
        # silent one.  Count it separately so the two are never conflated.
        mkdir_rc_fail=$((mkdir_rc_fail + 1))
        echo "  DD-MKDIR-RC round=$K rank=$R rc=$rc"
    fi

    # Verify the round that finished two slots ago — quiesced, but not yet torn
    # down.  Deferred (not immediate) so verification never serializes the
    # concurrent window above.
    if [ "$K" -gt 2 ]; then
        J=$((K - 2))
        if ! verify_round "$J"; then
            pending="$pending $J:$MISSING"
        fi
    fi

    # Re-ask about every still-pending round.  A name that was merely slow is
    # retired as LATE-OK here; only one that never appears is convicted below.
    if [ -n "$pending" ]; then
        keep=""
        for ent in $pending; do
            PJ="${ent%%:*}"
            if verify_round "$PJ"; then
                late_total=$((late_total + 1))
            else
                keep="$keep $PJ:$MISSING"
            fi
        done
        pending="${keep# }"
    fi

    # Teardown churn drives inode/daddr REUSE, which the storm proved is
    # required to reach the failing state.  Lag 10 rounds so a flagged round
    # still gets many rechecks before its directory is removed.  Detached so it
    # never eats into the round cadence.
    if [ "$R" = 1 ] && [ "$K" -gt 10 ]; then
        ( rm -rf "$BASE/r$((K - 10))" 2>/dev/null ) &
    fi
    # Drop any pending round that teardown has now been asked to remove: it can
    # no longer be judged either way (see TEARDOWN_LAG note below).
    if [ -n "$pending" ] && [ "$K" -gt 10 ]; then
        torn=$(( K - 10 )); keep=""
        for ent in $pending; do
            [ "${ent%%:*}" -le "$torn" ] 2>/dev/null && continue
            keep="$keep $ent"
        done
        pending="${keep# }"
    fi
done

# Final settle: give every still-pending round the full window before calling
# it a durable loss.  This is the LATE-vs-LOST distinction; do not shorten it.
waited=0
while [ -n "$pending" ] && [ "$waited" -lt "$SETTLE_MS" ]; do
    sleep 0.25; waited=$((waited + 250))
    keep=""
    for ent in $pending; do
        PJ="${ent%%:*}"
        if verify_round "$PJ"; then
            late_total=$((late_total + 1))
        else
            keep="$keep $PJ:$MISSING"
        fi
    done
    pending="${keep# }"
done
# TEARDOWN_LAG must match the lag used above.  Any round at or below
# ROUNDS-TEARDOWN_LAG has been handed to `rm -rf`, so it is UNRESOLVED, never a
# verdict.
#
# Checking `[ -d "$BASE/r$PJ" ]` is NOT sufficient and was measured producing a
# FALSE FAILURE: a PARTIALLY completed `rm -rf` leaves the round directory
# present while its children are already gone, so the round reads as
# "30 of 32 entries missing" and convicts.  test28 reported exactly that for
# r15/r16 (30 nodes each) on a run whose real durable_loss was zero.  sess20
# hit the same artifact in the storm harness ("a concurrent rm -rf walks nlink
# down and that alone was fabricating nlink=4 visible=2 expected=32 on 24
# nodes") — do not re-introduce it.
TEARDOWN_LAG=10
TORN_BELOW=$(( ROUNDS - TEARDOWN_LAG ))
for ent in $pending; do
    PJ="${ent%%:*}"
    [ "$PJ" -le "$TORN_BELOW" ] 2>/dev/null && continue
    [ -d "$BASE/r$PJ" ] || continue
    lost_rounds="$lost_rounds r$PJ[${ent#*:}]"
    # ccloop c7ee71c6 sess27: carry the round directory's INODE, and stamp it
    # into the KERNEL log so it lands inside the same MXFS_DIRENT_WINDOW scope
    # the probe census uses.  Without this the loss can only be matched to a
    # kernel probe by round NUMBER, and the losing rounds are torn down
    # (TEARDOWN_LAG) before anything can stat them — which is exactly what
    # blocked the 8/caw capture where P34J-RELOAD-RACE-BAIL=5 matched
    # durable_loss=5 but bail and loss could not be tied to the same round.
    # The parent inode is what the reload/bail machinery names, so this is the
    # join key.
    dd_ino=$(stat -c %i "$BASE/r$PJ" 2>/dev/null || echo 0)
    echo "  DD-DURABLE-LOSS round=$PJ rank=$R after=${SETTLE_MS}ms dir_ino=$dd_ino missing=[${ent#*:}]"
    echo "MXFS_DD_LOSS round=$PJ rank=$R dir_ino=$dd_ino missing=${ent#*:}" \
        > /dev/kmsg 2>/dev/null || true
done

ck "dd complete" coord_barrier "dd_done"

nlost=$(printf '%s\n' $lost_rounds | grep -c . 2>/dev/null); nlost=${nlost:-0}
st=PASS; reason=""
if [ "$nlost" -gt 0 ]; then
    st=FAIL
    reason="mkdir(2) returned success but the entry is DURABLY absent after ${SETTLE_MS}ms: ${lost_rounds# }"
elif [ "$mkdir_rc_fail" -gt 0 ]; then
    st=FAIL
    reason="$mkdir_rc_fail mkdir(2) call(s) returned an error"
fi
echo "RESULT: $st | test=dirent_durability | nodes=$T | measured=rounds=$ROUNDS durable_loss=$nlost late_ok=$late_total mkdir_err=$mkdir_rc_fail | reason=$reason"
[ "$st" = PASS ]
