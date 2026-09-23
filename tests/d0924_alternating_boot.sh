#!/bin/bash
# d0924_alternating_boot.sh — run the shutdown arm and the healthy reproducer
# ALTERNATELY WITHIN ONE MODULE LIFETIME on the node that never reloads, which
# is the one shape 14+ clean laps of D-0924 have never tried.
#
# WHY THIS SHAPE AND NOT ANOTHER LAP OF EITHER ARM.
# The tripwire that detects this leak (WARN_ON_ONCE in mxfs_ag_meta_track) fires
# when a NEW dirty epoch finds the token ALREADY armed.  It therefore reports a
# leak that happened EARLIER IN THAT BOOT, not one happening at the stack it
# prints -- the record corrected itself on exactly this point after reading the
# 0.75.63 evidence as if the printed stack were the origin.  The boot that
# actually leaked had been running tests for ~6.7 hours before the unload found
# objects in the slab.
#
# Every lap since has started from a fresh prep_cluster, and prep rmmods the
# module on BOTH nodes.  That destroys the slab and resets the tripwire.  So the
# whole measurement campaign has been systematically discarding the state the
# symptom is defined over: a prep between the arms is not neutral, it is the one
# thing guaranteed to hide this.
#
# THE ASYMMETRY THIS EXPLOITS.  agmeta_shutdown_retire.sh unmounts, RMMODS and
# reloads node A as part of its own run -- so A's slab is torn down and counted
# once per arm, and anything A leaked is either reported there or gone.  Node B
# stays mounted and loaded across every arm.  B is therefore the only place a
# leak can ACCUMULATE across arms, and nothing counts B's slab until something
# unloads it.  This harness runs the arms alternately without a prep and then
# unloads the fleet ONCE at the end, so B's whole accumulated history is counted
# in a single shutdown.
#
# WHAT WOULD MAKE THIS NON-VACUOUS.  A clean result only means something if the
# cause path ran, so the per-arm verdicts are reported rather than summarised:
# the shutdown arm must report that the injected shutdown happened AND that the
# put route was taken, and the healthy arm must report its reclaim/stale-clean
# lines.  An arm that did neither proves nothing about the fix, and this script
# says so instead of adding it to a pass count.
#
# the budget rule (derived, from the walls those harnesses recorded themselves): the
# shutdown arm measured ~70 s healthy (8 s churn + 20 s withdrawal settle + ~6 s
# dmesg captures + 5.6 s umount + ~2 s rmmod + ~3 s rejoin), so its bound is
# 150 s -- roughly twice measured, not a round number.  The stale-leak arm ran
# well under a minute in the s587/s597 laps; bound 120 s.  fleet_unload_check
# tears down two nodes concurrently, measured under 40 s; bound 90 s.  With
# ROUNDS=2 that is 2 x (150 + 120) + 90 = 630 s plus one prep.  Any step that
# exceeds its bound is a FAILURE and is recorded as one, never re-run wider.
#
# Usage: tests/d0924_alternating_boot.sh <label> [ROUNDS=2]
# Env:   MXFS_NODE_LIST (default test1,test2), MXFS_DEV, PREP=1 to prep first
#        (do this ONCE, at the start -- that is the point of the harness)
set -u
LABEL=${1:?label}
ROUNDS=${2:-2}
cd "$(dirname "$0")/.." || exit 2

export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
# the device under test by identity, not by path: the LUN this rig declares
# (data/rigs.json), verified by its WWID on the node, and the node's live mxfs
# mount when it has one; MXFS_DEV names a candidate that must be that LUN.
# mxfs_dev_resolve (tests/lib/rig.sh) ABORTs on anything else, never defaults
. "$(dirname "$0")/lib/rig.sh"
mxfs_dev_resolve "${MXFS_NODE_LIST%%,*}"; export MXFS_DEV=$MXFS_DEV_RESOLVED
A=${MXFS_NODE_LIST%%,*}
B=${MXFS_NODE_LIST##*,}
SSH=tools/mxfs_sshpass.sh
MNT=${MNT:-/mnt/shared}
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_d0924alt_$LABEL
mkdir -p "$OUT"

filt() { grep -av '^Unauthorized\|^Warning:\|^If you\|^$'; }
# rs: tests/lib/rig.sh (sourced above) provides the same helper; a local copy would shadow it

SV=$(modinfo mxfs.ko 2>/dev/null | sed -n 's/^srcversion: *//p')
echo "=== d0924_alternating_boot label=$LABEL rounds=$ROUNDS sv=$SV out=$OUT $(date -u +%FT%TZ) ==="

if [ "${PREP:-0}" = 1 ]; then
    s=$(date +%s)
    MXFS_FORCE_PREP=1 timeout 300 ./run.sh 2 tcp prep_cluster > "$OUT/prep.log" 2>&1
    prc=$?
    echo "STAGE prep rc=$prc wall=$(( $(date +%s) - s ))s"
    [ $prc = 0 ] || { echo "RESULT: INFRA label=$LABEL prep rc=$prc"; exit 2; }
fi

# Record the taint word and B's module identity BEFORE anything runs.  The taint
# bits are the load-bearing datum for the tripwire, not the log lines: the WARN
# fires at most once per boot and these nodes' rings wrap well inside a campaign.
bootid_before=""
for n in $A $B; do
    t=$(rs 25 "$n" "cat /proc/sys/kernel/tainted; cat /sys/module/mxfs/srcversion 2>/dev/null")
    echo "  BEFORE $n tainted+sv: $(echo "$t" | tr '\n' ' ')"
    [ "$n" = "$B" ] && bootid_before=$(rs 25 "$B" "cat /proc/sys/kernel/random/boot_id")
done

fails=0
for r in $(seq 1 "$ROUNDS"); do
    s=$(date +%s)
    timeout 150 tests/agmeta_shutdown_retire.sh "${LABEL}sd$r" > "$OUT/r${r}_shutdown.log" 2>&1
    src=$?
    sw=$(( $(date +%s) - s ))
    sv_line=$(grep -a '^RESULT:' "$OUT/r${r}_shutdown.log" | tail -1)
    [ "$sw" -le 150 ] && [ $src -le 1 ] || fails=$((fails+1))
    echo "round=$r arm=shutdown rc=$src wall=${sw}s :: ${sv_line:-NO_TERMINAL_RECORD}"

    # NO PREP HERE.  That omission is the entire experiment.
    s=$(date +%s)
    timeout 120 tests/agmeta_stale_leak_2node.sh "${LABEL}hl$r" > "$OUT/r${r}_healthy.log" 2>&1
    hrc=$?
    hw=$(( $(date +%s) - s ))
    hv_line=$(grep -a '^RESULT:' "$OUT/r${r}_healthy.log" | tail -1)
    [ "$hw" -le 120 ] && [ $hrc -le 1 ] || fails=$((fails+1))
    echo "round=$r arm=healthy  rc=$hrc wall=${hw}s :: ${hv_line:-NO_TERMINAL_RECORD}"

    # Non-vacuity, per round: did the cause path actually run this time?
    # sess567: report the shutdown arm's OWN verdicts, not a grep for strings it
    # never prints.  The first version searched its stdout for 'log_inject_ioerr'
    # and 'SHUTDOWN' and found neither, so it printed injected=0 on laps where
    # the injection had in fact fired and killed the log mid-churn
    # (arm_rc=0 ops=7785 op_errs=7532).  A non-vacuity line that under-reports is
    # worse than none: it says "this lap proved nothing" about a lap that did
    # exercise the mechanism, and the next reader stops there.  The arm already
    # asserts all of this itself; echo what it decided.
    echo "    NONVAC shutdown: $(grep -ao 'arm_rc=[0-9]* ops=[0-9]* op_errs=[0-9]*' "$OUT/r${r}_shutdown.log" | head -1)"
    echo "                     $(grep -ah 'the injected log error shut\|landed INSIDE the churn\|NON-VACUOUS: the xfs_buf_item_put' "$OUT/r${r}_shutdown.log" | sed 's/^ *//' | tr '\n' '|')"
    # The rejoin line must be the ARM'S OWN VERDICT, not a grep for the first
    # mount_rc= in its stdout.  The first version did the latter and reported
    # rejoin=mount_rc=0 for a round the arm had FAILED at mount_rc=32 — the
    # string it matched came from the assertion's own "want=mount_rc=0" half.
    # That is the second time in one session that a summary line invented a
    # cleaner result than the thing it was summarising, so: quote the verdict.
    echo "                     put_route=$(grep -ac 'P-AGMETA-RELSE-OUTSTANDING why=put' "$OUT/r${r}_shutdown.log") put_reclaim=$(grep -ac 'P-AGMETA-RECLAIM why=put' "$OUT/r${r}_shutdown.log")"
    echo "                     $(grep -ah 'rejoined the cluster with no operator action' "$OUT/r${r}_shutdown.log" | sed 's/^ *//' | head -1)"
    echo "    NONVAC healthy:  $(grep -ao 'reclaim_lines=[0-9]*\|stale_clean_lines=[0-9]*\|releases=[0-9]*' "$OUT/r${r}_healthy.log" | tr '\n' ' ')"

    # B never reloads, so its taint word carries the whole accumulated history.
    echo "    TAINT after round $r: $A=$(rs 25 "$A" 'cat /proc/sys/kernel/tainted') $B=$(rs 25 "$B" 'cat /proc/sys/kernel/tainted')"
    echo "    B tripwire lines so far: $(rs 30 "$B" "dmesg | grep -ac 'mxfs_ag_meta_track'")"
done

# B must not have rebooted underneath us, or the accumulation argument is void
# and every taint reading above belongs to a different module lifetime.
bootid_after=$(rs 25 "$B" "cat /proc/sys/kernel/random/boot_id")
if [ "$bootid_before" != "$bootid_after" ]; then
    echo "RESULT: INFRA label=$LABEL $B rebooted mid-run (boot_id changed) — accumulation void"
    exit 2
fi

# The single teardown that finally counts B's slab.
s=$(date +%s)
timeout 90 tests/fleet_unload_check.sh "${LABEL}u" > "$OUT/unload.log" 2>&1
urc=$?
uw=$(( $(date +%s) - s ))
uv_line=$(grep -a '^RESULT:' "$OUT/unload.log" | tail -1)
[ "$uw" -le 90 ] || fails=$((fails+1))
[ $urc = 0 ] || fails=$((fails+1))
echo "STAGE unload rc=$urc wall=${uw}s :: ${uv_line:-NO_TERMINAL_RECORD}"
echo "  SLAB lines: $(grep -ac 'Objects remaining' "$OUT/unload.log") ; WARN lines: $(grep -ac 'WARNING: CPU' "$OUT/unload.log")"
grep -a 'Objects remaining\|mxfs_ag_meta_track\|WARNING: CPU' "$OUT/unload.log" | head -12

echo "RESULT: label=$LABEL rounds=$ROUNDS fails=$fails sv=$SV evidence=$OUT"
[ "$fails" = 0 ]
