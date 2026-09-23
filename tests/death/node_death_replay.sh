#!/bin/bash
# node_death_replay — board criterion: mid-churn NODE DEATH + survivor
# foreign-log-replay under armed token enforcement.
#
# WHY (sess404 finding, D-FOREIGN-REPLAY-UNGATED-IMAGES gate item 3): the
# acceptance board contained NO node-death row — fence_during_write asserts
# no SPURIOUS fence (20 s < the ~62 s HB expiry) and fault_netpartition
# reconverges without a death — so "the board under production defaults"
# could not carry the replay assertions the enforcement default-on gate
# demands.  This row wraps the proven replay oracle
# (tests/tmpfile_churn_kill.sh, 5 armed laps PASS on 0.24.2, re-verified on
# 0.27.x) as a first-class criterion: two laps, shared-AG victims then
# single-AG victims, both with the fleet armed
# (target_cache_protected=1 foreign_replay_token_enforce=1).
#
# Each lap: every node churns O_TMPFILE create->write->linkat->unlink->close
# with the platter-fossil injector armed, two victims are virsh-destroyed
# mid-churn, and tck asserts: every survivor errs=0, every victim slice
# foreign-replayed to "complete" (zero "failed"), no shutdown / corruption /
# P53 / P-IUNL-INSFAIL / P-AGIFC-MISMATCH on any survivor, and chk_mxfs -v
# clean after a full fleet unmount.
#
# HOST-side (coord=host — run_host in run.sh): virsh + fleet orchestration
# the in-guest harness cannot do.  TERMINAL ROW: each tck lap ends with the
# fleet unmounted and the victims freshly rebooted, so this criterion MUST be
# the last row of the matrix (it lives in the terminal "death" category of
# criteria.json); the next board run's prep_cluster remounts everything.
#
# derived time budgets (derived from MEASURED walls, not padded):
#   lap 1 (auto:shared, --no-prep, board cluster already mounted): measured
#     sess413 first run: kills +5/+11 s, survivors done +29 s, both victims'
#     replay terminal +96 s, then victim restart + 30-node umount + chk on the
#     50G device (~60-80 s tail, sess404) -> ~170-190 s; bound 200 s.
#   lap 2 (auto:single, full tck prep — lap 1 unmounted the fleet): lap 1 wall
#     + measured 67-86 s prep -> ~240-270 s; bound 270 s.
#   criteria budget_s 470 = the two expected walls (180+250); a lap overrun
#     FAILs.  Tighten toward measured after healthy PASSes (record convention).
set -u
N=${MXFS_NODES:?}
RUN=${MXFS_RUN_ID:-local}
cd /src/mxfs || { echo "RESULT: FAIL src=test | measured=setup | reason=not-on-clyde"; exit 1; }
OUTROOT=tests/evidence/board_${RUN}_node_death_replay
mkdir -p "$OUTROOT"
# sess447 (0.54.0): NO harness override — foreign_replay_token_enforce
# defaults to 1 and the production declaration target_cache_protected=1 is
# set by tests/setup/prep_node.sh at insmod (the board runs production
# defaults; the design-consult phase-4 condition).
ARM=""

lap() {  # label victims bound extra_args...
    local label=$1 victims=$2 bound=$3; shift 3
    TCK_OUT="$OUTROOT/$label" TCK_PARAMS="$ARM" \
        timeout --kill-after=5 "$bound" tests/tmpfile_churn_kill.sh \
        "bd_$label" "$victims" 20 2000 "$N" "$@" > "$OUTROOT/$label.log" 2>&1
    local rc=$?
    local v; v=$(grep -a -m1 '^VERDICT' "$OUTROOT/$label.log" | cut -c1-160)
    echo "lap $label rc=$rc ${v:-<no verdict line>}" >&2
    LAPV="${v:-none}"
    return $rc
}

fail=0; m1=FAIL; m2=SKIP; r1=""; r2=""
if lap shared auto:shared 200 --no-prep; then m1=PASS; else fail=1; r1="shared: ${LAPV}"; fi
v1=$LAPV
if [ $fail = 0 ]; then
    if lap single auto:single 270; then m2=PASS; else fail=1; r2="single: ${LAPV}"; fi
    v2=$LAPV
else
    r2="single: not run (shared lap failed)"
    v2=skipped
fi

if [ $fail = 0 ]; then
    echo "RESULT: PASS src=test | measured=shared=$m1,single=$m2 | reason="
else
    echo "RESULT: FAIL src=test | measured=shared=$m1,single=$m2 | reason=${r1}${r1:+; }${r2} (evidence $OUTROOT)"
fi
exit $fail
