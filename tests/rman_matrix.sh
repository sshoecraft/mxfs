#!/bin/bash
# rman_matrix.sh — the recovery-manifest verification matrix (docs/recovery-
# manifest.md build step 6), driven as a sequence of tmpfile_churn_kill.sh
# arms, each with its own knobs and expectation.  One arm per invocation or
# all; each arm's verdict line and the rman: sweep line are collected into
# $OUT/matrix.txt so the whole matrix reads in one screen.
#
# Arms (VICTIMS class per arm; iters=2000, inj=0):
#   base_single   single-owner victims, report-only            expect PASS, sealed>=2
#   base_shared   shared-AG victims, enforcement armed         expect PASS, sealed>=2, admit>0
#   inject1       rman_inject=1 (fail pre-write) cleared +80 s expect PASS, snapshot_pending>=1
#   inject2       rman_inject=2 (fail pre-seal-CAS) cleared    expect PASS, snapshot_pending>=1
#   inject3       rman_inject=3 (torn crc), enforcement armed  expect TERMINAL MANIFEST-INVALID,
#                                                              nothing replayed/purged
#   mutate1       rman_test_mutate=1 on test1 (guarded clear)  expect PASS + guard_refused>=1
#   mutate2       rman_test_mutate=2 on test1 (bypass guard),  expect TERMINAL AUTHORITY-MUTATED
#                 enforcement armed
#   busy          rman_inject=4 holds the prover 30 s + forces the retry sweep
#                 (D-FENCE-RETRY-PROVE-BUSY-SPIN-406)      expect PASS, 1<=prove_busy<=20
#   takeover      rman_inject=1 parks the prover at SNAPSHOTTING; the after-kill
#                 hook (tests/rman_prover_kill.sh) destroys the prover (+75 s)
#                 and clears the knob            expect PASS, snapshot_takeover>=1, sealed>=3
#
# budget: each arm is bounded by the kill harness's own derived budget (230 s
# wall measured 170-230 on 0.24.2-0.26.x; prep 58-105 s inside it).  The
# takeover arm carries a SECOND heartbeat expiry (prover killed at +~90 s,
# expires +62 s, fence+takeover+seal+3 replays): TCK_EXTRA_RECOV=70 widens the
# churn budget and recovery bound by exactly that, wrapper 260+70.
# the source-tree rule: lives in tests/.  Evidence under tests/evidence/ (never the scratchpad).
#
# Usage: tests/rman_matrix.sh <evidence_dir> [arm ...]      (default: all arms)

set -u
cd "$(dirname "$0")/.." || exit 2
OUT=${1:?evidence dir}; shift
# sess415 guard (the sess413 chain2 trap): $1 is the EVIDENCE DIR — invoking
# `rman_matrix.sh base_shared base_shared base_shared` silently eats the first
# arm name as the dir and runs one arm fewer than requested.
case "$OUT" in
base_single|base_shared|inject1|inject2|inject3|mutate1|mutate2|busy|takeover)
    echo "ERROR: first arg is the EVIDENCE DIR but got arm name '$OUT' — pass a dir, then arms" >&2
    exit 2 ;;
esac
mkdir -p "$OUT"
ARMS=("$@"); [ ${#ARMS[@]} -eq 0 ] && ARMS=(base_single base_shared inject1 inject2 inject3 mutate1 mutate2 busy takeover)
SSH=tools/mxfs_sshpass.sh
# sess407: EVERY arm carries ENF.  The first matrix (0.26.2, sess406) ran the
# "report-only" arms with params='' and every one of them refused replay
# (POLICY-REFUSED rc=-117, quarantine=60, ATOMIC-SKIP): that is the DESIGNED
# foreign_replay_token_enforce=0 behaviour (ledger #1: knob default 0 keeps
# the sess232 fail-closed blanket refusal until the default-on gate is met;
# sess356: ENFORCEABLE_WOULD_APPLY=N/N refused).  A PASS-expecting arm without
# ENF cannot pass; the manifest mechanics under test need the replay to run.
# wrap (budget): measured 0.26.2 walls = non-recovery part 122..143 s + the
# recovery wait; inject1/2 wait up to TCK_RECOV_BOUND=150 -> 143+150+~15 = 310.
ENF="target_cache_protected=1 foreign_replay_token_enforce=1"
CLEAR1="TCK_AFTER_KILL_CMD='tests/fleet_set_params.sh rman_inject=0 32'"

run_arm() {
    local arm=$1 victims=$2 params=$3 expect=$4 extra_env=$5 wrap=${6:-260}
    local log=$OUT/$arm.log t0=$(date +%s) rc
    echo "=== arm=$arm victims=$victims params='$params' expect=$expect wrap=${wrap}s $(date -u +%FT%TZ)" | tee -a "$OUT/matrix.txt"
    # extra_env is a shell-quoted assignment list (values may carry spaces),
    # exported in a subshell so the harness and its after-kill hook inherit it.
    ( [ -n "$extra_env" ] && eval "export $extra_env"; TCK_PARAMS="$params" TCK_OUT="$OUT/$arm" timeout "$wrap" tests/tmpfile_churn_kill.sh "$arm" "$victims" 0 2000 32 ) > "$log" 2>&1
    rc=$?
    {
        echo "rc=$rc wall=$(( $(date +%s) - t0 ))s"
        grep -E '^victims|^extra victim|^knobs|^params|^churn|^WAIT|^sweep|^gate|^rman|^afterkill|^terminal arm|^chk|^FAIL|^VERDICT' "$log" | cut -c1-300
        grep -E 'P-RMAN-(TEST-MUTATE|GUARD-REFUSED|MUTATED-TERMINAL|INVALID-TERMINAL|SNAPSHOT-TAKEOVER|SNAPSHOT-PENDING)' "$OUT/$arm/sweep.txt" 2>/dev/null | grep -oE 'P-RMAN-.*' | cut -c1-240 | sort | uniq -c | head -12
    } | tee -a "$OUT/matrix.txt"
    echo | tee -a "$OUT/matrix.txt"
}

for arm in "${ARMS[@]}"; do
    case $arm in
    base_single) run_arm base_single auto:single "$ENF" PASS "" ;;
    base_shared) run_arm base_shared auto:shared "$ENF" PASS "" ;;
    inject1)     run_arm inject1 auto:single "$ENF rman_inject=1" PASS "$CLEAR1 TCK_AFTER_KILL_DELAY=80 TCK_RECOV_BOUND=150" 310 ;;
    inject2)     run_arm inject2 auto:single "$ENF rman_inject=2" PASS "$CLEAR1 TCK_AFTER_KILL_DELAY=80 TCK_RECOV_BOUND=150" 310 ;;
    inject3)     run_arm inject3 auto:single "$ENF rman_inject=3" TERMINAL "TCK_RMAN_EXPECT_TERMINAL=1" ;;
    mutate1)     run_arm mutate1 auto:single "$ENF" PASS "TCK_TEST1_PARAMS=rman_test_mutate=1 TCK_RMAN_EXPECT_GUARD=1" ;;
    mutate2)     run_arm mutate2 auto:single "$ENF" TERMINAL "TCK_TEST1_PARAMS=rman_test_mutate=2 TCK_RMAN_EXPECT_TERMINAL=1" ;;
    busy)        run_arm busy auto:single "$ENF rman_inject=4" PASS "TCK_RMAN_EXPECT_BUSY=1 TCK_RECOV_BOUND=130 TCK_EXTRA_RECOV=35" 300 ;;
    takeover)    run_arm takeover auto:single "$ENF rman_inject=1" PASS "TCK_AFTER_KILL_CMD=tests/rman_prover_kill.sh TCK_AFTER_KILL_DELAY=75 TCK_RECOV_BOUND=120 TCK_EXTRA_RECOV=70" 330 ;;
    *) echo "unknown arm $arm" | tee -a "$OUT/matrix.txt" ;;
    esac
done
echo "=== matrix done $(date -u +%FT%TZ) ===" | tee -a "$OUT/matrix.txt"
