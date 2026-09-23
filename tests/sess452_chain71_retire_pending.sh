#!/bin/bash
# sess452 chain 71: 0.59.2 RETIRE_PENDING — the sess451 design-consult STOP-SHIP #2
# fixes (bracketed absence proof, PR INs off the heartbeat, OWN restricted to
# P305 with a fresh proof, key-0 never ABSENT + no clustered self-clear,
# asserted departure quiescence) verified on the production build, with the
# deterministic arms the ruling required:
#   lap  1 retire_pending_admission sameboot     (victim test5,  joiner test6)
#   lap  2 retire_pending_admission joiner       (victim test7,  joiner test8)
#   lap  3 retire_pending_admission unknown      (victim test9,  joiner test10)
#   lap  4 retire_pending_admission unknownresv  (victim test11, joiner test12)
#   lap  5 retire_pending_admission trunc        (victim test13, joiner test14)
#   lap  6 retire_pending_admission slowpr       (victim test15, joiner test16)
#   lap  7 retire_pending_admission joinerunk    (victim test17, joiner test18)
#   lap  8 retire_pending_admission race         (victim test19, joiner test20)
#   lap  9 retire_pending_admission genmove      (victim test21, joiner test22)
#   lap 10 retire_pending_admission multipending (victim test23, joiner test24)
#   lap 11 pr_unregister_fail_restamp restamp    (victim test2)
#   lap 12 pr_unregister_fail_restamp crash      (victim test25)
# ABORTs unless the tree's mxfs.ko carries the 0.59.2 strings (no rebuild
# here; RULE: never rebuild under a run).
# budget: per-arm budgets from the harness header; tools 120; prep 300
# (measured 72-154 s at 32).  Whole chain ~55 min.
# sess453 (chain 72, label s453a): re-run on 0.59.3 (D-0518 PAL-log newline
# fix) with the harness fixes from the chain-71 harvest (prep_node MXFS_DEV,
# header-safe trunc ordering, race-B remount, restamp read-window race).
# Optional 2nd arg: the srcversion the tree's mxfs.ko MUST carry (abort
# otherwise — catches a stale or half-relinked .ko before the fleet loads it).
cd /src/mxfs || exit 1
LABEL=${1:-s452a}
EXPECT_SV=${2:-}
LOG=tests/evidence/sess452_chain71_retire_pending_$LABEL.log
lap() { # <budget_s> <label> <cmd...>
  local b="$1" l="$2"; shift 2
  local T0=$(date +%s)
  timeout "$b" "$@"; echo "STAGE $l rc=$? wall=$(( $(date +%s) - T0 ))s"
}
{
  echo "=== sess452 chain71 start $(date -u +%FT%TZ) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') VERSION=$(cat VERSION) quiesced=$(strings -a mxfs.ko | grep -c 'P304-RETIRE-QUIESCED') settledown=$(strings -a mxfs.ko | grep -c 'P305-RETIRE-SETTLED-OWN') ==="
  if [ "$(strings -a mxfs.ko | grep -c 'P305-RETIRE-SETTLED-OWN')" = 0 ]; then echo "ABORT: mxfs.ko is not a 0.59.2+ build"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  if [ -n "$EXPECT_SV" ] && [ "$(modinfo mxfs.ko | awk '/srcversion/{print $2}')" != "$EXPECT_SV" ]; then echo "ABORT: mxfs.ko srcversion $(modinfo mxfs.ko | awk '/srcversion/{print $2}') != expected $EXPECT_SV"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  lap 120 tools make tools
  lap 300 prep ./run.sh 32 caw prep_cluster
  lap 200 "retire_adm arm=sameboot victim=test5"      tests/retire_pending_admission.sh 32 test5  test6  test1 sameboot
  lap 270 "retire_adm arm=joiner victim=test7"        tests/retire_pending_admission.sh 32 test7  test8  test1 joiner
  # sess453 widened the fencing arms and the restamp laps by +150 s for the
  # D-0519 recovery latency (93 s fence->complete on 0.59.3).  sess455: D-0519
  # is FIXED AND VERIFIED (chains 76/77: fence->complete 0-1 s); budgets
  # re-derived from the measured walls on 0.60.0/0.61.0 (unknown 78/81 s,
  # unknownresv 77/81 s, joinerunk 96/93 s, race 111/110 s, restamp 39/36 s,
  # crash 76/71 s) at ~2x measured, per the budget rule.
  lap 170 "retire_adm arm=unknown victim=test9"       tests/retire_pending_admission.sh 32 test9  test10 test1 unknown
  lap 170 "retire_adm arm=unknownresv victim=test11"  tests/retire_pending_admission.sh 32 test11 test12 test1 unknownresv
  lap 120 "retire_adm arm=trunc victim=test13"        tests/retire_pending_admission.sh 32 test13 test14 test1 trunc
  lap 130 "retire_adm arm=slowpr victim=test15"       tests/retire_pending_admission.sh 32 test15 test16 test1 slowpr
  lap 200 "retire_adm arm=joinerunk victim=test17"    tests/retire_pending_admission.sh 32 test17 test18 test1 joinerunk
  lap 230 "retire_adm arm=race victim=test19"         tests/retire_pending_admission.sh 32 test19 test20 test1 race
  lap 200 "retire_adm arm=genmove victim=test21"      tests/retire_pending_admission.sh 32 test21 test22 test1 genmove
  lap 170 "retire_adm arm=multipending victim=test23" tests/retire_pending_admission.sh 32 test23 test24 test1 multipending
  lap 100 "pr_restamp mode=restamp victim=test2"      tests/pr_unregister_fail_restamp.sh 32 test2 test1 restamp
  lap 160 "pr_restamp mode=crash victim=test25"       tests/pr_unregister_fail_restamp.sh 32 test25 test1 crash
  lap 300 prep_after ./run.sh 32 caw prep_cluster
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
