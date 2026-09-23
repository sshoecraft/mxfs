#!/bin/bash
# sess465 chain 94: D-FREEOB-COMMIT-VS-FLUSHED-DISCHARGE-RACE-PENDING-STUCK-
# FAILCLOSED-SHUTDOWN-0524 — instrumented verification of the 0.63.1 entry-
# authoritative FREE obligation rewrite.
#
# The defect: the ifree commit (FREE_PENDING -> FREE) and the completion of a
# cluster-buffer write carrying the PRE-free unlink image raced on a lockless
# per-inode byte; the completion re-marked FREE_PENDING over the committed
# FREE, the release gate read 'ifree in flight' for 20 s and shut the node
# down (chain 88, 8/caw dir_reuse round 4, test1 fenced).
#
# Instrument: mxfs.freeob_commit_delay_ms widens the post-commit window so
# the completion reliably lands inside it.  With the fix the completion is
# consumed as a STALE token (P-FREEOB-FLUSH-STALE > 0 proves the interleaving
# was exercised) and nothing regresses: zero P-FREEOB-PENDING at the gate,
# zero P-FREEOB-PENDING-COMMITTED (the self-heal never has to fire), zero
# P-FREEOB-REFUSED / shutdowns, and every freed inode's image is published
# (P55C-FREE-FLUSH / P-FREEOB-PUBLISHED).  stale==0 after 3 laps means the
# window was not hit -> the delay is raised once (150 ms) and 3 more laps run
# (INCONCLUSIVE if still 0).  Then the same laps without the knob, then the
# full 32/caw board on the production module.
#
# Gated on chain 93 DONE (the tree's mxfs.ko is insmod'd by every prep).
# budget: build 420 (measured 311-332 s), tools 120, prep 8 nodes 240
# (measured 91 s), dir_reuse lap 150 (measured 57 s + harness overhead; the
# knob laps are NOT a pace measurement — each ifree sleeps delay_ms), prep 32
# nodes 300 (measured 86-106 s), 32/caw board 1200 (chain 88's 16/caw board
# was 1067 s; the 32/caw board is ~690 s of walls + 12 s x 28 rows overhead).
cd /src/mxfs || exit 1
LABEL=${1:-s465a}
GATE=${GATE:-tests/evidence/sess462_chain93_intents_evidence_s462b.log}
LOG=tests/evidence/sess465_chain94_d0524_$LABEL.log
SSH=tools/mxfs_sshpass.sh
while ! grep -q "^DONE" "$GATE" 2>/dev/null; do sleep 30; done
# second gate: the session touches this flag once every compiled-source edit
# for this build is complete (the chain builds the TREE; a half-edited tree
# must never reach `make modules`)
GO=${GO:-tests/evidence/sess465_chain94_go.flag}
while [ ! -f "$GO" ]; do sleep 30; done
lap() { # <budget_s> <label> <cmd...>
  local b="$1" l="$2"; shift 2
  local T0=$(date +%s)
  timeout "$b" "$@"; echo "STAGE $l rc=$? wall=$(( $(date +%s) - T0 ))s"
}
fleet_sum() { tests/d0524_freeob_sweep.sh 8 | tee -a "$LOG.sweep_$1" | grep '^FLEET'; }
val() { grep -oE "$1=[0-9]+" <<<"$2" | head -1 | cut -d= -f2; }
drc_laps() { # <tag> <n>
  local tag="$1" n="$2" i
  for i in $(seq 1 "$n"); do
    T1=$(date +%s); timeout 150 ./run.sh 8 caw dir_reuse_coherency > tests/evidence/sess465_chain94_drc_${tag}_${i}_$LABEL.log 2>&1
    echo "STAGE drc $tag lap $i rc=$? wall=$(( $(date +%s) - T1 ))s $(grep -a 'dir_reuse_coherency' tests/evidence/sess465_chain94_drc_${tag}_${i}_$LABEL.log | grep -a 'PASS\|FAIL' | tail -1 | cut -c1-200)"
  done
}
{
  echo "=== sess465 chain94 START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) ==="
  T0=$(date +%s)
  # The module under test is the FROZEN scratch build of the 0.63.1 sources
  # (D-0524 + D-0523 only), so later tree edits (dir-sharding wiring) cannot
  # leak into this verification.  SCRATCH_KO/SCRATCH_SV are set by the
  # session after the scratch compile; if unset, build the tree instead.
  SCRATCH_KO=${SCRATCH_KO:-}
  SCRATCH_SV=${SCRATCH_SV:-}
  if [ -n "$SCRATCH_KO" ] && [ -f "$SCRATCH_KO" ] && \
     [ "$(modinfo "$SCRATCH_KO" | awk '/srcversion/{print $2}')" = "$SCRATCH_SV" ]; then
    cp "$SCRATCH_KO" mxfs.ko; brc=$?
    for t in "$(dirname "$SCRATCH_KO")"/tools/*; do
      [ -f "$t" ] && [ -x "$t" ] && file "$t" | grep -q ELF && cp "$t" tools/
    done
    echo "STAGE install rc=$brc wall=$(( $(date +%s) - T0 ))s sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') from=$SCRATCH_KO stale_string=$(strings mxfs.ko | grep -c 'P-FREEOB-FLUSH-STALE') claimwait_string=$(strings mxfs.ko | grep -c 'P300-CLAIM-WAIT')"
  else
    timeout 420 make modules > tests/evidence/sess465_chain94_build_$LABEL.log 2>&1; brc=$?
    echo "STAGE build rc=$brc wall=$(( $(date +%s) - T0 ))s sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') errors=$(grep -c 'error:' tests/evidence/sess465_chain94_build_$LABEL.log) stale_string=$(strings mxfs.ko | grep -c 'P-FREEOB-FLUSH-STALE')"
    lap 120 tools make tools
  fi
  if [ "$brc" -ne 0 ]; then echo "ABORT: build/install"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi

  DELAY=50
  export MXFS_EXTRA_MODARGS="freeob_commit_delay_ms=$DELAY"
  lap 240 prep_knob50 ./run.sh 8 caw prep_cluster
  echo "knob check: $(for i in 1 8; do printf 'test%s:%s ' $i "$(timeout 20 $SSH test$i 'cat /sys/module/mxfs/parameters/freeob_commit_delay_ms' 2>/dev/null | tr -d '\r\n')"; done)"
  drc_laps knob50 3
  S=$(fleet_sum knob50); echo "SWEEP knob50: $S"
  if [ "$(val stale "$S")" = 0 ]; then
    DELAY=150
    export MXFS_EXTRA_MODARGS="freeob_commit_delay_ms=$DELAY"
    lap 240 prep_knob150 ./run.sh 8 caw prep_cluster
    drc_laps knob150 3
    S=$(fleet_sum knob150); echo "SWEEP knob150: $S"
  fi
  unset MXFS_EXTRA_MODARGS
  STALE=$(val stale "$S"); PCOMM=$(val pcomm "$S"); PEND=$(val pend "$S"); PFATAL=$(val pfatal "$S")
  REF=$(val refused "$S"); PROTO=$(val proto "$S"); BUSY=$(val busy "$S"); SHUT=$(val shut "$S"); P55C=$(val p55c "$S"); PUB=$(val pub "$S")
  DRC_FAIL=$(grep -a '^STAGE drc knob' "$LOG" | grep -c 'FAIL')
  if [ "${STALE:-0}" = 0 ]; then V="INCONCLUSIVE (window never hit: stale=0)";
  elif [ "${PCOMM:-0}" = 0 ] && [ "${PEND:-0}" = 0 ] && [ "${PFATAL:-0}" = 0 ] && [ "${REF:-0}" = 0 ] && [ "${PROTO:-0}" = 0 ] && [ "${BUSY:-0}" = 0 ] && [ "${SHUT:-0}" = 0 ] && [ "$DRC_FAIL" = 0 ]; then V="PASS";
  else V="FAIL"; fi
  echo "VERDICT knob: $V | stale=$STALE pcomm=$PCOMM pend=$PEND pfatal=$PFATAL refused=$REF proto=$PROTO busy=$BUSY shut=$SHUT p55c=$P55C pub=$PUB drc_fail_laps=$DRC_FAIL delay_ms=$DELAY (D-0524)"

  lap 240 prep_noknob ./run.sh 8 caw prep_cluster
  drc_laps noknob 2
  S2=$(fleet_sum noknob); echo "SWEEP noknob: $S2"
  echo "VERDICT noknob: stale=$(val stale "$S2") pcomm=$(val pcomm "$S2") pend=$(val pend "$S2") pfatal=$(val pfatal "$S2") refused=$(val refused "$S2") shut=$(val shut "$S2") drc_fail_laps=$(grep -a '^STAGE drc noknob' "$LOG" | grep -c FAIL)"

  lap 300 prep_32 ./run.sh 32 caw prep_cluster
  T1=$(date +%s); timeout 1200 ./run.sh 32 caw > tests/evidence/sess465_chain94_board_32caw_$LABEL.log 2>&1; echo "STAGE board 32/caw rc=$? wall=$(( $(date +%s) - T1 ))s"
  grep -a 'Total:\|FAIL \|POLICY' tests/evidence/sess465_chain94_board_32caw_$LABEL.log | tail -n 8 | cut -c1-200
  S3=$(tests/d0524_freeob_sweep.sh 32 | tee -a "$LOG.sweep_board32" | grep '^FLEET'); echo "SWEEP board32: $S3"

  # D-0523 verification: the guard_race joiner arm at 32/caw (chain 88 shape,
  # cap 560 s from its header).  Both halves must PASS: SAFETY (never claims
  # the guarded slot mid-sweep) and AVAILABILITY (mounts inside the 180 s hold
  # via the new claim wait: P300-CLAIM-WAIT-START ... WAIT-DONE).
  lap 300 prep_guard ./run.sh 32 caw prep_cluster
  T1=$(date +%s); timeout 560 tests/guard_race_arms.sh joiner test2 test1 > tests/evidence/sess465_chain94_guard_joiner_$LABEL.log 2>&1; echo "STAGE guard_race joiner rc=$? wall=$(( $(date +%s) - T1 ))s"
  grep -a 'RESULT:\|FAIL\|claim-wait lines\|joiner claim:' tests/evidence/sess465_chain94_guard_joiner_$LABEL.log | cut -c1-300 | tail -8
  lap 300 prep_final ./run.sh 32 caw prep_cluster
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
