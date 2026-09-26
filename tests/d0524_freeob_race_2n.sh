#!/bin/bash
# D-FREEOB-COMMIT-VS-FLUSHED-DISCHARGE-RACE-PENDING-STUCK-FAILCLOSED-SHUTDOWN-0524
# on 2-node CAW: the entry-authoritative FREE obligation, verified with the
# post-commit window widened.
#
# The defect: the ifree commit (FREE_PENDING -> FREE) and the completion of a
# cluster-buffer write carrying the PRE-free unlink image raced on a lockless
# per-inode byte; the completion re-marked FREE_PENDING over the committed FREE
# and the release gate shut the node down 20 s later (or, in the mirror
# ordering, dropped the committed FREE silently).
#
# mxfs.freeob_commit_delay_ms holds each ifree between its commit and the
# obligation's commit transition, so a cluster-buffer write completion lands in
# that gap.  With the fix the completion is consumed as a STALE token:
#   PASS  stale > 0 (the interleaving happened) and, on every node, zero
#         pcomm / pend / pfatal / refused / proto / busy / shut / supunpf
#         (P177-PUBOB-SUPERSEDED-FREE-UNPROVEN), and every dir_reuse lap PASS.
#   INCONCLUSIVE  stale == 0 after the 150 ms escalation.
# Then the same laps without the knob, which must also be clean.
#
# Budget (derived): prep 2 nodes 70-137 s measured -> 180; a dir_reuse lap is
# 120 s in the manifest (run.sh enforces it) + ~20 s harness -> 150; the knob
# laps are not a pace measurement (each ifree sleeps delay_ms).  Whole run:
# 3 preps + 8 laps + sweeps ~ 3x180 + 8x150 + 60 = ~1800 s wedge bound.
#
# Usage: MXFS_DEV=<by-id path> tests/d0524_freeob_race_2n.sh LABEL
#   Evidence: tests/evidence/d0524_2n/<stamp>_<LABEL>/.  Exit 0 PASS, 1 FAIL,
#   2 INFRA, 3 INCONCLUSIVE.
cd "$(dirname "$0")/.." || exit 2
LABEL=${1:?label}
EV=tests/evidence/d0524_2n/$(date -u +%Y%m%dT%H%M%SZ)_$LABEL
mkdir -p "$EV"
LOG=$EV/run.log
say() { echo "[$(date -u +%T)] $*" | tee -a "$LOG"; }
# the verdict line starts the line, so tests/lap_queue.sh picks it up
result() { echo "RESULT $*" | tee -a "$LOG"; }
val() { grep -oE "(^| )$1=[0-9]+" <<<"$2" | head -1 | cut -d= -f2; }

sweep() { # <tag> -> prints the FLEET line; per-node lines kept in $EV
  tests/d0524_freeob_sweep.sh 2 > "$EV/sweep_$1.txt" 2>&1
  for i in 1 2; do
    timeout 30 tools/mxfs_sshpass.sh test$i \
      "dmesg | grep -c 'P177-PUBOB-SUPERSEDED-FREE-UNPROVEN'" \
      > "$EV/supunpf_$1_test$i.txt" 2>/dev/null
  done
  local su
  su=$(cat "$EV"/supunpf_"$1"_test*.txt 2>/dev/null | awk '{s+=$1} END{print s+0}')
  echo "$(grep '^FLEET' "$EV/sweep_$1.txt") supunpf=$su"
}

prep() { # <tag>
  local t0=$(date +%s) rc
  MXFS_FORCE_PREP=1 timeout 180 ./run.sh 2 cawd prep_cluster > "$EV/prep_$1.log" 2>&1
  rc=$?
  say "prep $1 rc=$rc wall=$(( $(date +%s) - t0 ))s modargs='${MXFS_EXTRA_MODARGS:-}' knob=$(timeout 20 tools/mxfs_sshpass.sh test1 'cat /sys/module/mxfs/parameters/freeob_commit_delay_ms' 2>/dev/null | tr -d '\r\n') sv=$(timeout 20 tools/mxfs_sshpass.sh test1 'cat /sys/module/mxfs/srcversion' 2>/dev/null | tr -d '\r\n')"
  return $rc
}

laps() { # <tag> <n>
  local i t0 rc line
  for i in $(seq 1 "$2"); do
    t0=$(date +%s)
    timeout 150 ./run.sh 2 cawd dir_reuse_coherency > "$EV/drc_$1_$i.log" 2>&1
    rc=$?
    line=$(grep -a 'dir_reuse_coherency' "$EV/drc_$1_$i.log" | grep -a 'PASS\|FAIL' | tail -1 | cut -c1-200)
    say "drc $1 lap $i rc=$rc wall=$(( $(date +%s) - t0 ))s $line"
    grep -q 'PASS' <<<"$line" || echo "$1 $i" >> "$EV/failed_laps"
  done
}

bad() { # <fleet line> [show] -> 0 if any failure counter is nonzero
  local k v hit=1
  for k in pcomm pend pfatal refused proto busy shut supunpf; do
    v=$(val "$k" "$1")
    [ "${2:-}" = show ] && printf '%s=%s ' "$k" "$v"
    [ -n "$v" ] && [ "$v" != 0 ] && hit=0
  done
  return $hit
}

say "label=$LABEL dev=${MXFS_DEV:-run.sh default} evidence=$EV tree=$(cat VERSION)"
DELAY=50
export MXFS_EXTRA_MODARGS="freeob_commit_delay_ms=$DELAY"
prep knob50 || { result "INFRA prep"; exit 2; }
laps knob50 3
S=$(sweep knob50); say "SWEEP knob50: $S"
if [ "$(val stale "$S")" = 0 ]; then
  DELAY=150
  export MXFS_EXTRA_MODARGS="freeob_commit_delay_ms=$DELAY"
  prep knob150 || { result "INFRA prep"; exit 2; }
  laps knob150 3
  S=$(sweep knob150); say "SWEEP knob150: $S"
fi
unset MXFS_EXTRA_MODARGS
prep noknob || { result "INFRA prep"; exit 2; }
laps noknob 2
S2=$(sweep noknob); say "SWEEP noknob: $S2"

NFAIL=$(wc -l < "$EV/failed_laps" 2>/dev/null || echo 0)
if bad "$S" || bad "$S2" || [ "$NFAIL" != 0 ]; then
  result "FAIL delay_ms=$DELAY failed_laps=$NFAIL knob: $(bad "$S" show) noknob: $(bad "$S2" show)"
  exit 1
fi
if [ "$(val stale "$S")" = 0 ]; then
  result "INCONCLUSIVE window never hit (stale=0 at delay_ms=$DELAY)"
  exit 3
fi
result "PASS delay_ms=$DELAY stale=$(val stale "$S") p55c=$(val p55c "$S") pub=$(val pub "$S") disch=$(val disch "$S") failed_laps=0; noknob stale=$(val stale "$S2")"
exit 0
