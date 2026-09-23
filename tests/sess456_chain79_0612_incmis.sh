#!/bin/bash
# sess456 chain 79: build 0.61.2 IN TREE once chain 78 (0.61.1 sv 5AF0FCA5,
# tests/sess455_chain78_0611.sh s455b, whose last stage is the 32/caw board)
# prints DONE and the rig is idle, then verify:
#   D-FENCE-INTENT-ADOPTS-SECTOR-INCARNATION-GUARDS-UNOBSERVED-SUCCESSOR-0520
#     (fence_intent supersession predicate + P237-FENCE-SUPERSEDED-RETIRED)
#   D-MONITOR-INCARNATION-DOWNGRADE-TO-ZERO
#     (zero arm on a PRODUCTION build with the rewritten probe: P-HB-INC-ZERO,
#      P238-FENCE-ZEROINC, no descriptor, restore -> REDRIVE -> COMPLETE)
# via tests/incarnation_mismatch_probe.sh zero + nonzero, victim test32,
# writer test1, prep_cluster between arms (the victim is virsh-destroyed).
#   1  make modules + make tools (abort unless the srcversion CHANGES from
#      5AF0FCA570C65661FAB4AD8 and the P237-FENCE-SUPERSEDED-RETIRED string
#      is present)
#   2  prep_cluster @ 32/caw
#   3  probe zero    — outer bound: frozen-wait 30 + detect 45 + restore 5 +
#                      heal 100 + census/ssh fan-out 40 = 220 -> 240
#   4  prep_cluster
#   5  probe nonzero — frozen-wait 30 + detect 45 + heal 180 + census 40 =
#                      295 -> 300
#   6  prep_cluster (leave the fleet mounted on 0.61.2)
# derived time budgets: build measured 286 s in tree (chain 78) -> 600; prep 300.
cd /src/mxfs || exit 1
LABEL=${1:-s456a}
OLD_SV=${2:-5AF0FCA570C65661FAB4AD8}
GATE=tests/evidence/sess455_chain78_0611_s455b.log
LOG=tests/evidence/sess456_chain79_0612_incmis_$LABEL.log
while ! grep -q "^DONE" "$GATE" 2>/dev/null; do sleep 30; done
lap() { # <budget_s> <label> <cmd...>
  local b="$1" l="$2"; shift 2
  local T0=$(date +%s)
  timeout "$b" "$@"; echo "STAGE $l rc=$? wall=$(( $(date +%s) - T0 ))s"
}
{
  echo "=== sess456 chain79 START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) old_sv=$OLD_SV ==="
  T0=$(date +%s)
  timeout 600 make modules > tests/evidence/sess456_chain79_build_$LABEL.log 2>&1; brc=$?
  echo "STAGE build rc=$brc wall=$(( $(date +%s) - T0 ))s errors=$(grep -c 'error:' tests/evidence/sess456_chain79_build_$LABEL.log) warnings=$(grep -c 'warning:' tests/evidence/sess456_chain79_build_$LABEL.log)"
  NEW_SV=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  echo "srcversion now $NEW_SV modinfo_lab=$(modinfo mxfs.ko | grep -c mxfs_iclus_relmark_lab)"
  if [ "$brc" != 0 ] || [ "$NEW_SV" = "$OLD_SV" ] || [ "$(strings -a mxfs.ko | grep -c 'P237-FENCE-SUPERSEDED-RETIRED')" = 0 ]; then
    echo "ABORT: build rc=$brc sv=$NEW_SV (old $OLD_SV) retired_string=$(strings -a mxfs.ko | grep -c 'P237-FENCE-SUPERSEDED-RETIRED')"
    echo "DONE $(date -u +%FT%TZ)"; exit 1
  fi
  lap 120 tools make tools
  lap 300 prep ./run.sh 32 caw prep_cluster
  for arm in zero nonzero; do
    B=240; [ "$arm" = nonzero ] && B=300
    T0=$(date +%s)
    timeout $B tests/incarnation_mismatch_probe.sh $arm test32 test1 > tests/evidence/sess456_chain79_${arm}_$LABEL.txt 2>&1; rc=$?
    echo "STAGE probe_$arm rc=$rc wall=$(( $(date +%s) - T0 ))s"
    grep -a 'probe: \(PASS\|FAIL\|RESULT\|pending\|superseded\|descriptor\|self-heal\|restor\|note\|evidence\)' tests/evidence/sess456_chain79_${arm}_$LABEL.txt | cut -c1-220
    lap 300 "prep_after_$arm" ./run.sh 32 caw prep_cluster
  done
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
