#!/bin/bash
# sess467 chain 99: 0.64.2 on the rig —
#   1. install the frozen 0.64.2 module + tools (SCRATCH_KO/SCRATCH_SV) into
#      the tree (else build the tree);
#   2. prep_cluster 32/caw;
#   3. tests/guard_race_arms.sh joiner test2 test1  (D-0523 claim wait, with
#      the sess467 harness fix: the holder's DONE precedes the claim);
#   4. prep_cluster; tests/guard_race_arms.sh peerloss test2 test1 (D-0523
#      ruling STOP-SHIP 4 second half: every survivor destroyed inside NB's
#      claim wait -> in-mount bootstrap restart -> NB mounts as the owner);
#   5. prep_cluster; tests/intents_classless_attribute.sh s467a test1 2
#      (D-FOREIGN-SLICE-INTENTS-ABANDONED instrumented step: WHY the fragmented
#      free's images are classless — producer P239-OWNAUTH-NONDUR lines);
#   6. prep_final.
# Gated on chain 98 DONE.
# the budget rule (derived): install 30 / build 420; prep 300 (measured 86-113 s);
# joiner 560 (script header budget; chain 94 measured 189 s mount + sweep);
# peerloss 700 (480 mount cap + 150 restore + setup); attribute 60 (2 x 0.2 s
# build + 20 s inactivation + harvest); prep 300 x3.
cd /src/mxfs || exit 1
LABEL=${1:-s467a}
GATE=${GATE:-tests/evidence/sess466_chain98_dirshard_pace_s466c.log}
LOG=tests/evidence/sess467_chain99_d0523_peerloss_attrib_$LABEL.log
while ! grep -q "^DONE" "$GATE" 2>/dev/null; do sleep 30; done
lap() { # <budget_s> <label> <cmd...>
  local b="$1" l="$2"; shift 2
  local T0=$(date +%s)
  timeout "$b" "$@"; echo "STAGE $l rc=$? wall=$(( $(date +%s) - T0 ))s"
}
{
  echo "=== sess467 chain99 START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) ==="
  T0=$(date +%s)
  SCRATCH_KO=${SCRATCH_KO:-}
  SCRATCH_SV=${SCRATCH_SV:-}
  if [ -n "$SCRATCH_KO" ] && [ -f "$SCRATCH_KO" ] && \
     [ "$(modinfo "$SCRATCH_KO" | awk '/srcversion/{print $2}')" = "$SCRATCH_SV" ]; then
    cp "$SCRATCH_KO" mxfs.ko; brc=$?
    for t in "$(dirname "$SCRATCH_KO")"/tools/*; do
      [ -f "$t" ] && [ -x "$t" ] && file "$t" | grep -q ELF && cp "$t" tools/
    done
    echo "STAGE install rc=$brc wall=$(( $(date +%s) - T0 ))s sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') from=$SCRATCH_KO restart_string=$(strings -a mxfs.ko | grep -c 'P300-CLAIM-WAIT-RESTART-BOOTSTRAP') nondur_string=$(strings -a mxfs.ko | grep -c 'P239-OWNAUTH-NONDUR')"
  else
    timeout 420 make modules > tests/evidence/sess467_chain99_build_$LABEL.log 2>&1; brc=$?
    echo "STAGE build rc=$brc wall=$(( $(date +%s) - T0 ))s sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') errors=$(grep -c 'error:' tests/evidence/sess467_chain99_build_$LABEL.log) restart_string=$(strings -a mxfs.ko | grep -c 'P300-CLAIM-WAIT-RESTART-BOOTSTRAP')"
    lap 120 tools make tools
  fi
  if [ "$brc" -ne 0 ] || [ "$(strings -a mxfs.ko | grep -c 'P300-CLAIM-WAIT-RESTART-BOOTSTRAP')" = 0 ]; then echo "ABORT: build/install (no 0.64.2 markers)"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi

  lap 300 prep_joiner ./run.sh 32 caw prep_cluster
  T1=$(date +%s); timeout 560 tests/guard_race_arms.sh joiner test2 test1 > tests/evidence/sess467_chain99_guard_joiner_$LABEL.log 2>&1; echo "STAGE guard_race joiner rc=$? wall=$(( $(date +%s) - T1 ))s $(grep -a '^RESULT' tests/evidence/sess467_chain99_guard_joiner_$LABEL.log | tail -1 | cut -c1-300)"
  grep -a 'joiner claim\|claim-wait lines\|refusal' tests/evidence/sess467_chain99_guard_joiner_$LABEL.log | cut -c1-300 | tail -n 4

  lap 300 prep_peerloss ./run.sh 32 caw prep_cluster
  T1=$(date +%s); timeout 700 tests/guard_race_arms.sh peerloss test2 test1 > tests/evidence/sess467_chain99_guard_peerloss_$LABEL.log 2>&1; echo "STAGE guard_race peerloss rc=$? wall=$(( $(date +%s) - T1 ))s $(grep -a '^RESULT' tests/evidence/sess467_chain99_guard_peerloss_$LABEL.log | tail -1 | cut -c1-300)"
  grep -a 'peerloss:\|refusal\|survivors\|inconclusive\|SAFETY\|AVAILABILITY' tests/evidence/sess467_chain99_guard_peerloss_$LABEL.log | cut -c1-300 | tail -n 6

  lap 300 prep_attrib ./run.sh 32 caw prep_cluster
  T1=$(date +%s); timeout 60 tests/intents_classless_attribute.sh "$LABEL" test1 2 > tests/evidence/sess467_chain99_attrib_$LABEL.log 2>&1; echo "STAGE attribute rc=$? wall=$(( $(date +%s) - T1 ))s $(grep -a '^=== VERDICT' tests/evidence/sess467_chain99_attrib_$LABEL.log | tail -1 | cut -c1-200)"
  grep -a 'INFO\|outcome=\|PASS\|FAIL' tests/evidence/sess467_chain99_attrib_$LABEL.log | cut -c1-200 | tail -n 16

  # 7. same-node exerciser (D-SAMENODE-WAITER-CANCEL-COLLISION + siblings):
  #    0.64.3 prints the verified PRE-unlock holder bit on the PASS line and
  #    the harness counts fault lines as one integer — chain 95's two
  #    harness FAILs; the kernel contract itself passed 32/32 arms there.
  #    budget: 150 s per invocation (script header: 4 arms x ~26 s + harvest).
  lap 300 prep_samenode ./run.sh 32 caw prep_cluster
  for lapn in 1 2 3; do
    T1=$(date +%s); timeout 150 tests/caw_samenode_selftest.sh test1 test2 all > tests/evidence/sess467_chain99_samenode_${lapn}_$LABEL.log 2>&1; echo "STAGE samenode lap=$lapn rc=$? wall=$(( $(date +%s) - T1 ))s $(grep -a '^=== caw_samenode_selftest' tests/evidence/sess467_chain99_samenode_${lapn}_$LABEL.log | tail -1 | cut -c1-160)"
  done
  T1=$(date +%s); timeout 150 tests/caw_samenode_selftest.sh test7 test19 all > tests/evidence/sess467_chain99_samenode_pair2_$LABEL.log 2>&1; echo "STAGE samenode pair2 rc=$? wall=$(( $(date +%s) - T1 ))s $(grep -a '^=== caw_samenode_selftest' tests/evidence/sess467_chain99_samenode_pair2_$LABEL.log | tail -1 | cut -c1-160)"
  grep -ah '\[samenode\] FAIL\|INFRA' tests/evidence/sess467_chain99_samenode_*_$LABEL.log | sort | uniq -c | sort -rn | head -n 8

  lap 300 prep_final ./run.sh 32 caw prep_cluster
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
