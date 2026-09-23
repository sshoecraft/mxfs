#!/bin/bash
# sess447 chain 55: BUILD 0.54.0 (foreign_replay_token_enforce default 1 +
# mount-time durability-domain admission + F4 census truth probe), then the
# Design-consult ruling's phases 3-5 for the scoped coherence-only default flip:
#   1. domain_admission_matrix (7 mount-time rows on test32);
#   2. prep with the PRODUCTION declaration only (prep_node.sh caw MODARGS =
#      target_cache_protected=1; no harness enforce override anywhere);
#   3. the full 32/caw board (production defaults) — every node must print
#      P-DOMAIN-ADMITTED ... COHERENCE-ONLY;
#   4. node_death_replay x N laps (N from arg 2, default 3 here; the ruling
#      wants >= 10 consecutive — later chains continue the streak).
# Precondition: the tree's scripts already carry the production declaration
# (edited after chain 54 DONE).  Must start only when no other chain runs.
# budget: build 300; matrix 240; prep 300; board ~12 min measured (900);
# N x (prep 300 + row 500).
cd /src/mxfs || exit 1
while ! grep -q "^DONE" tests/evidence/sess447_chain54_0514_lapF2_s447d.log 2>/dev/null; do sleep 30; done
LABEL=${1:-s447e}; NLAPS=${2:-3}
LOG=tests/evidence/sess447_chain55_0540_default_on_$LABEL.log
{
  echo "=== sess447 chain55 start $(date -u +%FT%TZ) pre-build sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') VERSION=$(cat VERSION) ==="
  OLD=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  timeout 300 make modules > tests/evidence/sess447_chain55_build_$LABEL.log 2>&1; brc=$?
  NEW=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  echo "STAGE build rc=$brc old_sv=$OLD new_sv=$NEW errors=$(grep -c 'error:' tests/evidence/sess447_chain55_build_$LABEL.log) newstrings=$(strings -a mxfs.ko | grep -c 'P-DOMAIN-REFUSED\|enforce DEFAULT since\|truth=%s')"
  echo "PARM $(modinfo mxfs.ko | grep 'parm:.*foreign_replay_token_enforce' | cut -c1-160)"
  if [ "$brc" -ne 0 ] || [ "$NEW" = "$OLD" ] || [ "$(strings -a mxfs.ko | grep -c 'P-DOMAIN-REFUSED')" -eq 0 ]; then echo "ABORT: build failed / srcversion unchanged / new strings missing"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  timeout 300 ./run.sh 32 caw prep_cluster; prc=$?; echo "STAGE prep rc=$prc"
  if [ "$prc" -ne 0 ]; then echo "ABORT: prep failed"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  echo "ADMITTED nodes: $(for i in $(seq 1 32); do timeout 20 tools/mxfs_sshpass.sh test$i "journalctl -k --since -10min --no-pager 2>/dev/null | grep -ac 'P-DOMAIN-ADMITTED'" 2>/dev/null | tr -dc '0-9'; echo -n ' '; done)"
  T0=$(date +%s); timeout 240 tests/domain_admission_matrix.sh $LABEL test32; echo "STAGE domain_matrix rc=$? wall=$(( $(date +%s) - T0 ))s"
  timeout 300 ./run.sh 32 caw prep_cluster; prc=$?; echo "STAGE prep2 rc=$prc"
  if [ "$prc" -ne 0 ]; then echo "ABORT: prep2 failed"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  T0=$(date +%s); timeout 900 ./run.sh 32 caw; echo "STAGE board rc=$? wall=$(( $(date +%s) - T0 ))s"
  ./showstat.sh 32 caw 2>/dev/null | grep -a 'PASS\|FAIL\|SKIP\|PENDING' | cut -c1-140
  for lap in $(seq 1 $NLAPS); do
    timeout 300 ./run.sh 32 caw prep_cluster; prc=$?; echo "STAGE prep_ndr$lap rc=$prc"
    if [ "$prc" -ne 0 ]; then echo "ABORT: prep failed"; break; fi
    T0=$(date +%s); timeout 500 ./run.sh 32 caw node_death_replay; echo "STAGE node_death_replay$lap rc=$? wall=$(( $(date +%s) - T0 ))s"
    D=$(ls -dt tests/evidence/board_*_node_death_replay | head -1); echo "EVIDENCE $D"
    for l in shared single; do echo "LAP$lap $l: $(grep -a '^VERDICT\|WAIT ' $D/$l.log 2>/dev/null | head -2 | cut -c1-160 | tr '\n' ' ')"; done
    echo "LAP$lap f4truth: $(cat $D/*/recov_test*.txt 2>/dev/null | grep -ao 'truth=[A-Z-]*' | sort | uniq -c | tr '\n' ' ')"
  done
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep_final rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
