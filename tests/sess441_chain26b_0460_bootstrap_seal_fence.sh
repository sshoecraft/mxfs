#!/bin/bash
# sess441 chain 26: build 0.46.0 (item 5b: whole-cluster bootstrap OWNER path —
# survivor scan, claim, fresh scan, key classification, manifest, seal,
# RECOVERING, phase-3 fencing of every manifest entry through the certified
# pipeline; phase 4 refused as P-BOOT-REPLAY-UNBUILT), deploy, then:
#   prep                 32/32 regression gate (the pre-REGISTER record peek
#                        and the survivor scan run on EVERY CAW mount: a live
#                        cluster must be recognised within one poll)
#   node_death_replay    the ordinary one-death path is untouched
#   prep_mid             fleet back
#   bootstrap_seal_fence the item-5b measurement (tests/bootstrap_seal_fence.sh)
#   prep2                mkfs resets the record; fleet re-preps
# Gated on chain 25 DONE.  Budgets: build ~3 min (bound 500), tools 120,
# prep 77 s (bound 300), node_death_replay 334 s (bound 497),
# bootstrap_seal_fence ~680 s (bound 720), prep2 300.
cd /src/mxfs || exit 1
LABEL=${1:-s441b}
LOG=tests/evidence/sess441_chain26_0460_bootstrap_seal_fence_$LABEL.log
EV=tests/evidence/sess441_chain26_0460_bootstrap_seal_fence_$LABEL
GATE=tests/evidence/sess441_chain25_0453_item5a_regression_s441a.log
mkdir -p "$EV"
{
  echo "=== sess441 chain26 start $(date -u +%FT%TZ) ==="
  for t in $(seq 1 180); do grep -q '^DONE' "$GATE" 2>/dev/null && break; sleep 10; done
  grep -q '^DONE' "$GATE" || { echo "ABORT: chain25 not DONE"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  echo "gate passed at $(date -u +%FT%TZ) (iter $t)"
  OLD=NONE
  timeout 500 make modules > "$EV/build.txt" 2>&1; brc=$?
  timeout 120 make tools >> "$EV/build.txt" 2>&1; trc=$?
  NEW=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  echo "BUILD_RC=$brc TOOLS_RC=$trc VERSION=$(cat VERSION) sv_old=$OLD sv_new=$NEW"
  echo "build errors=$(grep -c 'error:\|ERROR:' "$EV/build.txt")"
  grep -a 'error:\|ERROR:' "$EV/build.txt" | cut -c1-200 | head -10
  if [ "$brc" -ne 0 ] || [ "$trc" -ne 0 ] || [ "$NEW" = "$OLD" ]; then echo "ABORT: build failed or srcversion unchanged"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  timeout 300 ./run.sh 32 caw prep_cluster; prc=$?; echo "STAGE prep rc=$prc"
  if [ "$prc" -ne 0 ]; then echo "ABORT: prep failed on $(cat VERSION)"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  timeout 497 ./run.sh 32 caw node_death_replay; echo "STAGE node_death_replay rc=$?"
  timeout 300 ./run.sh 32 caw prep_cluster; prc=$?; echo "STAGE prep_mid rc=$prc"
  if [ "$prc" -ne 0 ]; then echo "ABORT: prep_mid failed"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  timeout 720 tests/bootstrap_seal_fence.sh $LABEL 32 test1; echo "STAGE bootstrap_seal_fence rc=$?"
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep2 rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
