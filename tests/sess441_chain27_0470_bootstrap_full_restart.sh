#!/bin/bash
# sess441 chain 27: build 0.47.0 (item 5d shape B: adopted-slice escrow
# (bootstrap record v3, PROTO_GEN 15), claim_victim_slot with
# HB_FEAT_BOOTSTRAP_PENDING, XLOG_MXFS_BOOTSTRAP_ADOPTED own-log replay fed
# from the escrow, ladder complete-bit before zero, barrier terminal/finish
# hooks, destroy-path unwind), deploy, then:
#   prep                    32/32 regression gate (gen-15 mkfs + admission)
#   node_death_replay       the ordinary path through the ladder hook
#   prep_mid
#   bootstrap_full_restart  the item-5 end-to-end (tests/bootstrap_full_restart.sh)
#   prep2
# Budgets: build ~3 min (bound 500), tools 120, prep 77-157 s (bound 300),
# node_death_replay 360 s (bound 497), full_restart ~1000 s (bound 1080),
# prep2 300.
cd /src/mxfs || exit 1
LABEL=${1:-s441d}
LOG=tests/evidence/sess441_chain27_0470_bootstrap_full_restart_$LABEL.log
EV=tests/evidence/sess441_chain27_0470_bootstrap_full_restart_$LABEL
mkdir -p "$EV"
{
  echo "=== sess441 chain27 start $(date -u +%FT%TZ) ==="
  OLD=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
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
  timeout 1080 tests/bootstrap_full_restart.sh $LABEL 32 test1; echo "STAGE bootstrap_full_restart rc=$?"
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep2 rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
