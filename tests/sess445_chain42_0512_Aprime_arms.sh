#!/bin/bash
# sess445 chain 42 (0.53.0): the D-0512 ruling A′ replay arms, lap 2.  Lap 1
# (chain 39) armed foreign_replay_token_enforce BEFORE target_cache_protected
# on the mounted fleet; the knob's F2 check refused the write silently and
# the survivor replayed enforcement-OFF (every image 'unauthorized', REFUSED
# with WOULD_APPLY=10/10).  The harness now arms in the right order and its
# gate fails closed unless every node reads enforce=1.
#   fix     -> victim slice with the sf->block txn replays COMPLETE, 24 names
#   inject1 -> MIXED  -> REFUSED      inject2 -> retype_nodirty -> REFUSED
# budget: 3 x (prep 79-120 s (300) + arm <= 300 s) + prep2.
cd /src/mxfs || exit 1
while ! grep -q "^DONE" tests/evidence/sess445_chain41_0510_icreate_negative3_s445d.log 2>/dev/null; do sleep 30; done
LABEL=${1:-s445e}
LOG=tests/evidence/sess445_chain42_0512_Aprime_arms_$LABEL.log
{
  echo "=== sess445 chain42 start $(date -u +%FT%TZ) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') VERSION=$(cat VERSION) ==="
  for arm in fix inject1 inject2; do
    timeout 300 ./run.sh 32 caw prep_cluster; prc=$?; echo "STAGE prep_$arm rc=$prc"
    if [ "$prc" -ne 0 ]; then echo "ABORT: prep failed before arm $arm"; break; fi
    T0=$(date +%s); timeout 300 tests/d0512_sf_to_block_replay.sh $LABEL $arm test2 32 test1; echo "STAGE d0512_$arm rc=$? wall=$(( $(date +%s) - T0 ))s"
  done
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep2 rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
