#!/bin/bash
# sess446 chain 47 (0.53.0): the D-0512 ruling A′ replay arms, lap 3 — the victim now stops at the converting create (lap 2 replayed only the last 3-4 txns; the re-typed image was never in the slice).  Lap 1
# (chain 39) armed foreign_replay_token_enforce BEFORE target_cache_protected
# on the mounted fleet; the knob's F2 check refused the write silently and
# the survivor replayed enforcement-OFF (every image 'unauthorized', REFUSED
# with WOULD_APPLY=10/10).  The harness now arms in the right order and its
# gate fails closed unless every node reads enforce=1.
#   fix     -> victim slice with the sf->block txn replays COMPLETE, 24 names
#   inject1 -> MIXED  -> REFUSED      inject2 -> retype_nodirty -> REFUSED
# budget: 3 x (prep 79-120 s (300) + arm <= 300 s) + prep2.
cd /src/mxfs || exit 1
while ! grep -q "^DONE" tests/evidence/sess446_chain46_0510_icreate_negative4_s446c.log 2>/dev/null; do sleep 30; done
LABEL=${1:-s446d}
LOG=tests/evidence/sess446_chain47_0512_Aprime_arms3_$LABEL.log
{
  echo "=== sess445 chain47 start $(date -u +%FT%TZ) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') VERSION=$(cat VERSION) ==="
  for arm in fix inject1 inject2; do
    timeout 300 ./run.sh 32 caw prep_cluster; prc=$?; echo "STAGE prep_$arm rc=$prc"
    if [ "$prc" -ne 0 ]; then echo "ABORT: prep failed before arm $arm"; break; fi
    T0=$(date +%s); timeout 300 tests/d0512_sf_to_block_replay.sh $LABEL $arm test2 32 test1; echo "STAGE d0512_$arm rc=$? wall=$(( $(date +%s) - T0 ))s"
  done
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep2 rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
