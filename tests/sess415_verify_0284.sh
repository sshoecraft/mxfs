#!/bin/bash
# sess415 0.28.4 verification chain — D-512 T2/T6 drain pausepoints
# (dbg_rel_pause_{ino,stage,ms} + 5 pause sites in bast_process, no-op
# unarmed) + regression.  Stage caps (budget): prep 300 (new srcversion),
# t2 ladder ~55s bound 150, d512 gate 100, t1 90, zsl 120, board 1400.
cd /src/mxfs || exit 1
LOG=tests/evidence/sess415_verify_0284.log
{
  echo "=== sess415 0.28.4 verify start $(date -u +%FT%TZ) build=$(cat VERSION) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') ==="
  timeout 300 ./run.sh 32 caw prep_cluster
  echo "STAGE prep rc=$?"
  timeout 150 tests/d512_t2_pause.sh s415t2 test2 test1
  echo "STAGE t2 rc=$?"
  timeout 100 tests/d512_incarn_gate_verify.sh s415d test5
  echo "STAGE d512 rc=$?"
  timeout 90 tests/d512_t1_reuse.sh s415t1c test1 test2
  echo "STAGE t1 rc=$?"
  timeout 120 ./run.sh 32 caw zero_silent_loss
  echo "STAGE zsl rc=$?"
  timeout 1400 ./run.sh 32 caw
  echo "STAGE board rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
