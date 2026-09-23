#!/bin/bash
# sess434 chain 3: waits for chain 2c's DONE (the last 0.40.1 rig user), then
# builds 0.41.0 (D-0354 candidate A step 1: a lone node mints real on-disk CAW
# grants + real epochs; single-node exemptions removed from the token trailer,
# the tenure-track hooks and the join-time surrender), preps 32/caw, and runs
# the directed arms in dependency order:
#   lone_mount_create fixed             (D-0353 regression, 60 s)
#   lone_rsync_bench x2                 (the budget rule vs the chain-2b 0.40.1 baseline, 120 s each)
#   d379b_dirty_depart_peer_fence       (D-0357/D-379 regression, 240 s)
#   lone_crash_replay enforce1/enforce0 (D-0354 closure arms; 200 s each; virsh-destroys A — LAST)
#   prep 32/caw
cd /src/mxfs || exit 1
LABEL=${1:-s434e}
LOG=tests/evidence/sess434_chain3_0410_$LABEL.log
GATE=tests/evidence/sess434_chain2c_0401_s434f.log
{
  echo "=== sess434 chain3 start $(date -u +%FT%TZ) ==="
  for t in $(seq 1 240); do grep -q '^DONE' "$GATE" 2>/dev/null && break; sleep 10; done
  grep -q '^DONE' "$GATE" || { echo "ABORT: chain2c not DONE after 2400 s"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  echo "gate passed at $(date -u +%FT%TZ) (iter $t)"
  OLD=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  timeout 500 make modules > tests/evidence/sess434_build3_$LABEL.txt 2>&1; brc=$?
  timeout 120 make tools >> tests/evidence/sess434_build3_$LABEL.txt 2>&1; trc=$?
  NEW=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  echo "BUILD_RC=$brc TOOLS_RC=$trc VERSION=$(cat VERSION) sv_old=$OLD sv_new=$NEW"
  grep -c 'error:' tests/evidence/sess434_build3_$LABEL.txt | sed 's/^/build errors=/'
  if [ "$brc" -ne 0 ] || [ "$NEW" = "$OLD" ]; then echo "ABORT: build failed or srcversion unchanged"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep rc=$?"
  timeout 60  tests/lone_mount_create.sh ${LABEL}_fixed test1 32 fixed;             echo "STAGE fixed rc=$?"
  timeout 120 tests/lone_rsync_bench.sh ${LABEL}_b1 test1 32;                       echo "STAGE bench1 rc=$?"
  timeout 120 tests/lone_rsync_bench.sh ${LABEL}_b2 test1 32;                       echo "STAGE bench2 rc=$?"
  timeout 240 tests/d379b_dirty_depart_peer_fence.sh ${LABEL}_d379b test1 test2 32; echo "STAGE d379b rc=$?"
  timeout 200 tests/lone_crash_replay.sh ${LABEL}_e1 test1 test2 32 enforce1;       echo "STAGE crash_enforce1 rc=$?"
  for t in $(seq 1 20); do timeout 10 tools/mxfs_sshpass.sh test1 "uptime" >/dev/null 2>&1 && break; sleep 10; done
  timeout 200 tests/lone_crash_replay.sh ${LABEL}_e0 test3 test4 32 enforce0;       echo "STAGE crash_enforce0 rc=$?"
  for t in $(seq 1 20); do timeout 10 tools/mxfs_sshpass.sh test3 "uptime" >/dev/null 2>&1 && break; sleep 10; done
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep2 rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
