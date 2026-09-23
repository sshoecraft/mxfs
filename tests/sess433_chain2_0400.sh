#!/bin/bash
# sess433 chain 2: after the first chain's lone_crash_replay enforce1 arm
# power-cycled test1 (and left slots 0/1/2 quarantined on the LUN), wait for
# test1 to answer ssh, re-prep 32/caw (fresh mkfs clears the quarantine),
# re-run the D-0354 enforce0 arm that chain 1 lost to the reboot race, run
# the rewritten vergate mixed_build (MB3 = slice byte-compare), then prep
# again so the fleet is left healthy.  The budget rule bounds = each harness's own.
cd /src/mxfs || exit 1
LABEL=${1:-s433b}
LOG=tests/evidence/sess433_chain2_0400_$LABEL.log
{
  echo "=== sess433 chain2 start $(date -u +%FT%TZ) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') ==="
  for t in $(seq 1 20); do timeout 10 tools/mxfs_sshpass.sh test1 "uptime" >/dev/null 2>&1 && break; sleep 10; done
  echo "test1 reachable at $(date -u +%FT%TZ) (wait iterations=$t)"
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep1 rc=$?"
  timeout 200 tests/lone_crash_replay.sh ${LABEL}_e0 test1 test2 32 enforce0; echo "STAGE crash_enforce0 rc=$?"
  for t in $(seq 1 20); do timeout 10 tools/mxfs_sshpass.sh test1 "uptime" >/dev/null 2>&1 && break; sleep 10; done
  echo "test1 reachable again at $(date -u +%FT%TZ)"
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep2 rc=$?"
  timeout 240 tests/vergate.sh test32 mixed_build; echo "STAGE vergate_mixed_build rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
