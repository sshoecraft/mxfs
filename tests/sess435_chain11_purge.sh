#!/bin/bash
# sess435 chain 11: D-PURGE-NONATOMIC-PUBLICATION closure arms on 0.41.2.  The
# sess420 reruns never executed (tests/evidence/s420_fixups_prep_purge_*.log:
# NODE_PREP_FAIL on test1), so the three arms have NO run since the sess420
# enforcement-arming fix.  Waits for chain 10's DONE.  Each arm ends with the
# victim dead and the fs needing prep; the harness preps per arm as documented.
#   prep 32/caw; d_purge_nonatomic_verify concurrent (200 s)
#   prep 32/caw; d_purge_nonatomic_verify midscan    (200 s)
#   prep 32/caw; d_purge_nonatomic_verify prefinal   (200 s)
#   prep 32/caw
# NEVER `make modules` before this prints DONE.
cd /src/mxfs || exit 1
LABEL=${1:-s435d}
LOG=tests/evidence/sess435_chain11_purge_$LABEL.log
GATE=tests/evidence/sess435_chain10_ccprof_s435c.log
{
  echo "=== sess435 chain11 start $(date -u +%FT%TZ) ==="
  for t in $(seq 1 600); do grep -q '^DONE' "$GATE" 2>/dev/null && break; sleep 10; done
  grep -q '^DONE' "$GATE" || { echo "ABORT: chain10 not DONE after 6000 s"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  echo "gate passed at $(date -u +%FT%TZ) (iter $t) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')"
  for arm in concurrent midscan prefinal; do
    for t in $(seq 1 20); do timeout 10 tools/mxfs_sshpass.sh test8 "uptime" >/dev/null 2>&1 && break; sleep 10; done
    timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep_$arm rc=$?"
    timeout 200 tests/d_purge_nonatomic_verify.sh ${LABEL}_$arm $arm; echo "STAGE $arm rc=$?"
  done
  for t in $(seq 1 20); do timeout 10 tools/mxfs_sshpass.sh test8 "uptime" >/dev/null 2>&1 && break; sleep 10; done
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep_final rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
