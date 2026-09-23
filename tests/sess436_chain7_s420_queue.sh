#!/bin/bash
# sess436 chain 7: the sess420 verification queue that never ran (every leg
# died at prep on 2026-08-28 07:27 and then failed its srcversion gate), now
# on 0.41.8.  Gated on chain 6.  Budgets from each harness header:
#   zero_epoch 300; radv transient/deadline/invariant 480 each, takeover 200;
#   no_survivor 840 (destroys ALL nodes; restart fleet after); prep 300 each.
cd /src/mxfs || exit 1
LABEL=${1:-s436g}
LOG=tests/evidence/sess436_chain7_s420_queue_$LABEL.log
GATE=tests/evidence/sess436_chain6_ubsweep_burst_s436f.log
VIRSH="sudo virsh -c qemu:///system"
{
  echo "=== sess436 chain7 start $(date -u +%FT%TZ) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') ==="
  for t in $(seq 1 900); do grep -q '^DONE' "$GATE" 2>/dev/null && break; sleep 10; done
  grep -q '^DONE' "$GATE" || { echo "ABORT: chain6 not DONE"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  echo "gate passed at $(date -u +%FT%TZ) (iter $t)"
  timeout 300 tests/d_recov_zero_epoch_verify.sh $LABEL; echo "STAGE zeroinc rc=$?"
  $VIRSH start test8 >/dev/null 2>&1; sleep 45
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep_zeroinc rc=$?"
  for arm in transient deadline invariant; do
    timeout 480 tests/d_recov_advance_bounded_verify.sh $LABEL $arm; echo "STAGE radv_$arm rc=$?"
    for i in $(seq 1 32); do $VIRSH start test$i >/dev/null 2>&1; done; sleep 45
    timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep_radv_$arm rc=$?"
  done
  timeout 200 tests/d_recov_advance_bounded_verify.sh $LABEL takeover; echo "STAGE radv_takeover rc=$?"
  for i in $(seq 1 32); do $VIRSH start test$i >/dev/null 2>&1; done; sleep 45
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep_takeover rc=$?"
  timeout 840 tests/no_survivor_crash_replay.sh $LABEL; echo "STAGE nosurv rc=$?"
  for i in $(seq 1 32); do $VIRSH start test$i >/dev/null 2>&1; done; sleep 90
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep_final rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
