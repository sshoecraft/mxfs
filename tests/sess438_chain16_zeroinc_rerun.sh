#!/bin/bash
# sess438 chain 16: re-run the zero-epoch arm on 0.42.0 with the harness fix
# (tests/d_recov_zero_epoch_verify.sh counted 'foreign replay of slot N .* complete'
# — two spaces — and read 0 on chain 12 s437a although one survivor re-drove the
# fence (P238-FENCE-REDRIVE), certified PREEMPT_ABORT_DONE, replayed slice 4 and
# published P163-RECOVERY-COMPLETE; 30 peers ran P163-RECOVERED).  Gated on
# chain 15 DONE.  Budgets: prep ~95 s (bound 300), zeroinc ~205 s (bound 300),
# V restart 45 s.
cd /src/mxfs || exit 1
LABEL=${1:-s438b}
LOG=tests/evidence/sess438_chain16_zeroinc_rerun_$LABEL.log
EV=tests/evidence/sess438_chain16_zeroinc_rerun_$LABEL
GATE=tests/evidence/sess438_chain15_takeover_rerun_s438a.log
VIRSH="sudo virsh -c qemu:///system"
mkdir -p "$EV"
{
  echo "=== sess438 chain16 start $(date -u +%FT%TZ) ==="
  for t in $(seq 1 900); do grep -q '^DONE' "$GATE" 2>/dev/null && break; sleep 10; done
  grep -q '^DONE' "$GATE" || { echo "ABORT: chain15 not DONE"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  echo "gate passed at $(date -u +%FT%TZ) (iter $t) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')"
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep rc=$?"
  timeout 300 tests/d_recov_zero_epoch_verify.sh $LABEL; echo "STAGE zeroinc rc=$?"
  $VIRSH start test8 >/dev/null 2>&1; sleep 45
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep2 rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
