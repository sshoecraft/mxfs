#!/bin/bash
# sess447 chain 52 (0.53.2 = D-0514 instrumentation + dbg_sweep_hold_ms):
# instrument step 2 for D-TWO-VICTIM-DEATH-SECOND-SLICE-REPLAY-NOT-STARTED-0514.
# Forced shape: two shared-class victims 20 s apart, so victim A's replay
# completes (and its inline tail sweep starts) BEFORE victim B is detected;
# the knob on test1 (the elected replayer, slot 0) parks A's sweep until B's
# death is notified, then holds 30 s.  H1 predicts: P-FREPLAY-NOTIFY slot=B
# busy=RUNNING, NO P-FREPLAY-ENTER / P238-RECOV-LEASE for B during the hold,
# B's lease only after P-DBG-SWEEP-HOLD-END (same inv+1).
# budget: prep 300; harness churn 11 + gap 20 + detect 62 + replay 5 + park
# ~15 + hold 30 + B replay ~70 + wait 95 = ~310 s (bound 500); prep2 300.
cd /src/mxfs || exit 1
while ! grep -q "^DONE" tests/evidence/sess447_chain51_0515_nsop_verify_s447a.log 2>/dev/null; do sleep 30; done
LABEL=${1:-s447b}
LOG=tests/evidence/sess447_chain52_0514_forced_repro_$LABEL.log
{
  echo "=== sess447 chain52 start $(date -u +%FT%TZ) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') VERSION=$(cat VERSION) ==="
  timeout 300 ./run.sh 32 caw prep_cluster; prc=$?; echo "STAGE prep rc=$prc"
  if [ "$prc" -ne 0 ]; then echo "ABORT: prep failed"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  timeout 30 tools/mxfs_sshpass.sh test1 "echo 30000 > /sys/module/mxfs/parameters/dbg_sweep_hold_ms; echo knob=\$(cat /sys/module/mxfs/parameters/dbg_sweep_hold_ms)" 2>/dev/null | grep -a knob
  OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_d0514_forced_$LABEL; mkdir -p "$OUT"
  T0=$(date +%s); TCK_PARAMS="target_cache_protected=1 foreign_replay_token_enforce=1" TCK_VICTIM_GAP=20 TCK_OUT="$OUT" timeout 500 tests/tmpfile_churn_kill.sh d0514_$LABEL auto:shared 20 2000 32 --no-prep; echo "STAGE tmpfile_churn_kill rc=$? wall=$(( $(date +%s) - T0 ))s out=$OUT"
  echo "--- test1 D-0514 trail ---"
  grep -a 'P-FREPLAY-\|P97-SWEEP\|P-DBG-SWEEP\|P238-RECOV-LEASE\|elected\|foreign replay of\|RECOVERY-COMPLETE' "$OUT/recov_test1.txt" 2>/dev/null | cut -c1-230
  timeout 30 tools/mxfs_sshpass.sh test1 "echo 0 > /sys/module/mxfs/parameters/dbg_sweep_hold_ms" 2>/dev/null
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep2 rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
