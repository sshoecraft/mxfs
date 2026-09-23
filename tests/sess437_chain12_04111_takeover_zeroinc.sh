#!/bin/bash
# sess437 chain 12: build 0.42.0 (incarnation-tuple owner liveness in
# mxfs_v5_dlm_recovery_acquire + same-node/new-epoch takeover; zero-epoch:
# hb_still_dead_stamp keeps the barrier on an INVALID same-node epoch and the
# replayer re-drives a never-landed fence), deploy, then the two arms that
# failed on 0.41.8/0.41.10:
#   radv takeover arm  (tests/d_recov_advance_bounded_verify.sh, bound 150 s + 62 s death)
#   zero-epoch arm     (tests/d_recov_zero_epoch_verify.sh, caller bound 300 s)
# Gated on chain 11 printing DONE.  Budgets: build ~3 min (bound 500), prep
# ~95 s (bound 300), takeover ~200 s (bound 300), zeroinc ~205 s (bound 300).
cd /src/mxfs || exit 1
LABEL=${1:-s437a}
LOG=tests/evidence/sess437_chain12_04111_takeover_zeroinc_$LABEL.log
EV=tests/evidence/sess437_chain12_04111_takeover_zeroinc_$LABEL
GATE=tests/evidence/sess436_chain11_fln_churn_s436k.log
VIRSH="sudo virsh -c qemu:///system"
mkdir -p "$EV"
{
  echo "=== sess437 chain12 start $(date -u +%FT%TZ) ==="
  for t in $(seq 1 900); do grep -q '^DONE' "$GATE" 2>/dev/null && break; sleep 10; done
  grep -q '^DONE' "$GATE" || { echo "ABORT: chain11 not DONE"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  echo "gate passed at $(date -u +%FT%TZ) (iter $t)"
  OLD=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  timeout 500 make modules > "$EV/build.txt" 2>&1; brc=$?
  timeout 120 make tools >> "$EV/build.txt" 2>&1; trc=$?
  NEW=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  echo "BUILD_RC=$brc TOOLS_RC=$trc VERSION=$(cat VERSION) sv_old=$OLD sv_new=$NEW"
  grep -c 'error:' "$EV/build.txt" | sed 's/^/build errors=/'
  if [ "$brc" -ne 0 ] || [ "$NEW" = "$OLD" ]; then echo "ABORT: build failed or srcversion unchanged"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep rc=$?"
  timeout 300 tests/d_recov_advance_bounded_verify.sh $LABEL takeover; echo "STAGE radv_takeover rc=$?"
  $VIRSH start test8 >/dev/null 2>&1; sleep 45
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep2 rc=$?"
  timeout 300 tests/d_recov_zero_epoch_verify.sh $LABEL; echo "STAGE zeroinc rc=$?"
  $VIRSH start test8 >/dev/null 2>&1; sleep 45
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep3 rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
