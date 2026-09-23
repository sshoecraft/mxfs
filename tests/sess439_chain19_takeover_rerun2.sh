#!/bin/bash
# sess439 chain 19: re-run the radv takeover arm (on whatever chain 17 built —
# 0.43.0 if its BUILD_RC was 0) with the SECOND harness fix: chain 15 s438a
# computed owner_epoch+1 in bash's signed $(( )), which wrapped negative for the
# random u64 11135932352591552525, so setowner refused and no takeover was ever
# provoked (fails=5 were all harness).  The +1 is now done in python mod 2^64.
# Gated on chain 18 DONE.  Budgets: prep ~66 s measured (bound 300), takeover
# ~112 s measured (bound 300), V restart 45 s.
cd /src/mxfs || exit 1
LABEL=${1:-s439a}
LOG=tests/evidence/sess439_chain19_takeover_rerun2_$LABEL.log
EV=tests/evidence/sess439_chain19_takeover_rerun2_$LABEL
GATE=tests/evidence/sess438_chain18_openunlink_deaths_armed_s438d.log
mkdir -p "$EV"
{
  echo "=== sess439 chain19 start $(date -u +%FT%TZ) ==="
  for t in $(seq 1 900); do grep -q '^DONE' "$GATE" 2>/dev/null && break; sleep 10; done
  grep -q '^DONE' "$GATE" || { echo "ABORT: chain18 not DONE"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  echo "gate passed at $(date -u +%FT%TZ) (iter $t) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')"
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep rc=$?"
  timeout 300 tests/d_recov_advance_bounded_verify.sh $LABEL takeover; echo "STAGE radv_takeover rc=$?"
  sleep 45
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep2 rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
