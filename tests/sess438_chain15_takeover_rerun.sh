#!/bin/bash
# sess438 chain 15: re-run the radv takeover arm on 0.42.0 with the harness
# fix (RNODE was unbound at tests/d_recov_advance_bounded_verify.sh:176 in
# chain 12 s437a, so the arm aborted under set -u AFTER the kernel had already
# taken its own stale incarnation over and published P163-RECOVERY-COMPLETE
# slot=31 at 03:39:30Z; no verdict was produced).  Gated on chain 14 DONE.
# Budgets: prep ~95 s (bound 300), takeover ~200 s (bound 300), V restart 45 s.
cd /src/mxfs || exit 1
LABEL=${1:-s438a}
LOG=tests/evidence/sess438_chain15_takeover_rerun_$LABEL.log
EV=tests/evidence/sess438_chain15_takeover_rerun_$LABEL
GATE=tests/evidence/sess437_chain14_openunlink_deaths_s437c.log
VIRSH="sudo virsh -c qemu:///system"
mkdir -p "$EV"
{
  echo "=== sess438 chain15 start $(date -u +%FT%TZ) ==="
  for t in $(seq 1 900); do grep -q '^DONE' "$GATE" 2>/dev/null && break; sleep 10; done
  grep -q '^DONE' "$GATE" || { echo "ABORT: chain14 not DONE"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  echo "gate passed at $(date -u +%FT%TZ) (iter $t) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')"
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep rc=$?"
  timeout 300 tests/d_recov_advance_bounded_verify.sh $LABEL takeover; echo "STAGE radv_takeover rc=$?"
  sleep 45
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep2 rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
