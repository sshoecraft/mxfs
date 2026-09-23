#!/bin/bash
# sess443 chain 31 (0.50.0): item 5f STAGE B — the takeover ARM (docs/
# whole-cluster-restart.md §6.8): contender election on the takeover journal,
# fence of the old owner (slotless P&A here: hold points 11/12 = before K is
# adopted), validated inheritance of T's sealed manifest, INHERITED
# tombstones, lineage entry, reseal as T+1, then the ordinary phase 3 /
# adoption / replay under T+1.  Points 13/14 (old owner on K) need the
# composite K replay (stage C) and run in a later chain.
#   prep                      32/32 regression gate (no rebuild: chain 30 built 0.50.0)
#   bootstrap_takeover 11     owner destroyed after phase 3 (escrow NONE)
#   prep
#   bootstrap_takeover 12     owner destroyed after PREPARED (K still guarded)
#   prep2
# Budgets: prep 77-157 s (bound 300); takeover ~1300 s (bound 1500) x2 —
# the contender's phase 3 re-leases 31 descriptors owned by the fenced
# owner's incarnation at ~6 s each (MXFS_RECOV_ABANDON_MS re-proof).
cd /src/mxfs || exit 1
# queued behind chain 30 — wait for its DONE (it built 0.50.0)
while ! grep -q "^DONE" tests/evidence/sess443_chain30_0490_bootstrap_layout_s443a.log 2>/dev/null; do sleep 30; done
LABEL=${1:-s443b}
LOG=tests/evidence/sess443_chain31_0500_bootstrap_takeover_$LABEL.log
EV=tests/evidence/sess443_chain31_0500_bootstrap_takeover_$LABEL
mkdir -p "$EV"
{
  echo "=== sess443 chain31 start $(date -u +%FT%TZ) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') VERSION=$(cat VERSION) ==="
  if grep -q '^ABORT' tests/evidence/sess443_chain30_0490_bootstrap_layout_s443a.log; then echo "ABORT: chain 30 aborted (no 0.50.0 build to measure)"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  for pt in 11 12; do
    timeout 300 ./run.sh 32 caw prep_cluster; prc=$?; echo "STAGE prep_before_takeover$pt rc=$prc"
    if [ "$prc" -ne 0 ]; then echo "ABORT: prep failed before takeover $pt"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
    timeout 1500 tests/bootstrap_takeover.sh ${LABEL}t$pt $pt 32 test1 test2; echo "STAGE bootstrap_takeover$pt rc=$?"
  done
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep2 rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
