#!/bin/bash
# sess449 chain 68: D-0356 / D-377 departure re-stamp (0.58.0) —
# tests/pr_unregister_fail_restamp.sh on the production build, 2 laps with
# different victims.  Rebuilds + re-preps itself if the tree's mxfs.ko lacks
# the P303 string.  budget: harness bound 300 s (derived in its header);
# build 300; prep 300.  Gated on chain 67 DONE (which ends with a prep).
cd /src/mxfs || exit 1
while ! grep -q "^DONE" tests/evidence/sess449_chain67_d513b_write_eio_s449c.log 2>/dev/null; do sleep 30; done
LABEL=${1:-s449d}
LOG=tests/evidence/sess449_chain68_pr_restamp_$LABEL.log
{
  echo "=== sess449 chain68 start $(date -u +%FT%TZ) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') VERSION=$(cat VERSION) p303=$(strings -a mxfs.ko | grep -c 'P303-RETIRE-PENDING-RESTAMPED') ==="
  if [ "$(strings -a mxfs.ko | grep -c 'P303-RETIRE-PENDING-RESTAMPED')" = 0 ]; then
    T0=$(date +%s); timeout 300 make modules -j8 > tests/evidence/sess449_chain68_build_$LABEL.log 2>&1; echo "STAGE build rc=$? wall=$(( $(date +%s) - T0 ))s sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')"
    timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep rc=$?"
  fi
  for lap in 1 2; do
    victim=$([ "$lap" = 1 ] && echo test2 || echo test11)
    T0=$(date +%s); timeout 300 tests/pr_unregister_fail_restamp.sh 32 "$victim" test1; echo "STAGE pr_restamp lap=$lap victim=$victim rc=$? wall=$(( $(date +%s) - T0 ))s"
  done
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep_after rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
