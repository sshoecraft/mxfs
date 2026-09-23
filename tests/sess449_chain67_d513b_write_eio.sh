#!/bin/bash
# sess449 chain 67: D-FOREIGN-SHADOW-UNWIND-HOST-SHUTDOWN-513B closure arm —
# injected foreign replay-write EIO (survivor must not shut down) + live-write
# control (that mount must shut down).  tests/d513_write_eio_containment.sh
# on the PRODUCTION build; rebuilds + re-preps itself if the tree's mxfs.ko
# lacks the sess449 knob string.  budget: harness bound 300 s (derived in the
# harness header); build 300; prep 300; the run leaves a quarantine and a
# shut-down control mount so it ends with a re-prep.  Two laps with different
# victims.  Gated on chain 66 DONE.
cd /src/mxfs || exit 1
while ! grep -q "^DONE" tests/evidence/sess449_chain66_samenode_s449b.log 2>/dev/null; do sleep 30; done
LABEL=${1:-s449c}
LOG=tests/evidence/sess449_chain67_d513b_write_eio_$LABEL.log
{
  echo "=== sess449 chain67 start $(date -u +%FT%TZ) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') VERSION=$(cat VERSION) knob=$(strings -a mxfs.ko | grep -c 'P227-FR-INJECT-WRITE-EIO') ==="
  if [ "$(strings -a mxfs.ko | grep -c 'P227-FR-INJECT-WRITE-EIO')" = 0 ]; then
    T0=$(date +%s); timeout 300 make modules -j8 > tests/evidence/sess449_chain67_build_$LABEL.log 2>&1; echo "STAGE build rc=$? wall=$(( $(date +%s) - T0 ))s sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')"
    timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep rc=$?"
  fi
  for lap in 1 2; do
    victim=$([ "$lap" = 1 ] && echo test2 || echo test9)
    T0=$(date +%s); timeout 300 tests/d513_write_eio_containment.sh 32 "$victim" test3; echo "STAGE write_eio lap=$lap victim=$victim rc=$? wall=$(( $(date +%s) - T0 ))s"
    timeout 60 sudo virsh -c qemu:///system start "$victim" >/dev/null 2>&1
    sleep 45
    timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep_after_lap$lap rc=$?"
  done
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
