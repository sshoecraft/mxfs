#!/bin/bash
# sess435 chain 14: the vergate "loop arms" on the SHARED LUN (VG_DEV port,
# sess435) — legacy_refuse, upgrade, mixed_build — because 0.41.3 refuses
# CAW-less devices at admission (D-0359 step 1) and the loop device is one.
# mixed_build on a CAW device is gate item 7 of D-FOREIGN-REPLAY-UNGATED-IMAGES
# / B4 of D-MIXED-VERSION-UNGATED-REPLAY.  Waits for chain 13's DONE.
#   vergate test32 legacy_refuse upgrade mixed_build   ~90 s/arm -> 300 s
#   prep 32/caw (re-mkfs)
# NEVER `make modules` before this prints DONE.
cd /src/mxfs || exit 1
LABEL=${1:-s435g}
LOG=tests/evidence/sess435_chain14_vergate_lun_$LABEL.log
GATE=tests/evidence/sess435_chain13_0414_s435f.log
{
  echo "=== sess435 chain14 start $(date -u +%FT%TZ) ==="
  for t in $(seq 1 600); do grep -q '^DONE' "$GATE" 2>/dev/null && break; sleep 10; done
  grep -q '^DONE' "$GATE" || { echo "ABORT: chain13 not DONE after 6000 s"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  echo "gate passed at $(date -u +%FT%TZ) (iter $t) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')"
MXFS_DEV=${MXFS_DEV:?this chain ran the tcpmp condition, TCP over the multipath LUN: name that LUN with MXFS_DEV (never assumed from a rig path)}
  VG_DEV=$MXFS_DEV timeout 300 tests/vergate.sh test32 legacy_refuse upgrade mixed_build; echo "STAGE vergate_lun rc=$?"
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
