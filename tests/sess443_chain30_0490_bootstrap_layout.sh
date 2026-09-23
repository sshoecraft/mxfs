#!/bin/bash
# sess443 chain 30 (0.49.0): item 5f STAGE A — the takeover LAYOUT (docs/
# whole-cluster-restart.md §6.8): PROTO_GEN 17, record v5, 32 KiB region
# (manifest banks by term parity, DIRECT completion tombstones CAW'd before
# every completion bit, lineage, takeover journal), incarnation-scoped dead
# proof, HOLD inject points 11-14, same-boot resume demanding the tombstone.
# No takeover arm yet (stage B).  The measurement: everything that passed on
# 0.48.1 (chain 29) still passes, chk reports 31 DIRECT tombstones and every
# completion bit covered, and P-BOOT-TOMB lines precede the bit CAS.
#   prep                    32/32 regression gate
#   bootstrap_full_restart  item 5 end-to-end
#   prep; bootstrap_resume 3 / 1 / 2
#   prep2
# Budgets as chain 29: build ~3 min (bound 500), tools 120, prep 77-157 s
# (bound 300), full_restart ~1000 s (bound 1080), resume ~1100 s (bound 1260) x3.
cd /src/mxfs || exit 1
# queued behind chain 29 — wait for its DONE before touching mxfs.ko
while ! grep -q "^DONE" tests/evidence/sess442_chain29_0481_bootstrap_resume_s442b.log 2>/dev/null; do sleep 30; done
LABEL=${1:-s443a}
LOG=tests/evidence/sess443_chain30_0490_bootstrap_layout_$LABEL.log
EV=tests/evidence/sess443_chain30_0490_bootstrap_layout_$LABEL
mkdir -p "$EV"
{
  echo "=== sess443 chain30 start $(date -u +%FT%TZ) ==="
  OLD=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  timeout 500 make modules > "$EV/build.txt" 2>&1; brc=$?
  timeout 120 make tools >> "$EV/build.txt" 2>&1; trc=$?
  NEW=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  echo "BUILD_RC=$brc TOOLS_RC=$trc VERSION=$(cat VERSION) sv_old=$OLD sv_new=$NEW"
  echo "build errors=$(grep -c 'error:\|ERROR:' "$EV/build.txt")"
  grep -a 'error:\|ERROR:' "$EV/build.txt" | cut -c1-200 | head -10
  if [ "$brc" -ne 0 ] || [ "$trc" -ne 0 ] || [ "$NEW" = "$OLD" ]; then echo "ABORT: build failed or srcversion unchanged"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  timeout 300 ./run.sh 32 caw prep_cluster; prc=$?; echo "STAGE prep rc=$prc"
  if [ "$prc" -ne 0 ]; then echo "ABORT: prep failed on $(cat VERSION)"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  timeout 1080 tests/bootstrap_full_restart.sh $LABEL 32 test1; echo "STAGE bootstrap_full_restart rc=$?"
  HOST_IMG=$(tools/mxfs_host_image.sh) || { echo "$HOST_IMG"; exit 2; }
  timeout 240 tools/chk_mxfs -v "$HOST_IMG" 2>&1 | grep -a 'bootstrap' | head -8
  for pt in 3 1 2; do
    timeout 300 ./run.sh 32 caw prep_cluster; prc=$?; echo "STAGE prep_before_resume$pt rc=$prc"
    if [ "$prc" -ne 0 ]; then echo "ABORT: prep failed before resume $pt"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
    timeout 1260 tests/bootstrap_resume.sh ${LABEL}p$pt $pt 32 test1; echo "STAGE bootstrap_resume$pt rc=$?"
  done
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep2 rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
