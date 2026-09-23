#!/bin/bash
# sess444 chain 32 (0.51.0): D-ICREATE-REPLAY-REINIT-CLOBBERS-PEER-INODES-0510
# fix — SYNCINIT invariant + writer-time ICREATE trailer + verify-and-skip
# replay + AG-sibling ICREATE verdict (P-ICREATE-AUTH / -VERIFIED / -REFUSE).
# The measurement: the bootstrap legs that ended on ONE terminal slice with
# nonbuf_taint=1 on 0.48.1/0.50.0 (chains 29/30) must now reach
# RECOVERY_COMPLETE with every slice's create txn APPLY'd and its ICREATE
# verified-and-skipped (nothing written).
#   build 0.51.0 (bound 500) + tools (120)
#   prep                    32/32 regression gate (bound 300)
#   bootstrap_full_restart  (bound 1080)
#   prep; bootstrap_resume 3 (bound 1260)
#   prep2
cd /src/mxfs || exit 1
# queued behind chain 31 — never rebuild mxfs.ko while a rig run is in flight
while ! grep -q "^DONE" tests/evidence/sess443_chain31_0500_bootstrap_takeover_s443b.log 2>/dev/null; do sleep 30; done
LABEL=${1:-s444a}
LOG=tests/evidence/sess444_chain32_0510_icreate_syncinit_$LABEL.log
EV=tests/evidence/sess444_chain32_0510_icreate_syncinit_$LABEL
mkdir -p "$EV"
{
  echo "=== sess444 chain32 start $(date -u +%FT%TZ) ==="
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
  timeout 300 ./run.sh 32 caw prep_cluster; prc=$?; echo "STAGE prep_before_resume3 rc=$prc"
  if [ "$prc" -ne 0 ]; then echo "ABORT: prep failed before resume 3"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  timeout 1260 tests/bootstrap_resume.sh ${LABEL}p3 3 32 test1; echo "STAGE bootstrap_resume3 rc=$?"
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep2 rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
