#!/bin/bash
# sess436 chain 9: build 0.41.9 (disklock zero-epoch guard), deploy, rerun the
# zero-epoch arm (post-restore leg must now recover), then the open-unlink
# functional matrix and its two death arms.  Gated on chain 8.
#   build ~3 min; prep 300; zeroinc 300; matrix <420 (bound 480); deaths ~240/case (bound 360)
cd /src/mxfs || exit 1
LABEL=${1:-s436i}
LOG=tests/evidence/sess436_chain9_0419_zeroinc_openunlink_$LABEL.log
EV=tests/evidence/sess436_chain9_0419_zeroinc_openunlink_$LABEL
GATE=tests/evidence/sess436_chain8_ubsweep_clean_s436h.log
VIRSH="sudo virsh -c qemu:///system"
mkdir -p "$EV"
{
  echo "=== sess436 chain9 start $(date -u +%FT%TZ) ==="
  for t in $(seq 1 900); do grep -q '^DONE' "$GATE" 2>/dev/null && break; sleep 10; done
  grep -q '^DONE' "$GATE" || { echo "ABORT: chain8 not DONE"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  echo "gate passed at $(date -u +%FT%TZ) (iter $t)"
  OLD=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  timeout 500 make modules > "$EV/build.txt" 2>&1; brc=$?
  timeout 120 make tools >> "$EV/build.txt" 2>&1; trc=$?
  NEW=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  echo "BUILD_RC=$brc TOOLS_RC=$trc VERSION=$(cat VERSION) sv_old=$OLD sv_new=$NEW"
  grep -c 'error:' "$EV/build.txt" | sed 's/^/build errors=/'
  if [ "$brc" -ne 0 ] || [ "$NEW" = "$OLD" ]; then echo "ABORT: build failed or srcversion unchanged"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep rc=$?"
  timeout 300 tests/d_recov_zero_epoch_verify.sh $LABEL; echo "STAGE zeroinc rc=$?"
  $VIRSH start test8 >/dev/null 2>&1; sleep 45
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep2 rc=$?"
  timeout 480 tests/openunlink_matrix.sh test1 test2 test3 > "$EV/matrix.txt" 2>&1; echo "STAGE matrix rc=$?"; grep -a 'PASS\|FAIL\|RESULT' "$EV/matrix.txt" | tail -20
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep3 rc=$?"
  for c in unlinker_death opener_death; do
    timeout 360 tests/openunlink_deaths.sh $c test1 test2 > "$EV/deaths_$c.txt" 2>&1; echo "STAGE deaths_$c rc=$?"; grep -a 'PASS\|FAIL\|RESULT' "$EV/deaths_$c.txt" | tail -8
    for i in 1 2; do $VIRSH start test$i >/dev/null 2>&1; done; sleep 60
    timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep_$c rc=$?"
  done
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
