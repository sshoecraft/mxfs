#!/bin/bash
# dialloc_validate_ab.sh — the instrumented A/B for the D-0351 dialloc containment
# on ONE build (0.39.4+, mxfs.dialloc_validate knob):
#   arm 0 (knob off = pre-containment allocator): tests/dialloc_disklive_inject.sh
#     must FAIL — the cache-miss create of a planted DISK-LIVE number ends in
#     P-CR62 DISK-LIVE + a dirty xfs_trans_cancel + node shutdown;
#   prep (recovers the shut-down node);
#   arm 1 (knob on): the same injector must PASS — P-DIALLOC-DISKLIVE, no
#     shutdown, creates succeed, X never handed out.
# Verdict: PASS iff arm 0 FAILED with a DISK-LIVE/shutdown signature on the
# node AND arm 1 PASSED.  (An arm 0 that passes means the measurement did not
# exercise the fault — reported as FAIL, never as "fixed".)
#
#   tests/dialloc_validate_ab.sh <label> [node=test3] [peer=test4]
# Budget (budget): 2 x injector (<= 60 s each) + prep 300 s.
set -u
LABEL=${1:?label}; NODE=${2:-test3}; PEER=${3:-test4}
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd); cd "$REPO"
E=tests/evidence
fails=0
echo "=== dialloc_validate_ab label=$LABEL node=$NODE peer=$PEER $(date -u +%FT%TZ) ==="
MXFS_DIALLOC_VALIDATE=0 timeout 180 tests/dialloc_disklive_inject.sh "${LABEL}k0" "$NODE" "$PEER" 16 > "$E/ab_${LABEL}_k0.txt" 2>&1; rc0=$?
out0=$(grep -ao 'out=tests/evidence/[^ ]*' "$E/ab_${LABEL}_k0.txt" | tail -1 | cut -d= -f2)
sig0=$(cat "$out0/dmesg_$NODE.txt" 2>/dev/null | grep -ac 'P-CR62 .*DISK-LIVE\|P-CR63-DEFER-DISKLIVE\|Filesystem has been shut down\|xfs_do_force_shutdown')
gotx0=$(grep -ao 'receiving the DISK-LIVE number X=[0-9]* got=[0-9]*' "$E/ab_${LABEL}_k0.txt" | grep -ao 'got=[0-9]*' | cut -d= -f2)
echo "  INFO arm0 (knob off) rc=$rc0 disklive_or_shutdown_signatures=$sig0 X_handed_out=${gotx0:-?} out=$out0"
# sess431: the pre-containment defect has TWO measured shapes — the loud one
# (P-CR62 DISK-LIVE / shutdown signatures) and the SILENT one (s438 arm0 on
# 0.39.4: X was handed out to a created file with zero errors and no
# shutdown, i.e. the live platter dinode was clobbered by the create).  Either
# is the defect; the arm only fails to reproduce when NEITHER appears.
if [ "$rc0" -ne 0 ] && { [ "${sig0:-0}" -gt 0 ] || [ "${gotx0:-0}" -gt 0 ]; }; then echo "  PASS arm0 reproduced the pre-containment failure (sig=$sig0 X_handed_out=$gotx0)"; else echo "  FAIL arm0 did not reproduce the pre-containment failure (rc=$rc0 sig=$sig0 X_handed_out=${gotx0:-?})"; fails=$((fails+1)); fi
timeout 300 ./run.sh 32 caw prep_cluster > "$E/ab_${LABEL}_prep.log" 2>&1; prc=$?
echo "  INFO prep rc=$prc"
[ $prc -eq 0 ] || { echo "  FAIL prep after arm0 failed"; fails=$((fails+1)); }
MXFS_DIALLOC_VALIDATE=1 timeout 180 tests/dialloc_disklive_inject.sh "${LABEL}k1" "$NODE" "$PEER" 16 > "$E/ab_${LABEL}_k1.txt" 2>&1; rc1=$?
out1=$(grep -ao 'out=tests/evidence/[^ ]*' "$E/ab_${LABEL}_k1.txt" | tail -1 | cut -d= -f2)
dl1=$(grep -ao 'P-DIALLOC-DISKLIVE for X: [0-9]*' "$E/ab_${LABEL}_k1.txt" | grep -ao '[0-9]*$')
echo "  INFO arm1 (knob on) rc=$rc1 P-DIALLOC-DISKLIVE=$dl1 out=$out1"
if [ "$rc1" -eq 0 ] && [ "${dl1:-0}" -gt 0 ]; then echo "  PASS arm1 contained the fault"; else echo "  FAIL arm1 (rc=$rc1 disklive=$dl1)"; fails=$((fails+1)); fi
grep -a '^  \(PASS\|FAIL\|WARN\)' "$E/ab_${LABEL}_k0.txt" | sed 's/^/  arm0: /'
grep -a '^  \(PASS\|FAIL\|WARN\)' "$E/ab_${LABEL}_k1.txt" | sed 's/^/  arm1: /'
echo "=== dialloc_validate_ab RESULT $([ $fails -eq 0 ] && echo PASS || echo FAIL) fails=$fails ==="
[ $fails -eq 0 ]
