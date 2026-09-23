#!/bin/bash
# sess461 chain 91: the settle_token_arms matrix chain 83 never ran.  Chain 83
# (tests/sess459_chain83_untokened_gate.sh) aborted at 05:20:27Z on its own
# "srcversion must CHANGE" guard: chain 85 had already built the identical
# 0.61.7 production tree (sv 0C5C1083), so NEW_SV == OLD_SV and the seven
# settle arms + board were skipped.  Chain 87 carries the board; this chain
# carries the arms.  Runs on the PRODUCTION build after chain 90 (the fleet
# is on the chain-89 prod prep); no rebuild — the guard here is that the
# tree's mxfs.ko carries P304-IOCNT-UNTOKENED and the fleet runs the tree.
# budget: prep 300; arms per tests/settle_token_arms.sh header (plain/inval/
# double/latewait 120, slowrace 130, probehang 200, untokened 160).
cd /src/mxfs || exit 1
LABEL=${1:-s461c}
GATE=${GATE:-tests/evidence/sess461_chain90_samenode_s461b.log}
LOG=tests/evidence/sess461_chain91_settle_arms_$LABEL.log
SSH=tools/mxfs_sshpass.sh
while ! grep -q "^DONE" "$GATE" 2>/dev/null; do sleep 30; done
lap() { # <budget_s> <label> <cmd...>
  local b="$1" l="$2"; shift 2
  local T0=$(date +%s)
  timeout "$b" "$@"; echo "STAGE $l rc=$? wall=$(( $(date +%s) - T0 ))s"
}
{
  SV=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  FSV=$(timeout 20 $SSH test1 'cat /sys/module/mxfs/srcversion' 2>/dev/null | grep -aE '^[0-9A-F]{20,}$')
  echo "=== sess461 chain91 START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) sv=$SV fleet_sv=$FSV modinfo_lab=$(modinfo mxfs.ko | grep -c 'mxfs_iclus_relmark_lab') gate_string=$(strings -a mxfs.ko | grep -c 'P304-IOCNT-UNTOKENED') ==="
  if [ "$(strings -a mxfs.ko | grep -c 'P304-IOCNT-UNTOKENED')" = 0 ] || [ "$(modinfo mxfs.ko | grep -c 'mxfs_iclus_relmark_lab')" != 0 ]; then echo "ABORT: tree mxfs.ko is not the production build with the untokened gate"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  if [ "$FSV" != "$SV" ]; then
    echo "fleet sv differs from tree; re-prepping"
  fi
  lap 300 prep ./run.sh 32 caw prep_cluster
  lap 120 "settle arm=plain victim=test3"       tests/settle_token_arms.sh 32 test3  test1 plain
  lap 160 "settle arm=untokened victim=test4"   tests/settle_token_arms.sh 32 test4  test1 untokened
  lap 120 "settle arm=latewait victim=test29"   tests/settle_token_arms.sh 32 test29 test1 latewait
  lap 200 "settle arm=probehang victim=test28"  tests/settle_token_arms.sh 32 test28 test1 probehang
  lap 120 "settle arm=inval victim=test26"      tests/settle_token_arms.sh 32 test26 test1 inval
  lap 120 "settle arm=double victim=test27"     tests/settle_token_arms.sh 32 test27 test1 double
  lap 130 "settle arm=slowrace victim=test30"   tests/settle_token_arms.sh 32 test30 test1 slowrace
  echo "=== settle arms done $(date -u +%FT%TZ) ==="
  grep -a '^STAGE\|PASS @\|FAIL' "$LOG" | tail -20
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
