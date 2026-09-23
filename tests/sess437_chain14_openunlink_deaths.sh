#!/bin/bash
# sess437 chain 14: rerun the open-unlink death arms with the sess437 forensics
# capture (A's holder state + kernel journal saved under tests/evidence/oud_*
# BEFORE any prep can power-cycle A).  Gated on chain 13.  ~4 min/case (bound
# 360) + rejoin/prep 300 each.
cd /src/mxfs || exit 1
LABEL=${1:-s437c}
LOG=tests/evidence/sess437_chain14_openunlink_deaths_$LABEL.log
EV=tests/evidence/sess437_chain14_openunlink_deaths_$LABEL
GATE=tests/evidence/sess437_chain13_handoff_anatomy_s437b.log
VIRSH="sudo virsh -c qemu:///system"
mkdir -p "$EV"
{
  echo "=== sess437 chain14 start $(date -u +%FT%TZ) ==="
  for t in $(seq 1 900); do grep -q '^DONE' "$GATE" 2>/dev/null && break; sleep 10; done
  grep -q '^DONE' "$GATE" || { echo "ABORT: chain13 not DONE"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  echo "gate passed at $(date -u +%FT%TZ) (iter $t) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')"
  for c in unlinker_death opener_death; do
    timeout 360 tests/openunlink_deaths.sh $c test1 test2 > "$EV/deaths_$c.txt" 2>&1; echo "STAGE deaths_$c rc=$?"; grep -a 'PASS\|FAIL\|RESULT\|forensics' "$EV/deaths_$c.txt" | tail -8
    for i in 1 2; do $VIRSH start test$i >/dev/null 2>&1; done; sleep 60
    timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep_$c rc=$?"
  done
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
