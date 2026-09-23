#!/bin/bash
# sess438 chain 18: the open-unlink death arms with foreign-replay token
# enforcement ARMED (tests/openunlink_deaths.sh now arms it fleet-wide; chain
# 14 s437c measured the enforcement-OFF blanket refusal instead — ledger #1).
# Runs on 0.43.0 (gated on chain 17 DONE).  ~4 min/case (bound 360) +
# rejoin/prep 300 each.
cd /src/mxfs || exit 1
LABEL=${1:-s438d}
LOG=tests/evidence/sess438_chain18_openunlink_deaths_armed_$LABEL.log
EV=tests/evidence/sess438_chain18_openunlink_deaths_armed_$LABEL
GATE=tests/evidence/sess438_chain17_0430_prkey64_verify_s438c.log
VIRSH="sudo virsh -c qemu:///system"
mkdir -p "$EV"
{
  echo "=== sess438 chain18 start $(date -u +%FT%TZ) ==="
  for t in $(seq 1 1200); do grep -q '^DONE' "$GATE" 2>/dev/null && break; sleep 10; done
  grep -q '^DONE' "$GATE" || { echo "ABORT: chain17 not DONE"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  echo "gate passed at $(date -u +%FT%TZ) (iter $t) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')"
  for c in unlinker_death opener_death; do
    timeout 400 tests/openunlink_deaths.sh $c test1 test2 > "$EV/deaths_$c.txt" 2>&1; echo "STAGE deaths_$c rc=$?"; grep -a 'PASS\|FAIL\|RESULT\|forensics\|armed' "$EV/deaths_$c.txt" | tail -8
    for i in 1 2; do $VIRSH start test$i >/dev/null 2>&1; done; sleep 60
    timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep_$c rc=$?"
  done
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
