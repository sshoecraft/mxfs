#!/bin/bash
# sess446 chain 44 (0.53.0): the D-0512 disposition lap — item 5f takeover point
# 13, the exact shape that found the defect on chain 35 (0.51.0): the term-2
# takeover owner replayed 23 victim slices then REFUSED slot 24 whose slice held
# the sf->block dir-conversion txn with a voided (class=NONE/INCOMPLETE) token.
# On 0.53.0 (A' re-type re-proof) expect: 32 replays, no REFUSED slot, payload
# 32/32, peers admitted, chk clean; contender dmesg with zero
# 'P227-TOKEN ... class=0 st=6' and zero POLICY-REFUSED lines.
# Also the D-0450 LIVE-OWNER probe (MXFS_TK_LIVE_PROBE=1): the contender must
# refuse to contend while the owner holds and heartbeats (+~180 s).
# budget: prep 79-120 s (300); bootstrap_takeover point 13 (1500+180, derived in
# the harness header); prep2 (300).
cd /src/mxfs || exit 1
while ! grep -q "^DONE" tests/evidence/sess445_chain43_0511_prefetch_ring_s445f.log 2>/dev/null; do sleep 30; done
LABEL=${1:-s446a}
LOG=tests/evidence/sess446_chain44_0512_takeover13_$LABEL.log
{
  echo "=== sess446 chain44 start $(date -u +%FT%TZ) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') VERSION=$(cat VERSION) ==="
  timeout 300 ./run.sh 32 caw prep_cluster; prc=$?; echo "STAGE prep rc=$prc"
  if [ "$prc" -ne 0 ]; then echo "ABORT: prep failed"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  T0=$(date +%s); MXFS_TK_LIVE_PROBE=1 timeout 1700 tests/bootstrap_takeover.sh $LABEL 13 32 test1 test2; echo "STAGE bootstrap_takeover13 rc=$? wall=$(( $(date +%s) - T0 ))s"
  D=$(ls -dt tests/evidence/*_boottakeover13 | head -1); echo "EVIDENCE $D"
  for f in $D/contender_dmesg.txt $D/owner_dmesg.txt; do [ -f $f ] || continue
    echo "TOKENS $(basename $f): classless=$(grep -ac 'P227-TOKEN.*class=0 st=6' $f) refused=$(grep -ac 'POLICY-REFUSED\|REFUSED slot' $f) void=$(grep -ac 'P-AUTHCAP-VOID' $f) retype_ok=$(grep -ac 'P-AUTHCAP-RETYPE-OK' $f) mixed=$(grep -ac 'P-AUTHCAP-RETYPE-MIXED' $f)"
  done
  grep -a 'RECOVERY_COMPLETE\|foreign replay of slot\|bootstrap: REFUSED' $D/contender_dmesg.txt 2>/dev/null | tail -5 | cut -c1-160
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep2 rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
