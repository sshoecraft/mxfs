#!/bin/bash
# sess445 chain 43 (0.53.0; chain 40 aborted on the run.sh lock of a killed chain-39 prep): D-0511 second measurement —
# the stability-proof prefetch RING (fr_stab_prefetch = depth 3).  Chain 36
# on 0.52.0 measured the purge batch (scan 175 ms p50) but the single-entry
# prefetch never engaged (1/31 prefetched, 143 s of serial 4.6 s proofs).
# Expect: P-FRSTAB-STABLE prefetched=1 on ~30/31 slices, foreign-replay
# phase ~60 s, mount wall ~200 s (bound 540 unchanged until measured).
# budget: prep 79-120 s (300); bootstrap_full_restart (1080); prep; run.sh
# node_death_replay (row 470 + 27 -> 500); prep2.
cd /src/mxfs || exit 1
while ! grep -q "^DONE" tests/evidence/sess445_chain42_0512_Aprime_arms_s445e.log 2>/dev/null; do sleep 30; done
LABEL=${1:-s445f}
LOG=tests/evidence/sess445_chain43_0511_prefetch_ring_$LABEL.log
{
  echo "=== sess445 chain40 start $(date -u +%FT%TZ) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') VERSION=$(cat VERSION) ==="
  strings mxfs.ko | grep -q 'inflight=%d depth=%d' && echo "probe: prefetch ring present" || { echo "ABORT: mxfs.ko lacks the prefetch ring (chain 39 build?)"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  timeout 300 ./run.sh 32 caw prep_cluster; prc=$?; echo "STAGE prep rc=$prc"
  if [ "$prc" -ne 0 ]; then echo "ABORT: prep failed"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  timeout 1080 tests/bootstrap_full_restart.sh $LABEL 32 test1; echo "STAGE bootstrap_full_restart rc=$?"
  D=$(ls -dt tests/evidence/*_bootfull | head -1)
  echo "RING: prefetched=$(grep -ac 'prefetched=1' $D/remounter_dmesg.txt) inline=$(grep -a 'P-FRSTAB-STABLE' $D/remounter_dmesg.txt | grep -vc 'prefetched=1') failed=$(grep -ac 'P-FRSTAB-PREFETCH-FAILED\|P-FRSTAB-ALLOC' $D/remounter_dmesg.txt)"
  grep -a 'P-FRSTAB-STABLE' $D/remounter_dmesg.txt | grep -o 'waited_ms=[0-9]*' | cut -d= -f2 | sort -n | awk '{a[NR]=$1;s+=$1} END{print "RING waited_ms n="NR" p50="a[int(NR/2)+1]" max="a[NR]" sum="s}'
  grep -a 'foreign replay of dead slot 1 \|foreign replay of slot 31 complete' $D/remounter_dmesg.txt | cut -c1-80
  timeout 300 ./run.sh 32 caw prep_cluster; prc=$?; echo "STAGE prep_before_ndr rc=$prc"
  if [ "$prc" -eq 0 ]; then T0=$(date +%s); timeout 500 ./run.sh 32 caw node_death_replay; echo "STAGE node_death_replay rc=$? wall=$(( $(date +%s) - T0 ))s"; fi
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep2 rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
