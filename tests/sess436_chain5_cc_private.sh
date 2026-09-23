#!/bin/bash
# sess436 chain 5: design-consult ruling measurement 5 (headroom) — crash_consistency
# with CC_PRIVATE=1 (one private subdir per node) vs the shared-dir control,
# both on 0.41.8 at 32/caw with the P138 journal capture.  Gated on chain 4.
#   per leg: prep ~130 s (300) + cc row 37 s startup + 90 s budget (160) + sweep
cd /src/mxfs || exit 1
LABEL=${1:-s436e}
LOG=tests/evidence/sess436_chain5_cc_private_$LABEL.log
EV=tests/evidence/sess436_chain5_cc_private_$LABEL
GATE=tests/evidence/sess436_chain4_intents_laps_s436d.log
mkdir -p "$EV"
{
  echo "=== sess436 chain5 start $(date -u +%FT%TZ) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') ==="
  for t in $(seq 1 600); do grep -q '^DONE' "$GATE" 2>/dev/null && break; sleep 10; done
  grep -q '^DONE' "$GATE" || { echo "ABORT: chain4 not DONE"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  echo "gate passed at $(date -u +%FT%TZ) (iter $t)"
  for leg in private shared; do
    timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep_$leg rc=$?"
    T0=$(date -u '+%Y-%m-%d %H:%M:%S')
    if [ "$leg" = private ]; then MXFS_TEST_ENV="CC_PRIVATE=1" timeout 160 ./run.sh 32 caw crash_consistency; else timeout 160 ./run.sh 32 caw crash_consistency; fi
    echo "STAGE cc_$leg rc=$?"
    D="$EV/$leg"; mkdir -p "$D"
    for i in $(seq 1 32); do
      ( timeout 25 tools/mxfs_sshpass.sh test$i "journalctl -k --since '$T0' --utc -o short-precise | grep -aE 'P138-ACQ |P138-BAST|P138-ACQSUM|mxfs-CCph rank='" > "$D/test$i.log" 2>/dev/null; echo "test$i rc=$?" >> "$D/rc.txt" ) &
    done
    wait
    python3 tests/cc_tenure_modesplit.py "$D" > "$D/report.txt" 2>&1
    python3 tests/cc_phase_walls.py "$D" > "$D/phase_walls.txt" 2>&1
    echo "$leg acqsum_inode(test9): $(grep -ah 'P138-ACQSUM type=1 ' "$D"/test9.log | tail -1 | cut -c1-160)"
    grep -aE 'ACQ target|^  mode=[35]: n=' "$D/report.txt" | sed "s/^/$leg /"
  done
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep_final rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
