#!/bin/bash
# sess436 chain 3: build 0.41.8 (census pre-verdict pass), deploy, burst arm
# lap, prep.  Gated on chain 2's DONE (never rebuild under a live rig run).
#   build ~3 min; prep ~130 s (bound 300); burst arm ~115 s (bound 180).
cd /src/mxfs || exit 1
LABEL=${1:-s436c}
LOG=tests/evidence/sess436_chain3_0418_intents_$LABEL.log
EV=tests/evidence/sess436_chain3_0418_intents_$LABEL
GATE=tests/evidence/sess436_chain2_0417_intents_mht_s436b.log
mkdir -p "$EV"
{
  echo "=== sess436 chain3 start $(date -u +%FT%TZ) ==="
  for t in $(seq 1 600); do grep -q '^DONE' "$GATE" 2>/dev/null && break; sleep 10; done
  grep -q '^DONE' "$GATE" || { echo "ABORT: chain2 not DONE after 6000 s"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  echo "gate passed at $(date -u +%FT%TZ) (iter $t)"
  OLD=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  timeout 500 make modules > "$EV/build.txt" 2>&1; brc=$?
  timeout 120 make tools >> "$EV/build.txt" 2>&1; trc=$?
  NEW=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  echo "BUILD_RC=$brc TOOLS_RC=$trc VERSION=$(cat VERSION) sv_old=$OLD sv_new=$NEW"
  grep -c 'error:' "$EV/build.txt" | sed 's/^/build errors=/'
  if [ "$brc" -ne 0 ] || [ "$NEW" = "$OLD" ]; then echo "ABORT: build failed or srcversion unchanged"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep rc=$?"
  timeout 180 tests/d_intents_undischarged_verify.sh "$LABEL" burst; echo "STAGE intents burst rc=$?"
  sudo virsh -c qemu:///system start test8 >/dev/null 2>&1
  sleep 45
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep2 rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
