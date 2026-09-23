#!/bin/bash
# sess436 chain 1: D-FOREIGN-SLICE-INTENTS-ABANDONED — first lap of the
# burst arm that can actually leave an open intent.  sess436 measured the
# old 8-file burst at 1.35 s (build 1.53 s) on 0.41.6/test8: the 2 s destroy
# always landed on an idle V (open=0 in sess421/sess423).  The arm now builds
# 48 files (~8 s of frees) and destroys V at 2 s.
#   burst arm  ~115 s derived (see the harness header) -> bound 180 s
#   V restart + prep 32/caw (re-mkfs)  ~130 s measured -> bound 300 s
# NEVER `make modules` before this prints DONE.
cd /src/mxfs || exit 1
LABEL=${1:-s436a}
LOG=tests/evidence/sess436_chain1_intents_burst_$LABEL.log
{
  echo "=== sess436 chain1 start $(date -u +%FT%TZ) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') ==="
  timeout 180 tests/d_intents_undischarged_verify.sh "$LABEL" burst; echo "STAGE intents burst rc=$?"
  sudo virsh -c qemu:///system start test8 >/dev/null 2>&1; echo "STAGE virsh start test8 rc=$?"
  sleep 45
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
