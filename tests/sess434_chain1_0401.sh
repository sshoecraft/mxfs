#!/bin/bash
# sess434 chain 1 (0.40.1 on the fleet): waits for sess433 chain 4's DONE, then
# runs the board's node_death_replay row — the last verification item named by
# D-0357's record (and D-379's) — and leaves the fleet prepped.
#   node_death_replay   measured 329 s, budget 470 s (+12 s harness +15 s start)
#   prep 32/caw         300 s
# NEVER `make modules` before this prints DONE (the rig insmods the tree's
# mxfs.ko over NFS).
cd /src/mxfs || exit 1
LABEL=${1:-s434a}
LOG=tests/evidence/sess434_chain1_0401_$LABEL.log
{
  echo "=== sess434 chain1 start $(date -u +%FT%TZ) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') ==="
  for t in $(seq 1 90); do grep -q '^DONE' tests/evidence/sess433_chain4_0401_s433e.log 2>/dev/null && break; sleep 10; done
  echo "gate passed at $(date -u +%FT%TZ) (iter $t)"
  timeout 497 ./run.sh 32 caw node_death_replay; echo "STAGE node_death_replay rc=$?"
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
