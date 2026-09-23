#!/bin/bash
# sess435 chain 10: D-CRASH-CONSISTENCY-FLEETWIDE-BARRIER-TIMEOUT-401 /
# D-32NODE-SHARED-DIR-CREATE-PACE measurement on 0.41.2 — the crash_consistency
# row under the wall-clock kernel stack profiler (tests/cc_stackprof.sh), so the
# blocked wall is attributed to stacks (find_slot_skip caller chains, grant
# poll, BAST thread) rather than guessed.  Waits for chain 9's DONE.
#   prep 32/caw                       300 s
#   cc_stackprof start 110 s on 32    ~20 s deploy
#   run.sh 32 caw crash_consistency   row budget 90 s + 12 s overhead + 15 s startup = 117 s
#   cc_stackprof agg                  ~60 s
#   prep 32/caw
# NEVER `make modules` before this prints DONE.
cd /src/mxfs || exit 1
LABEL=${1:-s435c}
LOG=tests/evidence/sess435_chain10_ccprof_$LABEL.log
EV=tests/evidence/sess435_ccprof_$LABEL
GATE=tests/evidence/sess435_chain9_rman_vergate_s435b.log
mkdir -p "$EV"
{
  echo "=== sess435 chain10 start $(date -u +%FT%TZ) ==="
  for t in $(seq 1 420); do grep -q '^DONE' "$GATE" 2>/dev/null && break; sleep 10; done
  grep -q '^DONE' "$GATE" || { echo "ABORT: chain9 not DONE after 4200 s"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  echo "gate passed at $(date -u +%FT%TZ) (iter $t) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')"
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep rc=$?"
  timeout 60 tests/quiet_console.sh 32 2>/dev/null; echo "STAGE quiet rc=$?"
  timeout 60 tests/cc_stackprof.sh start 110 32; echo "STAGE prof_start rc=$?"
  timeout 130 ./run.sh 32 caw crash_consistency; echo "STAGE cc rc=$?"
  ./showstat.sh 32 caw 2>/dev/null | grep -a 'crash_consistency'
  timeout 120 tests/cc_stackprof.sh agg 32 > "$EV/agg.txt" 2>&1; echo "STAGE prof_agg rc=$?"
  head -80 "$EV/agg.txt"
  timeout 120 tests/cc_stackprof.sh harvest 32 > "$EV/harvest.txt" 2>&1; echo "STAGE prof_harvest rc=$?"
  D=$(mktemp -d)
  for i in $(seq 1 32); do
    ( timeout 30 tools/mxfs_sshpass.sh test$i "cat /proc/net/snmp | grep -A1 '^Udp:' | tail -1; dmesg | grep -a 'mxfs-CCph' | tail -9" > "$D/test$i.txt" 2>/dev/null ) &
  done
  wait
  cp -r "$D" "$EV/nodes"
  for i in 1 2 17 32; do echo "-- test$i"; cat "$D/test$i.txt"; done
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep2 rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
