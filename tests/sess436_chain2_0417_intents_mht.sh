#!/bin/bash
# sess436 chain 2: build 0.41.7 (dbg_efd_hold_ms knob), deploy, run the
# deterministic intents burst arm, then the design-consult ruling's measurement 3
# (inode_mht_ms sweep) on crash_consistency at 32/caw.
#   build ~3 min; prep ~130 s (bound 300); burst arm ~115 s (bound 180);
#   per MHT value: prep + params + cc row (37 s startup + 90 s budget ->
#   wrapper 160 s) + journal sweep ~20 s.
# NEVER `make modules` again before this prints DONE.
cd /src/mxfs || exit 1
LABEL=${1:-s436b}
LOG=tests/evidence/sess436_chain2_0417_intents_mht_$LABEL.log
EV=tests/evidence/sess436_chain2_0417_intents_mht_$LABEL
mkdir -p "$EV"
{
  echo "=== sess436 chain2 start $(date -u +%FT%TZ) ==="
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
  for mht in 0 10 50 300; do
    timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep_mht$mht rc=$?"
    timeout 60 tests/fleet_set_params.sh "inode_mht_ms=$mht" 32 "$EV/knobs_mht$mht.txt"; echo "STAGE params_mht$mht rc=$?"
    T0=$(date -u '+%Y-%m-%d %H:%M:%S')
    timeout 160 ./run.sh 32 caw crash_consistency; echo "STAGE cc_mht$mht rc=$? wall=$(( $(date +%s) - $(date -d "$T0" +%s) ))s"
    D="$EV/mht$mht"; mkdir -p "$D"
    for i in $(seq 1 32); do
      ( timeout 25 tools/mxfs_sshpass.sh test$i "journalctl -k --since '$T0' --utc -o short-precise | grep -aE 'P138-ACQ |P138-BAST|P138-ACQSUM|mxfs-CCph rank='" > "$D/test$i.log" 2>/dev/null; echo "test$i rc=$?" >> "$D/rc.txt" ) &
    done
    wait
    python3 tests/cc_tenure_modesplit.py "$D" > "$D/report.txt" 2>&1
    echo "mht=$mht acqsum_inode: $(grep -ah 'P138-ACQSUM type=1 ' "$D"/test*.log | tail -1 | cut -c1-160)"
    grep -aE '^  mode=[35]: n=' "$D/report.txt" | head -2 | sed "s/^/mht=$mht elapsed /"
    grep -a 'gaps between consecutive mode=5' "$D/report.txt" | sed "s/^/mht=$mht /"
    grep -a 'handoff dead time' "$D/report.txt" | sed "s/^/mht=$mht /"
  done
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep_final rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
