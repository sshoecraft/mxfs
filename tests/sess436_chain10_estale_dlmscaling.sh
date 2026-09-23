#!/bin/bash
# sess436 chain 10: (a) D-RECREATED-SHARED-DIR-PEER-MKDIR-ESTALE-0346 step 1:
# tests/dir_recreate_estale.sh x2 (bound 60 each); (b) D-DLMSCALING-380:
# loop dlm_scaling at 32/caw 5 laps, keeping the journals (journalctl, not
# the ring) and sweeping for the DSCAN-MISS/EUCLEAN face after a FAIL.
# Gated on chain 9.  Per dlm_scaling row: 37 s startup + manifest budget.
cd /src/mxfs || exit 1
LABEL=${1:-s436j}
LOG=tests/evidence/sess436_chain10_estale_dlmscaling_$LABEL.log
EV=tests/evidence/sess436_chain10_estale_dlmscaling_$LABEL
GATE=tests/evidence/sess436_chain9_0419_zeroinc_openunlink_s436i.log
mkdir -p "$EV"
B=$(awk '$2=="dlm_scaling"{print $5}' tests/suite/manifest | head -1); [ -n "$B" ] || B=60
{
  echo "=== sess436 chain10 start $(date -u +%FT%TZ) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') dlm_scaling budget=$B ==="
  for t in $(seq 1 900); do grep -q '^DONE' "$GATE" 2>/dev/null && break; sleep 10; done
  grep -q '^DONE' "$GATE" || { echo "ABORT: chain9 not DONE"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  echo "gate passed at $(date -u +%FT%TZ) (iter $t)"
  for lap in 1 2; do timeout 60 tests/dir_recreate_estale.sh ${LABEL}e$lap test1 test2 test3 test4 20 250 > "$EV/estale$lap.txt" 2>&1; echo "STAGE estale$lap rc=$?"; grep -a 'PASS\|FAIL\|P34H' "$EV/estale$lap.txt" | tail -6 | cut -c1-200; done
  for lap in 1 2 3 4 5; do
    T0=$(date -u '+%Y-%m-%d %H:%M:%S')
    timeout $(( B + 60 )) ./run.sh 32 caw dlm_scaling > "$EV/dlm_scaling$lap.txt" 2>&1; rc=$?
    line=$(grep -a '  dlm_scaling  ' "$EV/dlm_scaling$lap.txt" | tail -1 | cut -c1-160)
    echo "STAGE dlm_scaling$lap rc=$rc :: $line"
    if echo "$line" | grep -aq FAIL; then
      D="$EV/lap$lap"; mkdir -p "$D"
      for i in $(seq 1 32); do ( timeout 25 tools/mxfs_sshpass.sh test$i "journalctl -k --since '$T0' --utc -o short-precise | grep -aE 'DSCAN-MISS|EUCLEAN|shutdown|P26-|P33-|forced' | head -400" > "$D/test$i.log" 2>/dev/null ) & done; wait
      echo "  swept: $(cat "$D"/test*.log | grep -ac 'DSCAN-MISS') DSCAN-MISS, $(cat "$D"/test*.log | grep -aci 'euclean\|forced shutdown\|force_shutdown') shutdown-ish lines"
      break
    fi
  done
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep_final rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
