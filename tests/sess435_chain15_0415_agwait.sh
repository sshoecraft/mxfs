#!/bin/bash
# sess435 chain 15: build 0.41.5 (P138-AGWAIT, the AG-class twin of P138-WAIT)
# and attribute the crash_consistency create storm: only 2 P138-WAIT lines
# fired fleet-wide on 0.41.4 while the profile put 26.5% of blocked ticks in
# caw_wait_for_grant -> hypothesis: AG-lock handoff (4 AGs, 8 nodes each).
#   prep; quiet_console; cc_grantwait mark; run.sh crash_consistency (wrapper 160 s:
#   measured single-row startup 37 s + row 90 s + record); cc_grantwait report; prep
# Waits for chain 14's DONE.  NEVER `make modules` before this prints DONE.
cd /src/mxfs || exit 1
LABEL=${1:-s435h}
LOG=tests/evidence/sess435_chain15_0415_agwait_$LABEL.log
EV=tests/evidence/sess435_chain15_0415_agwait_$LABEL
GATE=tests/evidence/sess435_chain14_vergate_lun_s435g.log
mkdir -p "$EV"
{
  echo "=== sess435 chain15 start $(date -u +%FT%TZ) ==="
  for t in $(seq 1 600); do grep -q '^DONE' "$GATE" 2>/dev/null && break; sleep 10; done
  grep -q '^DONE' "$GATE" || { echo "ABORT: chain14 not DONE after 6000 s"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  echo "gate passed at $(date -u +%FT%TZ) (iter $t)"
  OLD=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  timeout 500 make modules > tests/evidence/sess435_build15_$LABEL.txt 2>&1; brc=$?
  timeout 120 make tools >> tests/evidence/sess435_build15_$LABEL.txt 2>&1; trc=$?
  NEW=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  echo "BUILD_RC=$brc TOOLS_RC=$trc VERSION=$(cat VERSION) sv_old=$OLD sv_new=$NEW"
  grep -c 'error:' tests/evidence/sess435_build15_$LABEL.txt | sed 's/^/build errors=/'
  if [ "$brc" -ne 0 ] || [ "$NEW" = "$OLD" ]; then echo "ABORT: build failed or srcversion unchanged"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep rc=$?"
  timeout 60 tests/quiet_console.sh 32 2>/dev/null; echo "STAGE quiet rc=$?"
  timeout 60 tests/cc_grantwait.sh mark 32; echo "STAGE mark rc=$?"
  T0=$(date +%s)
  timeout 160 ./run.sh 32 caw crash_consistency; echo "STAGE cc rc=$? wall=$(( $(date +%s) - T0 ))s"
  ./showstat.sh 32 caw 2>/dev/null | grep -a 'crash_consistency'
  timeout 240 tests/cc_grantwait.sh report 32 > "$EV/grantwait_report.txt" 2>&1; echo "STAGE report rc=$?"
  head -70 "$EV/grantwait_report.txt"
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep_final rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
