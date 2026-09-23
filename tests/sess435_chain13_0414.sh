#!/bin/bash
# sess435 chain 13: build 0.41.4 (D-PURGE-NONATOMIC reporting fixes: P234 owner
# %u, mid-scan refreeze -> P229 via purge_done), then:
#   prep; d_purge_nonatomic_verify concurrent (200 s)      expect 15/15
#   prep; d_purge_nonatomic_verify midscan    (200 s)      expect 11/11
#   prep; cc_grantwait mark; crash_consistency row (117 s); cc_grantwait report
#         -> P138-WAIT per-grant attribution for D-32NODE-SHARED-DIR-CREATE-PACE
#            (P138 is unconditional, 4000/boot cap — no instr, per the harness)
#   prep
# Waits for chain 12's DONE.  NEVER `make modules` before this prints DONE.
cd /src/mxfs || exit 1
LABEL=${1:-s435f}
LOG=tests/evidence/sess435_chain13_0414_$LABEL.log
EV=tests/evidence/sess435_chain13_0414_$LABEL
GATE=tests/evidence/sess435_chain12_0413_s435e.log
mkdir -p "$EV"
{
  echo "=== sess435 chain13 start $(date -u +%FT%TZ) ==="
  for t in $(seq 1 600); do grep -q '^DONE' "$GATE" 2>/dev/null && break; sleep 10; done
  grep -q '^DONE' "$GATE" || { echo "ABORT: chain12 not DONE after 6000 s"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  echo "gate passed at $(date -u +%FT%TZ) (iter $t)"
  OLD=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  timeout 500 make modules > tests/evidence/sess435_build13_$LABEL.txt 2>&1; brc=$?
  timeout 120 make tools >> tests/evidence/sess435_build13_$LABEL.txt 2>&1; trc=$?
  NEW=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  echo "BUILD_RC=$brc TOOLS_RC=$trc VERSION=$(cat VERSION) sv_old=$OLD sv_new=$NEW"
  grep -c 'error:' tests/evidence/sess435_build13_$LABEL.txt | sed 's/^/build errors=/'
  if [ "$brc" -ne 0 ] || [ "$NEW" = "$OLD" ]; then echo "ABORT: build failed or srcversion unchanged"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  for arm in concurrent midscan; do
    for t in $(seq 1 20); do timeout 10 tools/mxfs_sshpass.sh test8 "uptime" >/dev/null 2>&1 && break; sleep 10; done
    timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep_$arm rc=$?"
    timeout 200 tests/d_purge_nonatomic_verify.sh ${LABEL}_$arm $arm; echo "STAGE $arm rc=$?"
  done
  for t in $(seq 1 20); do timeout 10 tools/mxfs_sshpass.sh test8 "uptime" >/dev/null 2>&1 && break; sleep 10; done
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep_cc rc=$?"
  timeout 60 tests/quiet_console.sh 32 2>/dev/null; echo "STAGE quiet rc=$?"
  timeout 60 tests/cc_grantwait.sh mark 32; echo "STAGE mark rc=$?"
  timeout 130 ./run.sh 32 caw crash_consistency; echo "STAGE cc rc=$?"
  ./showstat.sh 32 caw 2>/dev/null | grep -a 'crash_consistency'
  timeout 240 tests/cc_grantwait.sh report 32 > "$EV/grantwait_report.txt" 2>&1; echo "STAGE report rc=$?"
  head -60 "$EV/grantwait_report.txt"
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep_final rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
