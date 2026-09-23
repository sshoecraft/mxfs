#!/bin/bash
# sess435 chain 8: build 0.41.2 (P308 boundary now advances the AIL head —
# mxfs_log_head_past_boundary; 0.41.1 measured 'did NOT advance', the cut was
# not in force and only P310 rescued the replay), then verify:
#   prep 32/caw
#   lone_crash_replay enforce1 x2   D-0354 closure arms (200 s each; virsh-destroys A).
#                                   Expect on A: P308 'ail_head_lsn X -> Y' with Y > X and
#                                   NO 'did NOT advance'; on B: P309 foreign tail beyond the
#                                   old record, P273 winc=0, preinc absent, replay complete, file=1.
#   lone_rsync_bench                the budget rule (120 s) — rerun: s434j ran on a rebooted node
#                                   without the module (harness ordering, not FS)
#   armed 32/caw board (sess432 shape: prep, knobs, board 1400 s, journal sweep)
cd /src/mxfs || exit 1
LABEL=${1:-s435a}
LOG=tests/evidence/sess435_chain8_0412_$LABEL.log
EV=tests/evidence/sess435_chain8_0412_$LABEL
mkdir -p "$EV"
{
  echo "=== sess435 chain8 start $(date -u +%FT%TZ) ==="
  OLD=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  timeout 500 make modules > tests/evidence/sess435_build8_$LABEL.txt 2>&1; brc=$?
  timeout 120 make tools >> tests/evidence/sess435_build8_$LABEL.txt 2>&1; trc=$?
  NEW=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  echo "BUILD_RC=$brc TOOLS_RC=$trc VERSION=$(cat VERSION) sv_old=$OLD sv_new=$NEW"
  grep -c 'error:' tests/evidence/sess435_build8_$LABEL.txt | sed 's/^/build errors=/'
  if [ "$brc" -ne 0 ] || [ "$NEW" = "$OLD" ]; then echo "ABORT: build failed or srcversion unchanged"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep rc=$?"
  timeout 200 tests/lone_crash_replay.sh ${LABEL}_e1 test5 test6 32 enforce1;         echo "STAGE crash_enforce1 rc=$?"
  for t in $(seq 1 20); do timeout 10 tools/mxfs_sshpass.sh test5 "uptime" >/dev/null 2>&1 && break; sleep 10; done
  timeout 200 tests/lone_crash_replay.sh ${LABEL}_e1b test7 test8 32 enforce1;        echo "STAGE crash_enforce1b rc=$?"
  for t in $(seq 1 20); do timeout 10 tools/mxfs_sshpass.sh test7 "uptime" >/dev/null 2>&1 && break; sleep 10; done
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep2 rc=$?"
  timeout 120 tests/lone_rsync_bench.sh ${LABEL}_b1 test1 32;                         echo "STAGE bench1 rc=$?"
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep3 rc=$?"
  timeout 60 tests/fleet_set_params.sh "target_cache_protected=1 foreign_replay_token_enforce=1" 32 "$EV/knobs.txt"
  prc=$?; echo "STAGE params rc=$prc"
  if [ "$prc" -ne 0 ]; then echo "ABORT: knob arming failed"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  BMARK="S435-BOARD-0412-$$"
  for i in $(seq 1 32); do ( timeout 12 tools/mxfs_sshpass.sh test$i "echo '$BMARK' > /dev/kmsg" >/dev/null 2>&1 ) & done; wait
  BMARKTIME=$(date -u '+%Y-%m-%d %H:%M:%S')
  timeout 1400 ./run.sh 32 caw; echo "STAGE board rc=$?"
  D=$(mktemp -d)
  for i in $(seq 1 32); do
    ( timeout 40 tools/mxfs_sshpass.sh test$i \
        "journalctl -k -q --since '$BMARKTIME' > /tmp/s435sweep.txt 2>/dev/null; echo JOURNAL_LINES=\$(wc -l < /tmp/s435sweep.txt); echo REFUSED=\$(grep -c 'POLICY-REFUSED' /tmp/s435sweep.txt); echo QUAR=\$(grep -c 'QUARANTINE-IMPORT\|P-QUAR\|P240-QUAR' /tmp/s435sweep.txt); echo FRF=\$(grep -c 'P227-FR-FAIL\|FR-REFUSED' /tmp/s435sweep.txt); echo P130R=\$(grep -c 'P130-FALSE-FRESH-REFUSED' /tmp/s435sweep.txt); echo P131R=\$(grep -c 'P131-INVAL-REFUSED' /tmp/s435sweep.txt); echo P243=\$(grep -c 'P243-AGAUTH-UNBOUND' /tmp/s435sweep.txt); echo P308NA=\$(grep -c 'did NOT advance' /tmp/s435sweep.txt); echo P308=\$(grep -c 'P308-LOG-INCARNATION-BOUNDARY written' /tmp/s435sweep.txt); echo P310=\$(grep -c 'P310-FR-PREINCARNATION-SKIP' /tmp/s435sweep.txt); echo INUSE=\$(grep -c 'known in-use inode' /tmp/s435sweep.txt); echo SHUTDOWN=\$(grep -c 'P-SESSION-POISON\|P237-EVICT-OBLIGATION\|Shutting down filesystem' /tmp/s435sweep.txt)" \
        > "$D/test$i" 2>/dev/null ) &
  done
  wait
  echo "sweep (nonzero only; JOURNAL_LINES = window size, absent = zero):"
  for i in $(seq 1 32); do
    while read -r line; do v=${line#*=}; [ -n "$v" ] && [ "$v" != "0" ] && echo "  test$i ${line}"; done < "$D/test$i" 2>/dev/null
  done
  cp -r "$D" "$EV/sweep" 2>/dev/null
  echo "sweep done (absent = zero)"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
