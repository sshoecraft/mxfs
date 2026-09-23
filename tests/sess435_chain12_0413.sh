#!/bin/bash
# sess435 chain 12: build 0.41.3 —
#   D-0359 step 1: operational CAW admission probe (disklock claim_via_caw +
#     negative probe on our own HB slot -> P311-CAW-CAP; v5 CAW-transport
#     mount refuses UNSUPPORTED/TRANSIENT/VIOLATION with P311-CAW-ADMISSION-REFUSED)
#   D-378 item 1: P378-TRANS-READ-FAIL marker
# Waits for chain 11 (purge arms) to print DONE.  Then:
#   prep 32/caw                 every mount passes the probe (P311-CAW-CAP OK on the LUN)
#   P311 sweep                  32/32 'P311-CAW-CAP ... OK', zero REFUSED
#   vergate test32 noncaw_refuse  ruling arm 1/14 on the loop device (90 s)
#   prep 32/caw
#   lone_mount_create fixed     D-0353 regression (60 s)
#   lone_crash_replay enforce1  D-0354 regression (200 s)
#   d379b                       D-379 regression (240 s)
#   prep + armed 32/caw board + sweep (sess432 shape)
cd /src/mxfs || exit 1
LABEL=${1:-s435e}
LOG=tests/evidence/sess435_chain12_0413_$LABEL.log
EV=tests/evidence/sess435_chain12_0413_$LABEL
GATE=tests/evidence/sess435_chain11_purge_s435d.log
mkdir -p "$EV"
{
  echo "=== sess435 chain12 start $(date -u +%FT%TZ) ==="
  for t in $(seq 1 600); do grep -q '^DONE' "$GATE" 2>/dev/null && break; sleep 10; done
  grep -q '^DONE' "$GATE" || { echo "ABORT: chain11 not DONE after 6000 s"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  echo "gate passed at $(date -u +%FT%TZ) (iter $t)"
  OLD=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  timeout 500 make modules > tests/evidence/sess435_build12_$LABEL.txt 2>&1; brc=$?
  timeout 120 make tools >> tests/evidence/sess435_build12_$LABEL.txt 2>&1; trc=$?
  NEW=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  echo "BUILD_RC=$brc TOOLS_RC=$trc VERSION=$(cat VERSION) sv_old=$OLD sv_new=$NEW"
  grep -c 'error:' tests/evidence/sess435_build12_$LABEL.txt | sed 's/^/build errors=/'
  if [ "$brc" -ne 0 ] || [ "$NEW" = "$OLD" ]; then echo "ABORT: build failed or srcversion unchanged"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep rc=$?"
  D=$(mktemp -d)
  for i in $(seq 1 32); do
    ( timeout 30 tools/mxfs_sshpass.sh test$i "dmesg | grep -a 'P311-CAW' | tail -3" > "$D/test$i.txt" 2>/dev/null ) &
  done
  wait
  echo "P311 sweep: OK=$(cat "$D"/test*.txt | grep -c 'P311-CAW-CAP.*OK') REFUSED=$(cat "$D"/test*.txt | grep -c 'ADMISSION-REFUSED') nodes_with_line=$(grep -l 'P311-CAW-CAP' "$D"/test*.txt | wc -l)"
  head -1 "$D/test1.txt"
  cp -r "$D" "$EV/p311"
  timeout 120 tests/vergate.sh test32 noncaw_refuse; echo "STAGE noncaw_refuse rc=$?"
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep2 rc=$?"
  timeout 60  tests/lone_mount_create.sh ${LABEL}_fixed test1 32 fixed;               echo "STAGE fixed rc=$?"
  timeout 200 tests/lone_crash_replay.sh ${LABEL}_e1 test5 test6 32 enforce1;         echo "STAGE crash_enforce1 rc=$?"
  for t in $(seq 1 20); do timeout 10 tools/mxfs_sshpass.sh test5 "uptime" >/dev/null 2>&1 && break; sleep 10; done
  timeout 240 tests/d379b_dirty_depart_peer_fence.sh ${LABEL}_d379b test3 test4 32;   echo "STAGE d379b rc=$?"
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep3 rc=$?"
  timeout 60 tests/fleet_set_params.sh "target_cache_protected=1 foreign_replay_token_enforce=1" 32 "$EV/knobs.txt"
  prc=$?; echo "STAGE params rc=$prc"
  if [ "$prc" -ne 0 ]; then echo "ABORT: knob arming failed"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  BMARKTIME=$(date -u '+%Y-%m-%d %H:%M:%S')
  timeout 1400 ./run.sh 32 caw; echo "STAGE board rc=$?"
  D2=$(mktemp -d)
  for i in $(seq 1 32); do
    ( timeout 40 tools/mxfs_sshpass.sh test$i \
        "journalctl -k -q --since '$BMARKTIME' > /tmp/s435sweep2.txt 2>/dev/null; echo JOURNAL_LINES=\$(wc -l < /tmp/s435sweep2.txt); echo REFUSED=\$(grep -c 'POLICY-REFUSED' /tmp/s435sweep2.txt); echo QUAR=\$(grep -c 'QUARANTINE-IMPORT\|P-QUAR\|P240-QUAR' /tmp/s435sweep2.txt); echo FRF=\$(grep -c 'P227-FR-FAIL\|FR-REFUSED' /tmp/s435sweep2.txt); echo P130R=\$(grep -c 'P130-FALSE-FRESH-REFUSED' /tmp/s435sweep2.txt); echo P131R=\$(grep -c 'P131-INVAL-REFUSED' /tmp/s435sweep2.txt); echo P243=\$(grep -c 'P243-AGAUTH-UNBOUND' /tmp/s435sweep2.txt); echo P308NA=\$(grep -c 'did NOT advance' /tmp/s435sweep2.txt); echo P311R=\$(grep -c 'P311-CAW-ADMISSION-REFUSED' /tmp/s435sweep2.txt); echo P378=\$(grep -c 'P378-TRANS-READ-FAIL' /tmp/s435sweep2.txt); echo INUSE=\$(grep -c 'known in-use inode' /tmp/s435sweep2.txt); echo SHUTDOWN=\$(grep -c 'P-SESSION-POISON\|P237-EVICT-OBLIGATION\|Shutting down filesystem' /tmp/s435sweep2.txt)" \
        > "$D2/test$i" 2>/dev/null ) &
  done
  wait
  echo "sweep (nonzero only; JOURNAL_LINES = window size, absent = zero):"
  for i in $(seq 1 32); do
    while read -r line; do v=${line#*=}; [ -n "$v" ] && [ "$v" != "0" ] && echo "  test$i ${line}"; done < "$D2/test$i" 2>/dev/null
  done
  cp -r "$D2" "$EV/sweep"
  echo "sweep done (absent = zero)"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
