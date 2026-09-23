#!/bin/bash
# sess432 armed board on 0.39.13 — regression proof for D-0353 step 1+2
# (single-node grant provenance; fail-closed AG-meta invalidation with
# P130/P131 enforced) and the D-0355 barrier retry: the acquire path changed
# for EVERY node, so the whole board is the regression check (design-consult ruling
# sess432 item 7).  Clone of tests/sess416_board_0286.sh (same stage caps,
# budget: prep 300, params 60, board 1400) with the sweep extended by the
# new tags.  Any P130-FALSE-FRESH-REFUSED / P131-INVAL-REFUSED on the board
# is a release-drain gap DEFECT to file — never a reason to relax the knobs.
cd /src/mxfs || exit 1
LABEL=${1:-s432b}
LOG=tests/evidence/sess432_board_03913_$LABEL.log
EV=tests/evidence/sess432_board_03913_$LABEL
mkdir -p "$EV"
{
  echo "=== sess432 armed board start $(date -u +%FT%TZ) build=$(cat VERSION) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') ==="
  timeout 300 ./run.sh 32 caw prep_cluster
  echo "STAGE prep rc=$?"
  timeout 60 tests/fleet_set_params.sh "target_cache_protected=1 foreign_replay_token_enforce=1" 32 "$EV/knobs.txt"
  prc=$?
  echo "STAGE params rc=$prc"
  if [ "$prc" -ne 0 ]; then echo "ABORT: knob arming failed"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  BMARK="S432-BOARD-03913-$$"
  for i in $(seq 1 32); do
    ( timeout 12 tools/mxfs_sshpass.sh test$i "echo '$BMARK' > /dev/kmsg" >/dev/null 2>&1 ) &
  done
  wait
  BMARKTIME=$(date -u '+%Y-%m-%d %H:%M:%S')
  timeout 1400 ./run.sh 32 caw
  echo "STAGE board rc=$?"
  D=$(mktemp -d)
  for i in $(seq 1 32); do
    ( timeout 40 tools/mxfs_sshpass.sh test$i \
        "journalctl -k -q --since '$BMARKTIME' > /tmp/s432sweep.txt 2>/dev/null; echo JOURNAL_LINES=\$(wc -l < /tmp/s432sweep.txt); echo REFUSED=\$(grep -c 'POLICY-REFUSED' /tmp/s432sweep.txt); echo QUAR=\$(grep -c 'QUARANTINE-IMPORT\|P-QUAR' /tmp/s432sweep.txt); echo FRF=\$(grep -c 'P227-FR-FAIL\|FR-REFUSED' /tmp/s432sweep.txt); echo P130R=\$(grep -c 'P130-FALSE-FRESH-REFUSED' /tmp/s432sweep.txt); echo P130=\$(grep -c 'P130-FALSE-FRESH agno' /tmp/s432sweep.txt); echo P131R=\$(grep -c 'P131-INVAL-REFUSED' /tmp/s432sweep.txt); echo P131D=\$(grep -c 'P131-INVAL-DISCARD' /tmp/s432sweep.txt); echo P47L=\$(grep -c 'P47-INVAL-SKIP-INAIL.*locked;' /tmp/s432sweep.txt); echo P243=\$(grep -c 'P243-AGAUTH-UNBOUND' /tmp/s432sweep.txt); echo SERA=\$(grep -c 'single-era-ended' /tmp/s432sweep.txt); echo INUSE=\$(grep -c 'known in-use inode' /tmp/s432sweep.txt); echo SHUTDOWN=\$(grep -c 'P-SESSION-POISON\|P237-EVICT-OBLIGATION\|Shutting down filesystem' /tmp/s432sweep.txt)" \
        > "$D/test$i" 2>/dev/null ) &
  done
  wait
  echo "sweep (nonzero only; JOURNAL_LINES = window size, absent = zero):"
  for i in $(seq 1 32); do
    while read -r line; do
      v=${line#*=}
      [ -n "$v" ] && [ "$v" != "0" ] && echo "  test$i ${line}"
    done < "$D/test$i" 2>/dev/null
  done
  cp -r "$D" "$EV/sweep" 2>/dev/null
  echo "sweep done (absent = zero)"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
