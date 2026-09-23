#!/bin/bash
# sess416 armed board on 0.28.6 — dual purpose:
#   (1) D-WEDGED-RELSTATE-CLOBBER-UNLOCK-PUBLISHED-0285 ledger item 3:
#       full-board regression proof for the sticky-WEDGED setter
#       (mxfs_rel_state_set) + the relocated T8 kind-4 reload injector
#       (both dormant unarmed — the board must be indistinguishable from
#       0.28.4/0.28.5 boards);
#   (2) D-FOREIGN-REPLAY-UNGATED-IMAGES knob=1 coherence-only capture
#       lap 3 (sess357 item 5) with the sess404 gate-3 assertions.
# Clone of tests/sess415_armed_board_0282.sh with the same stage caps
# (budget): prep 300, params 60, board 1400 (sess415-derived walls).
cd /src/mxfs || exit 1
LOG=tests/evidence/sess416_board_0286.log
EV=tests/evidence/sess416_board_0286
mkdir -p "$EV"
{
  echo "=== sess416 armed board start $(date -u +%FT%TZ) build=$(cat VERSION) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') ==="
  timeout 300 ./run.sh 32 caw prep_cluster
  echo "STAGE prep rc=$?"
  timeout 60 tests/fleet_set_params.sh "target_cache_protected=1 foreign_replay_token_enforce=1" 32 "$EV/knobs.txt"
  prc=$?
  echo "STAGE params rc=$prc"
  if [ "$prc" -ne 0 ]; then echo "ABORT: knob arming failed"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  # Board-start kmsg marker on every node: today's T8 injector runs put
  # P-D512-INJECT/P-INODE-WEDGE lines in the fleet's cumulative dmesg by
  # design; the sweep must count only lines from THIS board (sess414 tck
  # trap: cumulative dmesg sweeps fabricate verdicts).
  BMARK="S416-BOARD-0286-$$"
  for i in $(seq 1 32); do
    ( timeout 12 tools/mxfs_sshpass.sh test$i "echo '$BMARK' > /dev/kmsg" >/dev/null 2>&1 ) &
  done
  wait
  BMARKTIME=$(date -u '+%Y-%m-%d %H:%M:%S')
  timeout 1400 ./run.sh 32 caw
  echo "STAGE board rc=$?"
  # Gate-3 + P-D512 + 0285 sweep: per-node counts FROM THE MARK TIME, one
  # parallel bounded fan-out.  P-D512-INJECT / P-INODE-WEDGE must be ZERO
  # within the board window (the injectors are one-shot knobs this chain
  # never sets).
  # sess429: read JOURNALD since the mark time, not the dmesg ring — the ring
  # wraps within minutes under the board's probe volume, so the kmsg marker
  # was gone by the end of the s433 board and every count below read ZERO
  # (false "absent").  Node clocks are UTC.  JOURNAL_LINES says how much the
  # window actually held; a node rebooted by node_death_replay reports a
  # short window.
  D=$(mktemp -d)
  for i in $(seq 1 32); do
    ( timeout 40 tools/mxfs_sshpass.sh test$i \
        "journalctl -k -q --since '$BMARKTIME' > /tmp/s416sweep.txt 2>/dev/null; echo JOURNAL_LINES=\$(wc -l < /tmp/s416sweep.txt); echo REFUSED=\$(grep -c 'POLICY-REFUSED' /tmp/s416sweep.txt); echo QUAR=\$(grep -c 'QUARANTINE-IMPORT\|P-QUAR' /tmp/s416sweep.txt); echo FRF=\$(grep -c 'P227-FR-FAIL\|FR-REFUSED' /tmp/s416sweep.txt); echo D512=\$(grep -c 'P-D512-' /tmp/s416sweep.txt); echo WEDGE=\$(grep -c 'P-INODE-WEDGE' /tmp/s416sweep.txt); echo SHUTDOWN=\$(grep -c 'P-SESSION-POISON\|P237-EVICT-OBLIGATION\|Shutting down filesystem' /tmp/s416sweep.txt)" \
        > "$D/test$i" 2>/dev/null ) &
  done
  wait
  echo "gate-3 sweep (nonzero only; JOURNAL_LINES = window size, absent = zero):"
  for i in $(seq 1 32); do
    while read -r line; do
      v=${line#*=}
      [ -n "$v" ] && [ "$v" != "0" ] && echo "  test$i ${line}"
    done < "$D/test$i" 2>/dev/null
  done
  cp -r "$D" "$EV/gate3_sweep" 2>/dev/null
  echo "sweep done (absent = zero)"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
