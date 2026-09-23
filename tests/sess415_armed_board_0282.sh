#!/bin/bash
# sess415 armed board on 0.28.2 — D-FOREIGN-REPLAY-UNGATED-IMAGES knob=1
# coherence-only capture-campaign lap (sess357 item 5) + sess404 Option-A
# gate item 3 assertions.  Knobs armed AFTER prep (they are runtime params;
# prep remounts reset them), prerequisite first (enforce's setter fails
# closed without target_cache_protected=1 on this fua_disable=1 rig).
# Stage caps (budget): prep 300 (fleet unmounted by the prior board's ndr
# row), params 60 (40s bounded ssh fan-out), board 1400 (sess415-derived).
# Gate-3 assertions swept post-board from fleet dmesg: zero unexpected
# POLICY-REFUSED, zero quarantine imports, zero recovery-attributable EIO
# (the board's node_death_replay row exercises armed foreign replay).
cd /src/mxfs || exit 1
LOG=tests/evidence/sess415_armed_board_0282.log
EV=tests/evidence/sess415_armed_0282
mkdir -p "$EV"
{
  echo "=== sess415 armed board start $(date -u +%FT%TZ) build=$(cat VERSION) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') ==="
  timeout 300 ./run.sh 32 caw prep_cluster
  echo "STAGE prep rc=$?"
  timeout 60 tests/fleet_set_params.sh "target_cache_protected=1 foreign_replay_token_enforce=1" 32 "$EV/knobs.txt"
  prc=$?
  echo "STAGE params rc=$prc"
  if [ "$prc" -ne 0 ]; then echo "ABORT: knob arming failed"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  timeout 1400 ./run.sh 32 caw
  echo "STAGE board rc=$?"
  # Gate-3 + P-D512 sweep: per-node counts, one parallel bounded fan-out.
  D=$(mktemp -d)
  for i in $(seq 1 32); do
    ( timeout 12 tools/mxfs_sshpass.sh test$i \
        "echo REFUSED=\$(dmesg | grep -c 'POLICY-REFUSED'); echo QUAR=\$(dmesg | grep -c 'QUARANTINE-IMPORT\|P-QUAR'); echo FRF=\$(dmesg | grep -c 'P227-FR-FAIL\|FR-REFUSED'); echo D512=\$(dmesg | grep -c 'P-D512-')" \
        > "$D/test$i" 2>/dev/null ) &
  done
  wait
  echo "gate-3 sweep (nonzero only):"
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
