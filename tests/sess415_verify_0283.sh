#!/bin/bash
# sess415 0.28.3 verification chain — D-512 cycle-1 race-injection legs:
# dbg_incarn_race_ino/dbg_incarn_racewin_ms window knobs + 3 window sites
# (write_iter / fault / writepages, all no-op unarmed) + d512_race_verify.sh
# (write + writeback legs; fault leg lands with the T-matrix helper work).
# Stage caps (budget): prep 300 (new srcversion, full prep), d512 gate 100,
# race legs ~30s bound 90 -> 100, zsl 120 ea, board 1400 (sess415-derived).
# PASS: race VERDICT PASS + gate matrix PASS + zsl x2 + board green modulo
# open_defects/known faces + zero P-D512 fires OUTSIDE the race harness's
# own P-D512-RACEWIN (swept in-chain; racewin lines are expected from the
# race stage only, on its nominated inos).
cd /src/mxfs || exit 1
LOG=tests/evidence/sess415_verify_0283.log
{
  echo "=== sess415 0.28.3 verify start $(date -u +%FT%TZ) build=$(cat VERSION) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') ==="
  timeout 300 ./run.sh 32 caw prep_cluster
  echo "STAGE prep rc=$?"
  timeout 100 tests/d512_incarn_gate_verify.sh s415c test5
  echo "STAGE d512 rc=$?"
  timeout 100 tests/d512_race_verify.sh s415r test5
  echo "STAGE race rc=$?"
  timeout 120 ./run.sh 32 caw zero_silent_loss
  echo "STAGE zsl1 rc=$?"
  timeout 120 ./run.sh 32 caw zero_silent_loss
  echo "STAGE zsl2 rc=$?"
  timeout 1400 ./run.sh 32 caw
  echo "STAGE board rc=$?"
  D=$(mktemp -d)
  for i in $(seq 1 32); do
    ( timeout 12 tools/mxfs_sshpass.sh test$i \
        "echo WIN=\$(dmesg | grep -c 'P-D512-RACEWIN'); echo ARM=\$(dmesg | grep -c 'P-D512-REL-DRAIN\|P-D512-DRAIN2\|P-D512-DIRTY')" \
        > "$D/test$i" 2>/dev/null ) &
  done
  wait
  echo "P-D512 sweep (nonzero only; WIN expected only on the race node):"
  for i in $(seq 1 32); do
    while read -r line; do
      v=${line#*=}
      [ -n "$v" ] && [ "$v" != "0" ] && echo "  test$i ${line}"
    done < "$D/test$i" 2>/dev/null
  done
  echo "sweep done"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
