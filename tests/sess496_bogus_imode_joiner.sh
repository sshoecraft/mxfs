#!/bin/bash
# sess496: DOES A FREED-SHELL ADOPT STILL LOG 'init_special_inode: bogus i_mode (0)'?
# (D-RELOAD-FREED-ADOPT-BOGUS-IMODE, filed sess44 on 0.11.356; 0.11.357 guards the
# S_IFMT-change iops rewire with i_mode != 0.  The record's verify step: rerun the
# producer and assert zero 'bogus i_mode' lines cluster-wide.)
#
# THE PRODUCER.  tests/guard_race_arms.sh joiner: the fd-holder node (test1) keeps a
# victim file open, test2 unlinks it and is destroyed, the zombie parks on test2's
# AGI bucket, test2 rejoins while a survivor holds the guard; the fd holder adopts
# the freed image (P116-ZOMBIE-ADOPT -> P-RELOAD-IOPS-REWIRE old_ifmt=0100000
# new_mode=00 in the sess44 evidence).  The day's 1892 rig logs carried ZERO
# P116-ZOMBIE-ADOPT and ZERO 'bogus i_mode', so the negative is vacuous until the
# producer runs: the positive control (P116 count growth on the fd holder) is part
# of the verdict.
#
# Counts are per-node journal growth since a snapshot taken after prep, never
# "line exists" (dmesg persists across invocations).
#
# derived time budgets, derived: prep 300 (measured 104-146 s); joiner arm cap 560
# (the harness's own derived cap); two 32-node journal sweeps 90 each.  ~17 min.
#
# Usage: GATE=<log> setsid nohup bash tests/sess496_bogus_imode_joiner.sh s496a &
set -u
cd /src/mxfs || exit 1
LABEL=${1:-s496a}
GATE=${GATE:-tests/evidence/sess495_chain141_adopt_skip_s495d.log}
KO=${KO:-tests/evidence/sess496_frozen_07017/mxfs.ko}
WANT_SV=${WANT_SV:-01AE52DD876168E14CB1645}
LOG=tests/evidence/sess496_bogus_imode_$LABEL.log
O=tests/evidence/sess496_bogus_imode_$LABEL
SSH=tools/mxfs_sshpass.sh
mkdir -p "$O"

nodes() { seq 1 32 | sed 's/^/test/'; }

count_all() { # <tag> -> writes $O/.cnt.<tag>.<node> = "bogus p116 rewire" per node
    local tag=$1 n
    for n in $(nodes); do
        ( timeout 90 $SSH "$n" "journalctl -k --no-pager 2>/dev/null | awk '/bogus i_mode/{b++} /P116-ZOMBIE-ADOPT/{p++} /P-RELOAD-IOPS-REWIRE/{r++} END{printf \"%d %d %d\", b+0, p+0, r+0}'" \
            > "$O/.cnt.$tag.$n" 2>/dev/null ) &
    done
    wait
}

growth() { # <tag0> <tag1> -> prints per-node growth and totals
    local n b0 p0 r0 b1 p1 r1 gb=0 gp=0 gr=0 nb=0 np=0
    for n in $(nodes); do
        read -r b0 p0 r0 < "$O/.cnt.$1.$n" 2>/dev/null || { b0=0; p0=0; r0=0; }
        read -r b1 p1 r1 < "$O/.cnt.$2.$n" 2>/dev/null || { b1=0; p1=0; r1=0; }
        b0=${b0:-0}; p0=${p0:-0}; r0=${r0:-0}; b1=${b1:-0}; p1=${p1:-0}; r1=${r1:-0}
        if [ $((b1 - b0)) -gt 0 ] || [ $((p1 - p0)) -gt 0 ]; then
            echo "  NODE $n bogus_i_mode +$((b1 - b0)) P116-ZOMBIE-ADOPT +$((p1 - p0)) IOPS-REWIRE +$((r1 - r0))"
        fi
        gb=$((gb + b1 - b0)); gp=$((gp + p1 - p0)); gr=$((gr + r1 - r0))
        [ $((b1 - b0)) -gt 0 ] && nb=$((nb + 1))
        [ $((p1 - p0)) -gt 0 ] && np=$((np + 1))
    done
    echo "  STAGE growth bogus_i_mode=+$gb on $nb nodes; P116-ZOMBIE-ADOPT=+$gp on $np nodes; IOPS-REWIRE=+$gr"
}

{
  echo "=== sess496 bogus_imode START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) KO=$KO want_sv=$WANT_SV ==="
  gate_dl=$(( $(date +%s) + 21600 ))
  while ! grep -q "^DONE" "$GATE" 2>/dev/null; do
      [ "$(date +%s)" -ge "$gate_dl" ] && { echo "ABORT: gate $GATE never reached DONE within 6 h"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
      sleep 30
  done
  echo "STAGE gate cleared: $GATE"
  bash tests/rig_wait_free.sh 7200 || { echo "ABORT: rig not free"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  [ -f "$KO" ] || { echo "ABORT: missing $KO"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  cp "$KO" mxfs.ko
  sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  echo "STAGE install_ko sv=$sv want=$WANT_SV p13_marker=$(strings -a mxfs.ko | grep -ac 'P13-SFPARENT-DURABLE-FAIL ino=%llu state=%d releasing=%d refused=')"
  [ "$sv" = "$WANT_SV" ] || { echo "ABORT: installed sv $sv != $WANT_SV"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }

  t0=$(date +%s)
  timeout 300 ./run.sh 32 caw prep_cluster > "$O/prep.out" 2>&1; prc=$?
  echo "STAGE prep rc=$prc wall=$(( $(date +%s) - t0 ))s budget=300s"
  [ "$prc" = 0 ] || { echo "ABORT: prep rc=$prc"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  idok=0
  for n in $(nodes); do ( timeout 30 $SSH "$n" "cat /sys/module/mxfs/srcversion" 2>/dev/null | tr -dc 'A-F0-9' > "$O/.sv.$n" ) & done; wait
  for n in $(nodes); do [ "$(cat "$O/.sv.$n" 2>/dev/null)" = "$sv" ] && idok=$((idok + 1)); done
  echo "  STAGE fleet_identity match=$idok/32 sv=$sv"
  [ "$idok" -eq 32 ] || { echo "ABORT: fleet identity mismatch"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }

  count_all pre
  t0=$(date +%s)
  timeout 560 bash tests/guard_race_arms.sh joiner test2 test1 > "$O/joiner.out" 2>&1; jrc=$?
  echo "STAGE joiner rc=$jrc wall=$(( $(date +%s) - t0 ))s budget=560s"
  [ "$jrc" = 124 ] && echo "  budget: the joiner arm hit its cap — a result, not a number to widen."
  grep -aE 'PASS|FAIL|rc=|P99|P116|P163|guard' "$O/joiner.out" | tail -12 | cut -c1-200 | sed 's/^/  joiner: /'
  count_all post
  growth pre post
  # keep the raw lines for the ledger
  for n in $(nodes); do
      ( timeout 90 $SSH "$n" "journalctl -k --no-pager 2>/dev/null | grep -aE 'bogus i_mode|P116-ZOMBIE-ADOPT|P-RELOAD-IOPS-REWIRE|P89-REAP-DONE|P103-'" 2>/dev/null | gzip > "$O/kernlog_$n.gz" ) &
  done
  wait
  echo "--- VERDICT ---"
  echo "  Producer ran iff P116-ZOMBIE-ADOPT grew on the fd holder (test1); with that, bogus_i_mode=+0 cluster-wide is the record's closure bar (re-count in the parent before the ledger)."
  echo "  P116 +0 => the producer did not reach the freed-shell adopt: read joiner.out, do not dispose."
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
