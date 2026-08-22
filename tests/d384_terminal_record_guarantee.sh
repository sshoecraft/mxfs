#!/bin/bash
# tests/d384_terminal_record_guarantee.sh — LOCAL (single-host) verification of
# the RULE-0 terminal-record guarantee added in sess384 for
# D-CRASH-CONSISTENCY-NO-TERMINAL-RECORD-CAPTURE-374.
#
# The defect: run.sh kills each node's ssh at the criterion's RULE-0 budget,
# but the node-side rendezvous cap (COORD_TIMEOUT=120s) was LARGER than that
# budget for every criterion except dir_reuse_coherency.  A genuine stall was
# therefore SIGKILLed before the barrier layer could print BARRIER_TIMEOUT, and
# the board could only say `nodes_pass=0/32 states:NO_TERMINAL_RECORD=32`.
#
# This harness exercises the node-side half (lib.sh + coord.sh) directly, with
# no cluster and no MQTT broker, so the mechanics can be proven before a rig
# cycle spends 32 nodes on them:
#
#   1. a test that hangs past its deadline emits BUDGET_EXHAUSTED naming the
#      STEP it was in, on stdout AND in the node-local spool
#   2. that record arrives BEFORE the harness's kill box, not after
#   3. a healthy test still emits its own PASS and exits PROMPTLY — the
#      watchdog must not hold the inherited stdout open to the budget
#   4. the watchdog does not fire for a test that finishes normally
#   5. suite_proc_starttime returns a stable identity and detects exit
#
# Run:  bash tests/d384_terminal_record_guarantee.sh
set -u
LIB=/src/mxfs/tests/suite/lib.sh
W=$(mktemp -d)
PASSED=0; FAILED=0
ck() {  # <desc> <cond-cmd...>
    if "${@:2}"; then PASSED=$((PASSED+1)); printf '  ok   %s\n' "$1"
    else FAILED=$((FAILED+1)); printf '  FAIL %s\n' "$1"; fi
}

# ── 1/5  starttime identity ────────────────────────────────────────────────
# shellcheck source=/dev/null
( MXFS_NODES=1 SUITE_TEST_NAME=probe; source "$LIB" >/dev/null 2>&1
  a=$(suite_proc_starttime $$); b=$(suite_proc_starttime $$)
  [ -n "$a" ] && [ "$a" = "$b" ] || exit 1
  sleep 0.2 & p=$!; wait $p
  [ -z "$(suite_proc_starttime $p)" ] || exit 2 )
ck "suite_proc_starttime: stable for a live pid, empty for a dead one" test $? -eq 0

# ── 2/5  hung test emits BUDGET_EXHAUSTED with the step, before the kill ───
cat > "$W/hang.sh" <<'EOS'
source /src/mxfs/tests/suite/lib.sh
suite_step "the-stalled-step"
sleep 120
finish
EOS
SPOOL="$W/spool.result"
BUDGET=8
DL=$(( $(date +%s%3N) + BUDGET * 1000 ))
t0=$(date +%s%3N)
out=$(MXFS_NODES=1 MXFS_DEADLINE_MS=$DL MXFS_RESERVE_MS=3000 MXFS_SPOOL="$SPOOL" \
      timeout --kill-after=3 "$BUDGET" bash "$W/hang.sh" 2>&1)
rc=$?
t1=$(date +%s%3N)
wall=$(( t1 - t0 ))
printf '%s\n' "$out" > "$W/hang.out"
ck "hung test emits a RESULT record on stdout" grep -q '^RESULT: BUDGET_EXHAUSTED' "$W/hang.out"
ck "the record names the step it stalled in"   grep -q 'step=the-stalled-step' "$W/hang.out"
ck "the record is tagged src=watchdog"         grep -q 'src=watchdog' "$W/hang.out"
ck "the same record is spooled node-locally"   grep -q '^RESULT: BUDGET_EXHAUSTED' "$SPOOL"
# The stalled workload is NOT killed by the watchdog (a D-state wait cannot take
# a signal), so the ssh still burns the whole budget and the row still FAILs on
# RULE 0.  What must be true is that the RECORD was produced before the kill and
# survived it — measured from the spool file's mtime, not from the total wall.
spool_ms=$(( $(stat -c %Y "$SPOOL") * 1000 ))
ck "the record was written BEFORE the kill box (spool mtime +$(( spool_ms - t0 ))ms < ${BUDGET}000ms)" \
   test "$(( spool_ms - t0 ))" -lt "$(( BUDGET * 1000 ))"
ck "the harness still saw the budget expire (rc=$rc is 124/137)" \
   bash -c "[ $rc -eq 124 ] || [ $rc -eq 137 ]"

# ── 3/5  healthy test still passes, and exits promptly ─────────────────────
cat > "$W/ok.sh" <<'EOS'
source /src/mxfs/tests/suite/lib.sh
ckeq "trivial" 1 1
finish
EOS
DL=$(( $(date +%s%3N) + 60000 ))
t0=$(date +%s%3N)
out=$(MXFS_NODES=1 MXFS_DEADLINE_MS=$DL MXFS_RESERVE_MS=4000 MXFS_SPOOL="$W/ok.result" \
      timeout --kill-after=3 60 bash "$W/ok.sh" 2>&1)
t1=$(date +%s%3N)
wall=$(( t1 - t0 ))
printf '%s\n' "$out" > "$W/ok.out"
ck "healthy test emits its own PASS"           grep -q '^RESULT: PASS .*src=test' "$W/ok.out"
ck "healthy test emits NO watchdog record"     bash -c "! grep -q 'src=watchdog' '$W/ok.out'"
ck "healthy test returns promptly (wall ${wall}ms < 5000ms, i.e. the watchdog did not hold stdout)" \
   test "$wall" -lt 5000

# ── 4/5  a test that exits WITHOUT finish must not hold the pipe open ──────
cat > "$W/bail.sh" <<'EOS'
source /src/mxfs/tests/suite/lib.sh
echo "RESULT: FAIL | test=bail | nodes=1 | measured=setup | reason=prereq missing"
exit 1
EOS
DL=$(( $(date +%s%3N) + 60000 ))
t0=$(date +%s%3N)
MXFS_NODES=1 MXFS_DEADLINE_MS=$DL MXFS_RESERVE_MS=4000 MXFS_SPOOL="$W/bail.result" \
    timeout --kill-after=3 60 bash "$W/bail.sh" > "$W/bail.out" 2>&1
t1=$(date +%s%3N)
wall=$(( t1 - t0 ))
ck "early-exit test returns promptly (wall ${wall}ms < 5000ms)" test "$wall" -lt 5000
ck "early-exit test's own legacy RESULT survives" grep -q '^RESULT: FAIL' "$W/bail.out"

# ── 5/5  coord_eff_timeout clamps to the reporting deadline ────────────────
( MXFS_NODES=2 SUITE_TEST_NAME=probe MXFS_DEADLINE_MS=$(( $(date +%s%3N) + 10000 )) \
  MXFS_RESERVE_MS=3000 COORD_TIMEOUT=120
  source "$LIB" >/dev/null 2>&1
  suite_watchdog_stop
  eff=$(coord_eff_timeout) || exit 1
  [ "$eff" -le 7 ] && [ "$eff" -ge 5 ] || { echo "eff=$eff"; exit 2; }
  # and past the deadline it refuses outright
  SUITE_REPORT_S=-1
  coord_eff_timeout >/dev/null && exit 3
  exit 0 )
ck "coord_eff_timeout clamps 120s to the reporting deadline and refuses past it" test $? -eq 0

printf '\nRESULT: %s | passed=%s failed=%s\n' \
    "$([ "$FAILED" -eq 0 ] && echo PASS || echo FAIL)" "$PASSED" "$FAILED"
[ "$FAILED" -eq 0 ]
