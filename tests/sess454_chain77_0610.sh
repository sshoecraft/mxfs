#!/bin/bash
# sess454 chain 77: build 0.61.0 IN TREE once chain 76 (the 0.60.0 D-0519
# verification, tests/sess452_chain71_retire_pending.sh s454c) prints DONE and
# the rig is idle, then verify landing groups 2 and 3 on the fleet:
#   1  make modules + make tools (abort unless the srcversion CHANGES from the
#      0.60.0 build 0EB2C07B99A80502A11C6B1 and the 0.61.0 strings are present)
#   2  prep_cluster @ 32/caw
#   3  tests/settle_token_arms.sh: plain, inval, double, slowrace (group 2:
#      settle worker, proof token, CAS race), probehang (group 2: bounded join
#      + quarantine), latecomp (group 3: freeze/drain timeout, DIRTY, late
#      completion on live accounting)
#   4  the 12 RETIRE_PENDING laps (tests/sess452_chain71_retire_pending.sh
#      s454e) on 0.61.0 — regression of everything 0.59.x-0.60.0 verified
# derived time budgets: build = measured scratch compile (see the START line) → 900
# ceiling; prep 300 (measured 72-154 s at 32); settle arms per the harness
# header (plain/inval/double/slowrace 120, probehang 200, latecomp 160).
# Gate: chain 76 DONE.  Never rebuild under a run — that is what the gate is.
cd /src/mxfs || exit 1
LABEL=${1:-s454d}
OLD_SV=${2:-0EB2C07B99A80502A11C6B1}
GATE=tests/evidence/sess452_chain71_retire_pending_s454c.log
LOG=tests/evidence/sess454_chain77_0610_$LABEL.log
while ! grep -q "^DONE" "$GATE" 2>/dev/null; do sleep 30; done
lap() { # <budget_s> <label> <cmd...>
  local b="$1" l="$2"; shift 2
  local T0=$(date +%s)
  timeout "$b" "$@"; echo "STAGE $l rc=$? wall=$(( $(date +%s) - T0 ))s"
}
{
  echo "=== sess454 chain77 START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) old_sv=$OLD_SV ==="
  T0=$(date +%s)
  timeout 900 make modules > tests/evidence/sess454_chain77_build_$LABEL.log 2>&1; brc=$?
  echo "STAGE build rc=$brc wall=$(( $(date +%s) - T0 ))s errors=$(grep -c 'error:' tests/evidence/sess454_chain77_build_$LABEL.log) warnings=$(grep -c 'warning:' tests/evidence/sess454_chain77_build_$LABEL.log)"
  NEW_SV=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  echo "srcversion now $NEW_SV"
  if [ "$brc" != 0 ] || [ "$NEW_SV" = "$OLD_SV" ] || [ "$(strings -a mxfs.ko | grep -c 'P304-RETIRE-DRAIN-TIMEOUT')" = 0 ]; then
    echo "ABORT: build rc=$brc sv=$NEW_SV (old $OLD_SV) drain_string=$(strings -a mxfs.ko | grep -c 'P304-RETIRE-DRAIN-TIMEOUT')"
    echo "DONE $(date -u +%FT%TZ)"; exit 1
  fi
  lap 120 tools make tools
  lap 300 prep ./run.sh 32 caw prep_cluster
  lap 120 "settle arm=plain victim=test3"      tests/settle_token_arms.sh 32 test3  test1 plain
  lap 120 "settle arm=inval victim=test4"      tests/settle_token_arms.sh 32 test4  test1 inval
  lap 120 "settle arm=double victim=test26"    tests/settle_token_arms.sh 32 test26 test1 double
  lap 120 "settle arm=slowrace victim=test27"  tests/settle_token_arms.sh 32 test27 test1 slowrace
  lap 200 "settle arm=probehang victim=test28" tests/settle_token_arms.sh 32 test28 test1 probehang
  lap 160 "settle arm=latecomp victim=test29"  tests/settle_token_arms.sh 32 test29 test1 latecomp
  echo "=== settle arms done $(date -u +%FT%TZ); handing to the 12 RETIRE_PENDING laps (label s454e, sv $NEW_SV) ==="
  tests/sess452_chain71_retire_pending.sh s454e "$NEW_SV"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
