#!/bin/bash
# sess466 chain 96: re-run departure crash cut 5 (postunreg) on the corrected
# harness.  Chain 92's cut 5 (tests/evidence/20260902T090001Z_crashcut5_postunreg)
# failed ONE assertion — the S1 snapshot read EMPTY because peer test19's retire
# worker settled the record inside its next heartbeat lap, before the harness
# could poll the park marker and read the sector; every state-table fact held.
# tests/depart_crash_cuts.sh now accepts S1 EMPTY when a peer's
# P304-RETIRE-PENDING-SEEN line names the victim key via ident.  cond3 of
# D-PR-RETIREMENT-FAILURE-NOT-FAIL-CLOSED-377 is complete only when this lap
# prints VERDICT PASS cut=5.
# Runs on whatever module chain 95 left in the tree (frozen 0.63.2, sv
# DE0C4C40 expected) — no build; the fleet is re-prepped so the victim slot
# from chain 95's laps is clean.  Gated on chain 95 DONE.
# budget: prep 300 (measured 86-106 s), cut-5 arm 300 (harness header: whole
# arm <= 300 s, cut 5 ~200 s; chain 92 measured 47 s to verdict + restart),
# final prep 300.  Whole chain <= 15 min.
cd /src/mxfs || exit 1
LABEL=${1:-s466a}
GATE=${GATE:-tests/evidence/sess465_chain95_samenode_s465b.log}
LOG=tests/evidence/sess466_chain96_crashcut5_$LABEL.log
SSH=tools/mxfs_sshpass.sh
while ! grep -q "^DONE" "$GATE" 2>/dev/null; do sleep 30; done
lap() { # <budget_s> <label> <cmd...>
  local b="$1" l="$2"; shift 2
  local T0=$(date +%s)
  timeout "$b" "$@"; echo "STAGE $l rc=$? wall=$(( $(date +%s) - T0 ))s"
}
{
  echo "=== sess466 chain96 START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') cut_injector=$(strings -a mxfs.ko | grep -c 'P-DBG-DEPART-CUT') ==="
  lap 300 prep ./run.sh 32 caw prep_cluster
  echo "fleet: $(timeout 20 $SSH test1 'cat /sys/module/mxfs/srcversion; grep -c " mxfs " /proc/mounts' 2>/dev/null | grep -av '^Unauthorized\|^$\|^If you' | tr '\n' ' ')"
  lap 300 "cond3 crashcut 5 postunreg victim=test12" tests/depart_crash_cuts.sh 32 test12 test1 5
  lap 300 prep_final ./run.sh 32 caw prep_cluster
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
