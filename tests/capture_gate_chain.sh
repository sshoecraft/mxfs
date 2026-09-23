#!/bin/bash
# tests/capture_gate_chain.sh — several healthy capture-gate laps in one
# detached run, each restored and bounded on its own, with a one-line summary
# per lap that a driver can read back later.
#
# tests/capture_gate_sweep.sh runs ONE lap per invocation so that a driver
# never waits on anything longer than the manifest's bound; but a chain of
# laps whose bounds exceed what an interactive tool call may wait on (the
# d0932 family: 1140 s, 1230 s, 1300 s) has to be launched detached and read
# back, and a driver that launches three of those by hand and comes back to
# three logs is a driver that mis-attributes one.  So this runs the laps in
# order — `ensure` before each (both nodes up, prep_cluster once if either is
# not mounted-and-writable), then the lap — and appends to
# tests/evidence/gate_<label>/chain.log one line per lap:
#     CHAIN <harness> rc=<gate rc> wall=<s>s <the lap's RESULT line, or none>
# and a final line `CHAIN DONE laps=<n> ok=<n> wall=<s>s`.  A lap's own bound
# is the manifest's; nothing here widens or retries anything, and a lap that
# ABORTs or FAILs is recorded and the chain moves on (the next `ensure`
# restores the fleet it may have left unmounted).
#
# Usage: nohup setsid tests/capture_gate_chain.sh <label> <harness>... \
#            > tests/evidence/gate_<label>/chain.out 2>&1 &
set -u
LABEL=${1:?label}; shift
[ $# -ge 1 ] || { echo "usage: $0 <label> <harness>..."; exit 2; }
cd "$(dirname "$0")/.." || exit 2
OUT=tests/evidence/gate_$LABEL; mkdir -p "$OUT"
LOG=$OUT/chain.log
s0=$(date +%s); n=0; ok=0
echo "CHAIN START label=$LABEL laps=$# $(date -u +%FT%TZ)" >> "$LOG"
for h in "$@"; do
    n=$((n+1))
    timeout 900 tests/capture_gate_sweep.sh ensure "$LABEL" "pre_$h" >> "$OUT/ensure_chain.log" 2>&1
    erc=$?
    s=$(date +%s)
    tests/capture_gate_sweep.sh lap "$LABEL" "$h" > "$OUT/lap_$h.out" 2>&1
    rc=$?
    r=$(grep -a '^RESULT' "$OUT/$h.log" 2>/dev/null | tail -1 | cut -c1-300)
    echo "CHAIN $h ensure_rc=$erc rc=$rc wall=$(( $(date +%s) - s ))s ${r:-no RESULT line}" >> "$LOG"
    [ "$rc" = 0 ] && ok=$((ok+1))
done
echo "CHAIN DONE laps=$n ok=$ok wall=$(( $(date +%s) - s0 ))s $(date -u +%FT%TZ)" >> "$LOG"
