#!/bin/bash
# tests/mpath/sf_refresh_read_fail.sh — does a failed platter read in the
# shortform-directory coherence check corrupt a shared directory?
#
# mxfs_dir_sf_refresh_if_disk_differs is the mandatory adopt of the platter
# image for a shortform directory whose in-core fork is proven stale
# (dir_gen > loaded_gen).  When its FUA read fails it returns and the caller
# goes on with the stale fork.  Path faults made such reads fail thousands of
# times (21 attempts on the cut path, DID_NO_CONNECT), and a cold audit after a
# path lap once found a churn name in the shared directory naming a freed,
# reused inode.  This row makes those reads fail on purpose, with no path
# fault: PF_KNOBS="dbg_sf_refresh_read_fail=<N>" takes the next N reads made
# while the fork is proven stale, on every node, and each logs
# P-SF-REFRESH-READ-FAIL.  With the knob at 0 the same row is the control.
#
# Run it, then the cold audit, on one prepared group:
#   tests/mpath/lap_chain.sh row <config> <group> <run> tests/mpath/sf_refresh_read_fail.sh \
#       --budget 300 --knobs "dbg_sf_refresh_read_fail=2000"
#   ./run.sh <config> --group <group> chk_clean
#
# What a PASS claims: every node's load ran with no operation error, every
# acknowledged file reads back from another node, no node shut down or left,
# and (with the knob set) the injection was reached on at least one node.  The
# directory structure itself is judged by chk_clean, which must follow.
#
# derived time budget: warm-up 20 s + load PF_HOLD_S (120 s) + stop, verify
# and health ~6 s per node: ~170 s at 2 nodes; --budget 300.
set -u
ROW=sf_refresh_read_fail
. "$(dirname "$0")/lib.sh"
HOLD=${PF_HOLD_S:-120}
main() {
[ "$N" -ge 2 ] || { why="needs 2 nodes, got $N"; finish FAIL "nodes=$N"; exit 1; }
pf_start_gate
pf_load_start
echo "  INFO load running on $NODES, holding ${HOLD}s (knobs: ${PF_KNOBS:-none})"
sleep "$HOLD"
pf_load_stop
pf_verify
inj=0
for n in $NODES; do
    c=$(rs 20 "$n" "grep -ac 'P-SF-REFRESH-READ-FAIL' $KFILE" 2>/dev/null | grep -aE '^[0-9]+$' | tail -1)
    echo "  INFO $n: shortform refresh reads reported failed: ${c:-unread}"
    inj=$((inj + ${c:-0}))
done
case "${PF_KNOBS:-}" in
    *dbg_sf_refresh_read_fail=[1-9]*)
        ck "the injection was reached (failed refresh reads on any node > 0)" "$([ "$inj" -gt 0 ] && echo yes || echo no)" yes ;;
esac
pf_health
pf_done "injected=$inj hold_s=$HOLD"
}
main 2>&1 | tee "$OUT/row.log"
exit "${PIPESTATUS[0]}"
