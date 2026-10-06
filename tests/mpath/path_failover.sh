#!/bin/bash
# tests/mpath/path_failover.sh — F1 and F2 of docs/mpath-verification.md: one
# node loses a path under load, gets it back, and then loses the other.
#
#   F1 failover                 path a of the victim goes down; its I/O must
#                               continue on path b
#   F2 path recovery and        a comes back and multipathd reinstates it;
#      failback usability       then b goes down, and the I/O must continue on
#                               the path that returned
#
# F2 is reinstatement, not automatic failback: under `failback manual`
# multipath leaves I/O where it is when a path returns, so taking the other
# path away is what proves the returned one works.
#
# Host-coordinated (run on clyde by run.sh, or by hand on a mounted cluster):
#   MXFS_NODES=<n> MXFS_NODE_LIST=<a,b,..> MXFS_RUN_ID=<id> tests/mpath/path_failover.sh
# The victim is the last node of the list.  Every node runs the load
# (tests/mpath/pathload.py); a path is taken away from outside the node, at
# the hypervisor (scripts/san_net.sh link).
#
# What a PASS claims, for each of the two faults:
#   - no operation of the load returned an error on any node;
#   - every node's longest gap between completed operations is under the
#     bound of tools/mpath_settings.sh (measured from the load's own log: T1
#     the last completion before the gap, T2 the first after);
#   - on the victim the path left standing completed writes in the second
#     half of the fault window and the path taken away completed none;
# and for the whole row:
#   - multipathd reinstated each returned path (2 usable) within 60 s;
#   - the mutual-exclusion witness saw no double grant;
#   - no node shut down, withdrew, was declared dead or saw membership drop;
#   - the target holds the same reservation keys at the end as at the start,
#     each node's on every path;
#   - every file a node's load acknowledged reads back with its checksum from
#     ANOTHER node.
# It does not claim the cold structure of the platter: the board's chk_clean
# row, which follows the path rows, is that.
#
# derived time budget: warm-up 20 s + fault 60 s + reinstatement (measured
# 15-18 s, bound 60 s) + fault 60 s + reinstatement + stop, verify and audit
# ~6 s per node.  Measured 217-234 s at 2 nodes.
set -u
ROW=path_failover
. "$(dirname "$0")/lib.sh"
HOLD=${PF_HOLD_S:-60}
main() {
[ "$N" -ge 2 ] || { why="needs 2 nodes, got $N"; finish FAIL "nodes=$N"; exit 1; }
pf_start_gate
pf_load_start

fault() {  # <down net> <kept net> <tag>: the victim's path on <down net> away for $HOLD s
    local down=$1 kept=$2 tag=$3 T0 T1
    T0=$(now_ms)
    link "$V" "$down" down
    echo "  INFO $tag: $V path $down (portal $(portal_of "$down")) DOWN at $(date -u +%T), holding ${HOLD}s"
    sleep $((HOLD / 2))
    state "$V" "${tag}_mid"
    sleep $((HOLD - HOLD / 2))
    state "$V" "${tag}_end"
    T1=$(now_ms)
    pf_carried "$V" "$tag" "$kept" "$down"
    pf_window "$tag" "$T0" "$T1"
}

fault a b F1
link "$V" a up
ra=$(wait_usable "$V" F2_reinstated_a)
cklt "F2: multipathd reinstated the returned path a, seconds" "$ra" 61
fault b a F2
link "$V" b up
rb=$(wait_usable "$V" end_reinstated_b)
cklt "end: multipathd reinstated the returned path b, seconds" "$rb" 61

pf_load_stop
pf_verify
pf_health
pf_done "victim=$V f1_stall_ms=$(stall_of F1 "$V") f2_stall_ms=$(stall_of F2 "$V") reinstate_a_s=$ra reinstate_b_s=$rb"
}
main 2>&1 | tee "$OUT/row.log"
exit "${PIPESTATUS[0]}"
