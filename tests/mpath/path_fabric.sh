#!/bin/bash
# tests/mpath/path_fabric.sh — F3 of docs/mpath-verification.md: a whole
# storage network is lost.  Every node's path on network a goes down at once
# (a switch or a fabric dying), comes back, is reinstated everywhere, and then
# every node's path on network b goes down.
#
# Host-coordinated, on a mounted cluster under tests/mpath/pathload.py on every
# node.  This is the failover every node performs TOGETHER: each is stalled
# for its own path switch while the locks it needs are held by peers that are
# stalled too.
#
# What a PASS claims, for each of the two losses: no operation errored on any
# node; every node's longest stall is under the bound of
# tools/mpath_settings.sh; on every node the network left standing completed
# writes in the second half of the window and the lost one none.  And for the
# row: every returned path reinstated within 60 s; no double grant; no node
# left, shut down or was fenced; the target's reservation keys unchanged;
# every acknowledged file read back intact from another node.
#
# derived time budget: warm-up 20 s + loss 60 s + reinstatement on every node
# (bound 60 s) + loss 60 s + reinstatement (bound 60 s) + stop, verify and
# audit ~6 s per node.  Typical at 2 nodes ~200 s.
set -u
ROW=path_fabric
. "$(dirname "$0")/lib.sh"
HOLD=${PF_HOLD_S:-60}
main() {
[ "$N" -ge 2 ] || { why="needs 2 nodes, got $N"; finish FAIL "nodes=$N"; exit 1; }
pf_start_gate
pf_load_start

loss() {  # <down net> <kept net> <tag>
    local down=$1 kept=$2 tag=$3 T0 T1 n
    T0=$(now_ms)
    links "$down" down
    echo "  INFO $tag: network $down DOWN on all $N nodes at $(date -u +%T), holding ${HOLD}s"
    sleep $((HOLD / 2))
    states "${tag}_mid"
    sleep $((HOLD - HOLD / 2))
    states "${tag}_end"
    T1=$(now_ms)
    for n in $NODES; do pf_carried "$n" "$tag" "$kept" "$down"; done
    pf_window "$tag" "$T0" "$T1"
}
restore() {  # <net> <tag>: back up everywhere, every node reinstates it
    local worst
    links "$1" up
    worst=$(wait_usable_all "$2")
    cklt "$2: every node reinstated its path on $1, slowest in seconds" "$worst" 61
    echo "$worst"  > "$OUT/reinstate_$1.txt"
}

loss a b F3a
restore a F3a_reinstated
loss b a F3b
restore b F3b_reinstated

pf_load_stop
pf_verify
pf_health
worst_a=$(awk '$1 == "F3a"' "$OUT/stalls.txt" | sed -n 's/.*max_ms=\([0-9]*\).*/\1/p' | sort -n | tail -1)
worst_b=$(awk '$1 == "F3b"' "$OUT/stalls.txt" | sed -n 's/.*max_ms=\([0-9]*\).*/\1/p' | sort -n | tail -1)
pf_done "nodes=$N worst_stall_a_ms=$worst_a worst_stall_b_ms=$worst_b reinstate_a_s=$(cat "$OUT/reinstate_a.txt") reinstate_b_s=$(cat "$OUT/reinstate_b.txt")"
}
main 2>&1 | tee "$OUT/row.log"
exit "${PIPESTATUS[0]}"
