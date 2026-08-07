#!/bin/bash
# census_p.sh — parallel per-node dmesg pattern census for the 32-node rig.
#   tests/census_p.sh <nodes> "<remote shell snippet>"
# Runs the snippet on test1..testN in parallel (12s timeout each), prints
# each node's output prefixed with "testN ".  Job-control noise suppressed.
# The snippet sees a clean root shell; quote it single-quoted.
# sess36: replaces ad-hoc for-loops whose bash job table spammed the log.
set +m
N=${1:?nodes}
SNIP=${2:?snippet}
TOOLS_DIR="$(cd "$(dirname "$0")/../tools" && pwd)"
D=$(mktemp -d)
for n in $(seq 1 "$N"); do
	{ timeout 12 "$TOOLS_DIR/mxfs_sshpass.sh" "test$n" "$SNIP" \
		> "$D/n$n" 2>/dev/null; } &
done
wait 2>/dev/null
for n in $(seq 1 "$N"); do
	[ -s "$D/n$n" ] && sed "s/^/test$n /" "$D/n$n"
done
