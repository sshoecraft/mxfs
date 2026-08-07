#!/bin/bash
# mxfs_stallsample.sh — node-side D-state stack sampler.
#
# Runs ON a test node (invoked from /src/mxfs/tests, which is NFS-mounted there),
# so no heredoc has to survive an ssh round-trip — an earlier version tried that
# and silently failed to start.
#
# Every INTERVAL seconds, records every task in D state together with its kernel
# stack. Sampled STATE, not cumulative counters, so unlike probe counts it needs
# no baseline and cannot saturate against a per-module-load cap.
#
# Usage (on the node): /src/mxfs/tests/mxfs_stallsample.sh [interval_s] > /root/stall.log
set -u
INT="${1:-3}"
# Own pidfile so the launcher can stop us WITHOUT `pkill -f mxfs_stallsample`:
# that pattern matches the launching ssh payload's own command line and killed
# the remote shell outright (zero output, "sampler did not start"). Same
# self-match trap as `pkill -f <harness>` locally.
echo $$ > /root/stallsample.pid
while :; do
    echo "=== $(cut -d. -f1 /proc/uptime) ==="
    for p in /proc/[0-9]*; do
        read -r _ _ st _ < "$p/stat" 2>/dev/null || continue
        [ "$st" = D ] || continue
        echo "--- pid=${p#/proc/} comm=$(cat "$p/comm" 2>/dev/null)"
        head -14 "$p/stack" 2>/dev/null
    done
    sleep "$INT"
done
