#!/bin/bash
# mkdir_storm.sh — focused repro for the concurrent-mkdir dirent swallow
# (dlm_scaling run72 test4: all 32 nodes race `mkdir -p` of ONE fresh shared
# parent + immediately mkdir their own subdir into it; one node's subdir
# dirent durably vanished cluster-wide between its post-mkdir stat and its
# first file op — the r18/node9_f1 SHORTFORM-phase loss family).
#
# Each round, on an ALREADY-MOUNTED cluster (no prep, no reload):
#   1. rank1 rm -rf's the parent from test1
#   2. every node concurrently: mkdir -p parent && mkdir parent/nodeN
#      (the -p race means 31 nodes take EEXIST on the parent — the exact
#      dlm_scaling pattern)
#   3. settle 2s, then EVERY node counts parent entries; any node seeing
#      < N (or missing its OWN subdir) = HIT — stop, report round + victims.
#
# Run with instrumentation live-enabled first (no module reload needed):
#   for i in $(seq 1 N); do ssh testI 'echo 1 > /sys/module/mxfs/parameters/instr;
#                                      echo 1 > /sys/module/mxfs/parameters/dirwr'
# Usage: scripts/mkdir_storm.sh <N> <rounds>
set -u
N="${1:?usage: mkdir_storm.sh <N> <rounds>}"
ROUNDS="${2:-30}"
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"
PASS="${MXFS_PASS:-/tmp/.mxfs_pass}"
MNT="${MXFS_MOUNT:-/mnt/shared}"
P="$MNT/.mkdir_storm"

sq() { timeout "${3:-25}" "$SSH" "test$1" "$PASS" "$2" 2>/dev/null | grep -vE '^Warning:|^Unauthorized|^If you'; }

for r in $(seq 1 "$ROUNDS"); do
    sq 1 "rm -rf '$P'; sync" 40 >/dev/null
    # concurrent storm: parent mkdir -p race + own-subdir add
    for i in $(seq 1 "$N"); do
        ( sq "$i" "mkdir -p '$P' 2>/dev/null; mkdir '$P/node$i' 2>/dev/null; echo RC=\$?" ) >/dev/null &
    done
    wait
    sleep 2
    # verify from every node
    bad=""
    td=$(mktemp -d)
    for i in $(seq 1 "$N"); do
        ( sq "$i" "c=\$(ls '$P' 2>/dev/null | wc -l); o=\$([ -d '$P/node$i' ] && echo OK || echo MISSING); echo \"\$c \$o\"" > "$td/$i" ) &
    done
    wait
    for i in $(seq 1 "$N"); do
        read -r cnt own < "$td/$i" 2>/dev/null || { bad="$bad test$i(unreadable)"; continue; }
        [ "$cnt" = "$N" ] && [ "$own" = OK ] || bad="$bad test$i(cnt=$cnt own=$own)"
    done
    rm -rf "$td"
    if [ -n "$bad" ]; then
        echo "ROUND $r HIT:$bad"
        echo "parent view from test1: [$(sq 1 "ls '$P' 2>/dev/null | tr '\n' ' '")]"
        exit 1
    fi
    echo "round $r clean (all $N nodes see $N subdirs)"
done
echo "NO HIT in $ROUNDS rounds"
exit 0
