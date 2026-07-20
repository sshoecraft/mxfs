#!/bin/bash
# Concurrent cross-node rename coherency reproducer with ORCHESTRATOR-driven
# barriers (this shell waits for each phase on all nodes — no in-FS barrier,
# so barrier coherency cannot confound the result).
#
# Phase1: all nodes create N files (content_<id>_<i>) in a SHARED dir.
# Phase2: all nodes rename their files, sync.
# Phase3: each node stats+cats every node's files; reports per-writer
#         ok / empty(size) / missing.
#
# Usage: tests/repro_rename_concurrent.sh "test1 test2 test3 test4" [N]
set -u
NODES=(${1:-test1 test2 test3 test4})
N=${2:-20}
PASS=/tmp/.mxfs_pass
MNT=/mnt/shared
DIR="$MNT/.mxfs_test/rconc"
SSH="tools/mxfs_sshpass.sh"
TOTAL=${#NODES[@]}

phase_all() {  # run cmd-template on every node in parallel, wait all
  local tmpl="$1" to="$2"; local pids=()
  for idx in "${!NODES[@]}"; do
    local id=$((idx+1)) node="${NODES[$idx]}"
    local scr; scr=$(echo "$tmpl" | sed "s|%ID%|$id|g; s|%N%|$N|g; s|%TOTAL%|$TOTAL|g; s|%DIR%|$DIR|g")
    ( timeout "$to" $SSH "$node" "$PASS" "$scr" 2>/dev/null | sed "s/^/[$node] /" ) &
    pids+=($!)
  done
  for p in "${pids[@]}"; do wait "$p"; done
}

# reset
timeout 30 $SSH "${NODES[0]}" "$PASS" "rm -rf $DIR; mkdir -p $DIR; sync" 2>/dev/null

# Phase 1: create
phase_all 'for i in $(seq 1 %N%); do echo content_%ID%_${i} > %DIR%/n%ID%_before_${i}; done; sync; echo P1_DONE' 60

# Phase 2: rename
phase_all 'for i in $(seq 1 %N%); do mv %DIR%/n%ID%_before_${i} %DIR%/n%ID%_after_${i}; done; sync; echo P2_DONE' 60

sleep 3   # settle

# Phase 3: verify
phase_all '
fails=0
for w in $(seq 1 %TOTAL%); do
  ok=0; empty=0; miss=0; info=""
  for i in $(seq 1 %N%); do
    f=%DIR%/n${w}_after_${i}
    if [ ! -e "$f" ]; then miss=$((miss+1)); fails=$((fails+1)); continue; fi
    sz=$(stat -c %s "$f" 2>/dev/null); c=$(cat "$f" 2>/dev/null)
    if [ "$c" = "content_${w}_${i}" ]; then ok=$((ok+1));
    elif [ -z "$c" ]; then empty=$((empty+1)); fails=$((fails+1)); info="$info i${i}:sz${sz}";
    else fails=$((fails+1)); info="$info i${i}:WRONG";
    fi
  done
  [ $empty -gt 0 -o $miss -gt 0 ] && echo "  sees writer ${w}: ok=$ok empty=$empty miss=$miss [$info ]"
done
echo "TOTAL_FAILS=$fails"
' 60
