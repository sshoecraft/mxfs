#!/bin/bash
# repro_dirstress_rename.sh — faithful, state-preserving reproduction of
# the test_dir_stress Phase-3/4 failure: N nodes each create D subdirs
# (with files) in a SHARED parent dir, then each node renames its OWN
# subdirs (dirX -> renamedX) concurrently.  Parent dir is the contended
# resource.  Orchestrator-driven barriers (no in-FS barrier confound).
# Leaves all state intact for post-mortem inspection.
#
# Usage: tests/repro_dirstress_rename.sh "test1 ... testN" [DIRS_PER_NODE] [FILES_PER_DIR]
set -u
NODES=(${1:-test1 test2 test3 test4})
DPN=${2:-20}
FPD=${3:-10}
PASS=/tmp/.mxfs_pass
MNT=/mnt/shared
DIR="$MNT/.mxfs_test/dsr"
SSH=tools/mxfs_sshpass.sh
TOTAL=${#NODES[@]}

phase_all() {
  local tmpl="$1" to="$2"; local pids=()
  for idx in "${!NODES[@]}"; do
    local id=$((idx+1)) node="${NODES[$idx]}"
    local scr; scr=$(echo "$tmpl" | sed "s|%ID%|$id|g; s|%DPN%|$DPN|g; s|%FPD%|$FPD|g; s|%TOTAL%|$TOTAL|g; s|%DIR%|$DIR|g")
    ( timeout "$to" $SSH "$node" "$PASS" "$scr" 2>/dev/null | sed "s/^/[$node] /" ) &
    pids+=($!)
  done
  for p in "${pids[@]}"; do wait "$p"; done
}

# Parent dir created ONCE on node0 (like run_tests.sh pre-creates it on
# node1), then every node WAITS until it can see the parent before the
# concurrent phase — avoids a 16-way concurrent-mkdir split-brain on the
# parent path that is NOT what we are testing.
timeout 30 $SSH "${NODES[0]}" "$PASS" "rm -rf $DIR 2>/dev/null; mkdir -p $DIR; sync" 2>/dev/null
echo "=== waiting for parent dir visible on all nodes ==="
phase_all 'for t in $(seq 1 30); do [ -d %DIR% ] && { echo PARENT_OK; break; }; sleep 0.5; done' 25 | grep -c PARENT_OK | sed "s/^/  parent visible on /;s/$/\/$TOTAL nodes/"

echo "=== Phase 1: create $DPN dirs x $FPD files/node $(date -u +%T) ==="
phase_all 'for d in $(seq 1 %DPN%); do D=%DIR%/node%ID%_dir${d}; mkdir "$D" || echo "MKDIR_FAIL $D"; for f in $(seq 1 %FPD%); do echo n%ID%_d${d}_f${f} > "$D/file${f}"; done; done; sync; echo P1_DONE' 90 | grep -vE "^\[" >/dev/null
echo "  created."

echo "=== Phase 3: each node renames its own $DPN dirs $(date -u +%T) ==="
phase_all 'fail=0; for d in $(seq 1 %DPN%); do mv %DIR%/node%ID%_dir${d} %DIR%/node%ID%_renamed${d} || fail=$((fail+1)); done; sync; echo RENAME_FAIL=$fail' 90 | grep -E "RENAME_FAIL=[1-9]" || echo "  all mv returned 0 on all nodes"

sleep 2

echo "=== Phase 4: per-node visible renamed-dir count (expect $((TOTAL*DPN))) $(date -u +%T) ==="
phase_all 'r=$(ls -d %DIR%/node*_renamed* 2>/dev/null | wc -l); o=$(ls -d %DIR%/node*_dir* 2>/dev/null | wc -l); echo "renamed=$r old=$o"' 60

echo "=== STATE LEFT INTACT at $DIR ==="
