#!/bin/bash
# repro_sfblock_corrupt.sh — sess77 (run 14d31183) minimal reproducer for the
# DURABLE directory-inode format/content corruption that shuts down one node
# under the 16-node concurrent same-dir create storm (posix_multi16 root).
#
# Faithfully mirrors tests/lib/cluster.sh::barrier_signal, which is what the
# cluster-phase tests do and what corrupts cwr_write:
#   EVERY node concurrently:  mkdir -p D/parent ; mkdir -p D/parent/<name> ;
#                             touch D/parent/<name>/node<ID>
# i.e. a concurrent same-path mkdir create-race on the shared dir, followed by
# 16 concurrent distinct-entry adds that grow it shortform -> block.
#
# After each round, ALL nodes `ls` the dir; ANY "Structure needs cleaning"
# (EFSCORRUPTED) or a per-node FS shutdown is the bug.  Loops ROUNDS times with
# a fresh barrier name each round to catch the intermittent corruption.
#
# Usage: tests/repro_sfblock_corrupt.sh [nodes_csv] [rounds]
set -u
NODES_CSV="${1:-$(seq -s, -f 'test%g' 1 16)}"
ROUNDS="${2:-20}"
IFS=',' read -r -a NODES <<< "$NODES_CSV"
N=${#NODES[@]}
SSH=/src/mxfs/tools/mxfs_sshpass.sh
PASS=/tmp/.mxfs_pass
MNT=/mnt/shared
PARENT="$MNT/.repro_sfb_$$"

run() { timeout 30 "$SSH" "$1" "$PASS" "$2" 2>/dev/null | grep -vE 'Warning|Unauthorized|disconnect|^$'; }

echo "=== repro_sfblock_corrupt: $N nodes, $ROUNDS rounds, parent=$PARENT ==="
run "${NODES[0]}" "mkdir -p $PARENT; sync"

bad=0
for r in $(seq 1 "$ROUNDS"); do
    name="b${r}"
    D="$PARENT/$name"
    TD="$PARENT/td${r}"
    run "${NODES[0]}" "mkdir -p $TD" >/dev/null
    # Phase 0: every node concurrently writes 2 files into a SHARED TESTDIR
    # (grows it block/leaf) — mirrors cross_write_read data_nodeN + .md5 — THEN
    # Phase 1: the barrier_signal create-race sequence (concurrent mkdir -p of
    # the SAME dir D + distinct touch).  This is the full cross_write_read shape.
    for idx in "${!NODES[@]}"; do
        id=$((idx+1))
        # Each node: spawn a 6s background readdir storm (PR pressure on BOTH
        # the shared TESTDIR and barrier dir) THEN do the file-create + barrier
        # create-race (EX) — so EX creates race against cross-node PR readdir,
        # the sess50 writer-starvation / read-during-write coherency trigger.
        ( run "${NODES[$idx]}" "
            ( end=\$((SECONDS+2)); while [ \$SECONDS -lt \$end ]; do ls $D >/dev/null 2>&1; done ) &
            dd if=/dev/zero of=$TD/data_node$id bs=64k count=1 2>/dev/null
            echo cs > $TD/data_node$id.md5
            sync
            mkdir -p $D 2>/dev/null
            touch $D/node$id 2>&1
            wait" >/dev/null ) &
    done
    wait
    # Phase 2: every node lists D; detect EFSCORRUPTED / shutdown
    rbad=0
    csum=""
    for idx in "${!NODES[@]}"; do
        n="${NODES[$idx]}"
        out=$(run "$n" "ls $D 2>&1 | grep -c '^node'; ls $D 2>&1 | grep -iE 'Structure needs cleaning|Input/output error' | head -1")
        cnt=$(echo "$out" | head -1)
        err=$(echo "$out" | tail -n +2)
        if [ -n "$err" ]; then
            echo "round $r: $n ERROR: $err"
            rbad=1
        fi
        csum="$csum $n=$cnt"
    done
    if [ "$rbad" = 1 ]; then
        bad=$((bad+1))
        echo "round $r: CORRUPTION DETECTED  counts:$csum"
        # which nodes shut down?
        for idx in "${!NODES[@]}"; do
            n="${NODES[$idx]}"
            sd=$(run "$n" "dmesg | grep -c 'Shutting down filesystem'")
            [ "${sd:-0}" -gt 0 ] && echo "    $n shutdowns=$sd"
        done
        break
    else
        echo "round $r: ok  counts:$csum"
    fi
done

echo "=== RESULT: corruption_rounds=$bad / $ROUNDS ==="
[ "$bad" = 0 ] && echo "RESULT: PASS (no corruption)" || echo "RESULT: FAIL (durable dir corruption reproduced)"
