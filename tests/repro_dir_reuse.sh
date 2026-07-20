#!/bin/bash
# repro_dir_reuse.sh — reproduce the unlink_visibility "Not a directory" failure.
#
# Hypothesis: after a delete-storm frees many regular-file inodes, a concurrent
# mkdir of a shared barrier dir reuses one of those just-freed inode numbers; a
# peer that still has that inode cached as S_ISREG serves the stale inode on
# lookup -> ENOTDIR ("Not a directory") when touching a file inside it.
#
# Mirrors test_unlink_visibility's barrier sequence but tightly, on a fresh
# cluster, and reports any ENOTDIR.  Run AFTER tests/reset4.sh 4.
#
# Usage: tests/repro_dir_reuse.sh [N_NODES] [FILES_PER_NODE] [ROUNDS]
set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/criteria/lib.sh"

N=${1:-4}
FPN=${2:-30}
ROUNDS=${3:-10}
NODES=("${DEFAULT_NODES[@]:0:$N}")
M=/mnt/shared
PASS=/tmp/.mxfs_pass
SSH=/src/mxfs/tools/mxfs_sshpass.sh

run() { "$SSH" "$1" "$PASS" "$2" 2>&1 | grep -vE '^Warning|^Unauthorized|^If you'; }

echo "repro_dir_reuse: N=$N FPN=$FPN ROUNDS=$ROUNDS nodes=${NODES[*]}"

for r in $(seq 1 "$ROUNDS"); do
    D="$M/.mxfs_test/dr_round${r}"
    B="$M/.mxfs_barriers/dr_round${r}"
    run "${NODES[0]}" "mkdir -p $D $B/created $B/deleted; rm -f $B/created/* $B/deleted/*"
    # Phase 1: every node creates FPN files concurrently
    pids=()
    for idx in "${!NODES[@]}"; do
        nid=$((idx+1)); n="${NODES[$idx]}"
        run "$n" "for i in \$(seq 1 $FPN); do echo d_${nid}_\$i > $D/node${nid}_file\$i; done; touch $B/created/node${nid}" &
        pids+=($!)
    done
    wait "${pids[@]}"
    # barrier: all created
    run "${NODES[0]}" "while [ \$(ls $B/created 2>/dev/null | wc -l) -lt $N ]; do sleep 0.2; done" >/dev/null
    # Phase 2: every node deletes its files concurrently, then concurrently
    # mkdir the shared 'deleted' barrier dir + touch a marker (the suspect op).
    pids=(); declare -A out
    tmpd=$(mktemp -d)
    for idx in "${!NODES[@]}"; do
        nid=$((idx+1)); n="${NODES[$idx]}"
        run "$n" "for i in \$(seq 1 $FPN); do rm -f $D/node${nid}_file\$i; done; sync; mkdir -p $B/deleted && touch $B/deleted/node${nid} && echo OK_${nid} || echo FAILTOUCH_${nid}" \
            > "$tmpd/n${nid}" &
        pids+=($!)
    done
    wait "${pids[@]}"
    bad=0
    for idx in "${!NODES[@]}"; do
        nid=$((idx+1))
        if grep -q "Not a directory\|FAILTOUCH" "$tmpd/n${nid}"; then
            echo "ROUND $r: node${nid} FAILED: $(tr '\n' ' ' < "$tmpd/n${nid}")"
            bad=1
        fi
    done
    if [ "$bad" = "1" ]; then
        echo "ROUND $r: REPRODUCED ENOTDIR. uv-style barrier dir inode info:"
        run "${NODES[0]}" "ls -lid $B/deleted; stat -c 'ino=%i mode=%A' $B/deleted"
        rm -rf "$tmpd"
        exit 1
    else
        echo "ROUND $r: clean ($N/$N touched ok)"
    fi
    rm -rf "$tmpd"
done
echo "repro_dir_reuse: NO ENOTDIR in $ROUNDS rounds"
