#!/bin/bash
# sess119: concurrent same-dir create -> inode-cluster corruption (error 117 in
# xfs_imap_to_bp) detector.  Reproduces the cross_visibility workload (all nodes
# mkdir -p a shared dir then concurrently create their file + sync) WITHOUT
# clearing dmesg mid-run, then mines every node's P90-PICK alloc trace for a
# DUPLICATE inode (same ino picked by >1 slot = cross-node AG free-space
# double-alloc, or same slot twice = local stale-inobt) and reports any
# EFSCORRUPTED / metadata I/O error.  instr stays 0 (the race needs full speed).
set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/criteria/lib.sh"

NODES_LIST=(test1 test2 test3 test4)
N=${#NODES_LIST[@]}
M="$MXFS_MOUNT"
ITERS="${1:-20}"

echo "=== teardown + fresh mkfs/mount (instr=0) ==="
teardown_all "${NODES_LIST[*]}"
INSMOD_OPTS="instr=0" fresh_cluster_mount "${NODES_LIST[0]}" "${NODES_LIST[@]:1}" \
    || { echo MOUNT_FAIL; exit 1; }

for n in "${NODES_LIST[@]}"; do ssh_node_quiet "$n" "dmesg -C"; done

for it in $(seq 1 "$ITERS"); do
    CV="$M/.mxfs_test/cvrepro_$it"
    for i in $(seq 1 $N); do
        n="${NODES_LIST[$((i-1))]}"
        ssh_node "$n" "mkdir -p $CV 2>/dev/null; echo 'hello from node $i' > $CV/node$i.txt; sync" >/dev/null &
    done
    wait
    sleep 1

    # visibility check
    anymiss=0
    for i in $(seq 1 $N); do
        n="${NODES_LIST[$((i-1))]}"
        miss=$(ssh_node "$n" "for j in \$(seq 1 $N); do [ -f $CV/node\$j.txt ] || echo -n \"n\$j \"; done" 2>/dev/null)
        [ -n "$miss" ] && { anymiss=1; echo "iter $it: node$i MISSING [$miss]"; }
    done

    # corruption check
    corrupt=0
    for n in "${NODES_LIST[@]}"; do
        c=$(ssh_node_quiet "$n" "dmesg | grep -aciE 'EFSCORRUPTED|metadata I/O error|badmagic|Corruption|error 117'" 2>/dev/null | tr -dc '0-9')
        [ -n "$c" ] && [ "$c" != "0" ] && { corrupt=1; echo "iter $it: node($n) CORRUPTION count=$c"; }
    done

    [ "$anymiss" = "0" ] && [ "$corrupt" = "0" ] && { echo "iter $it: clean"; continue; }

    echo "=== iter $it: ISSUE (miss=$anymiss corrupt=$corrupt) — collecting evidence ==="
    # gather all P90-PICK across nodes, find duplicate inos
    tmp=$(mktemp)
    for n in "${NODES_LIST[@]}"; do
        ssh_node_quiet "$n" "dmesg | grep -aE 'P90-PICK'" 2>/dev/null | sed "s/^/[$n] /" >> "$tmp"
    done
    echo "--- duplicate inode allocations (ino picked >1x) ---"
    grep -aoE "ino=[0-9]+" "$tmp" | sort | uniq -c | awk '$1>1{print}' | head -20
    echo "--- P90-PICK lines for those dup inos ---"
    for dino in $(grep -aoE "ino=[0-9]+" "$tmp" | sort | uniq -c | awk '$1>1{print $2}' | head -8); do
        echo "  >>> $dino"
        grep -aE "$dino " "$tmp" | head -8
    done
    echo "--- corruption/imap lines ---"
    for n in "${NODES_LIST[@]}"; do
        ssh_node_quiet "$n" "dmesg | grep -aiE 'EFSCORRUPTED|metadata I/O error|imap_to_bp|badmagic|shutdown' | tail -4" 2>/dev/null | sed "s/^/[$n] /"
    done
    rm -f "$tmp"
    echo "=== stopping at first issue (iter $it) ==="
    break
done
echo "=== DONE ==="
