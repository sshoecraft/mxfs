#!/bin/bash
# Criterion: DLM/inode/block/dir cache caps honored — bounded memory.
# Verifier: read the configured caps from /sys/module/mxfs/parameters,
# drive a workload that exceeds them, sample the cache sizes via
# /sys/kernel/debug or via the module's exported sysfs/proc counters.
# Threshold: peak observed cache population <= cap * 1.1 (10% slack
# for LRU lag).
#
# Heuristic: if the module exports per-cache counters via
# /sys/kernel/debug/mxfs/{inode_cache_count,block_cache_count,
# dir_cache_count}, read them; else fall back to slabinfo for the
# kmem_caches the module creates (mxfs_inode_cache, mxfs_block_cache,
# mxfs_dir_cache).

set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/lib.sh"
result_init "cache_caps"
set_script_timeout 120

parse_common_args "$@"
NODE="${NODES[0]}"
teardown_all "$NODE"

# Mount a single-node mxfs; we can stress caches without a full cluster
fresh_cluster_mount "$NODE" \
    || result_fail "n/a" "mount-ok" "single-node mount failed"

# Read the configured caps
caps=$(ssh_node "$NODE" "
    for p in inode_cache_max block_cache_max dir_cache_max; do
        f=/sys/module/mxfs/parameters/mxfs_\$p
        if [ -e \$f ]; then echo \$p=\$(cat \$f); else echo \$p=unset; fi
    done
")
inode_cap=$(echo "$caps" | sed -n 's/inode_cache_max=//p' | tr -d ' \r\n')
block_cap=$(echo "$caps" | sed -n 's/block_cache_max=//p' | tr -d ' \r\n')
dir_cap=$(echo "$caps"   | sed -n 's/dir_cache_max=//p'   | tr -d ' \r\n')

# Drive a workload guaranteed to blow past inode cap: 5x the cap if known,
# else 50k files.
target_files=50000
if [ -n "$inode_cap" ] && [ "$inode_cap" != "unset" ] && [ "$inode_cap" -gt 0 ]; then
    target_files=$((inode_cap * 5))
    [ "$target_files" -gt 200000 ] && target_files=200000
fi

ssh_node_quiet "$NODE" "rm -rf $MXFS_MOUNT/cap_test; mkdir -p $MXFS_MOUNT/cap_test"
ssh_node "$NODE" "
    for k in \$(seq 1 $target_files); do
        echo x > $MXFS_MOUNT/cap_test/f\$k
    done
" >/dev/null

# Sample peak counts.  Try debugfs first, then slabinfo.
peak_inode=0; peak_block=0; peak_dir=0
for _ in $(seq 1 8); do
    counts=$(ssh_node "$NODE" "
        for f in inode_cache_count block_cache_count dir_cache_count; do
            p=/sys/kernel/debug/mxfs/\$f
            if [ -e \$p ]; then echo \$f=\$(cat \$p); fi
        done
        if [ ! -e /sys/kernel/debug/mxfs/inode_cache_count ]; then
            grep -E '^mxfs_(inode|block|dir)_cache ' /proc/slabinfo 2>/dev/null \
              | awk '{print \$1\"_active=\"\$2}'
        fi
    ")
    ic=$(echo "$counts" | sed -n 's/.*inode_cache_count=\([0-9]*\).*/\1/p; s/.*mxfs_inode_cache_active=\([0-9]*\).*/\1/p' | tail -1)
    bc=$(echo "$counts" | sed -n 's/.*block_cache_count=\([0-9]*\).*/\1/p; s/.*mxfs_block_cache_active=\([0-9]*\).*/\1/p' | tail -1)
    dc=$(echo "$counts" | sed -n 's/.*dir_cache_count=\([0-9]*\).*/\1/p;   s/.*mxfs_dir_cache_active=\([0-9]*\).*/\1/p'   | tail -1)
    ic=${ic:-0}; bc=${bc:-0}; dc=${dc:-0}
    [ "$ic" -gt "$peak_inode" ] && peak_inode=$ic
    [ "$bc" -gt "$peak_block" ] && peak_block=$bc
    [ "$dc" -gt "$peak_dir" ]   && peak_dir=$dc
    sleep 0.5
done

ssh_node_quiet "$NODE" "umount $MXFS_MOUNT 2>/dev/null; rmmod mxfs 2>/dev/null"

# Build measured/threshold lines, fail on any cap breach
check() {
    local name="$1" peak="$2" cap="$3"
    if [ -z "$cap" ] || [ "$cap" = "unset" ] || [ "$cap" = "0" ]; then
        echo "$name=$peak (cap=unset, skipped)"
        return 0
    fi
    local slack=$(( cap * 110 / 100 ))
    if [ "$peak" -gt "$slack" ]; then
        echo "$name=$peak BREACH (cap=$cap, slack=$slack)"
        return 1
    fi
    echo "$name=$peak ok (cap=$cap)"
    return 0
}

m1=$(check inode "$peak_inode" "$inode_cap"); rc1=$?
m2=$(check block "$peak_block" "$block_cap"); rc2=$?
m3=$(check dir   "$peak_dir"   "$dir_cap");   rc3=$?

measured="$m1 | $m2 | $m3"
threshold="peak<=cap*1.10"

if [ "$rc1" -ne 0 ] || [ "$rc2" -ne 0 ] || [ "$rc3" -ne 0 ]; then
    result_fail "$measured" "$threshold" "one or more caps exceeded"
fi
result_pass "$measured" "$threshold"
