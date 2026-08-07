#!/bin/bash
# unmount_leak_check.sh — D-UNMOUNT-BUSY-INODES detector driver.
#
# Unmounts mxfs on every node, removes the module, and reports:
#   * P202-LEAKED-INODE-AT-UNLOAD  — an xfs_inode still allocated after the
#     rcu_barrier in xfs_destroy_caches, i.e. the object that makes
#     kmem_cache_destroy(mxfs_inode) report "Slab cache still has objects".
#   * the kernel's own "Slab cache still has objects" line, and the
#     fs/super.c generic_shutdown_super WARNing that precedes it.
#
# The point of P202 is attribution: the kernel says only "objects=N used=M",
# which names nothing.  P202 prints the inode number, refcount, VFS i_state,
# mode/nlink and every MXFS DLM field for each survivor.
#
# The cluster is left UNMOUNTED with the module removed — re-prep afterwards.
#
# USAGE: tests/unmount_leak_check.sh [nodes]
# EXIT:  0 = no leak on any node.  1 = leak detected.  2 = infra failure.
set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd -- "$SCRIPT_DIR/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"
N="${1:-32}"
MNT="${MXFS_MNT:-/mnt/shared}"

STAMP=$(date -u +%Y%m%d_%H%M%S)
OUT="$REPO/tests/logs/umleak_$STAMP"
mkdir -p "$OUT"

echo "=== unmount_leak_check: nodes=$N out=$OUT ==="

teardown() {
    cat <<EOF
set -u
echo "MXFS_UMLEAK_WINDOW_OPEN" > /dev/kmsg 2>/dev/null || true
umount "$MNT" 2>&1 || echo "UMOUNT-RC=\$?"
sync
for t in 1 2 3 4 5 6 7 8; do
    rmmod mxfs 2>/dev/null && break
    sleep 3
done
lsmod | grep -q '^mxfs' && echo "RMMOD-FAILED" || echo "RMMOD-OK"
EOF
}

for r in $(seq 1 "$N"); do
    ( timeout 180 "$SSH" "test$r" "bash -s" <<< "$(teardown)" > "$OUT/node$r.log" 2>&1 ) &
done
wait

for r in $(seq 1 "$N"); do
    ( timeout 60 "$SSH" "test$r" \
        "dmesg | awk '/MXFS_UMLEAK_WINDOW_OPEN/{f=1} f'" > "$OUT/dmesg$r.log" 2>&1 ) &
done
wait

leak=0; infra=0
for r in $(seq 1 "$N"); do
    grep -q "RMMOD-OK" "$OUT/node$r.log" || { echo "INFRA/RMMOD-FAIL test$r: $(tr '\n' ' ' < "$OUT/node$r.log" | tail -c 200)"; infra=1; }
    p202=$(grep -c "P202-LEAKED-INODE-AT-UNLOAD" "$OUT/dmesg$r.log" 2>/dev/null || true)
    slab=$(grep -c "Slab cache still has objects" "$OUT/dmesg$r.log" 2>/dev/null || true)
    warn=$(grep -c "generic_shutdown_super" "$OUT/dmesg$r.log" 2>/dev/null || true)
    if [ "${p202:-0}" -gt 0 ] || [ "${slab:-0}" -gt 0 ]; then
        leak=1
        echo "--- test$r: P202=$p202 slab_warn=$slab shutdown_super=$warn"
        grep -h "P202-LEAKED-INODE" "$OUT/dmesg$r.log" | head -6
        grep -h "Slab cache still has objects" "$OUT/dmesg$r.log" | head -2
    fi
done

echo "=== RESULT: leak=$leak infra=$infra  logs: $OUT ==="
[ "$infra" = "1" ] && exit 2
[ "$leak" = "1" ] && exit 1
echo "=== unmount_leak_check PASS: no leaked xfs_inode on any of $N nodes ==="
exit 0
