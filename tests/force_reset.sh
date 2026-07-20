#!/bin/bash
# force_reset.sh — forcibly clear a wedged/shut-down mxfs mount + module on the
# given nodes so the next ./run.sh prep can load a fresh build.
#
# A shut-down/self-fenced FS returns EIO to a plain umount and pins the module
# (refcnt>0) so rmmod fails.  This does the proven recovery sequence:
#   umount -f  (force, tears down a shut-down FS)  -> umount -l (lazy fallback)
#   -> rmmod retry loop (module can be briefly busy after umount).
#
# Usage:  tests/force_reset.sh [node ...]      (default: test1 test2)
# Run from the repo root (uses tools/mxfs_sshpass.sh + /tmp/.mxfs_pass).

REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"
PF="${MXFS_PASS:-/tmp/.mxfs_pass}"
MNT="${MXFS_MOUNT:-/mnt/shared}"
NODES=("$@")
[ "${#NODES[@]}" -eq 0 ] && NODES=(test1 test2)

for n in "${NODES[@]}"; do
    echo "===== force_reset $n ====="
    timeout 90 bash "$SSH" "$n" "$PF" "
        if mountpoint -q '$MNT'; then
            umount '$MNT' 2>/dev/null \
                || timeout 25 umount -f '$MNT' 2>/dev/null \
                || umount -l '$MNT' 2>/dev/null || true
        fi
        if lsmod | grep -q '^mxfs'; then
            for i in \$(seq 1 8); do rmmod mxfs 2>/dev/null && break; sleep 3; done
        fi
        if lsmod | grep -q '^mxfs'; then
            echo 'STILL LOADED refcnt='\$(cat /sys/module/mxfs/refcnt 2>/dev/null)
        else
            echo 'UNLOADED OK'
        fi
    " 2>&1 | grep -vE '^Warning:|^Unauthorized|^If you|^$'
done
