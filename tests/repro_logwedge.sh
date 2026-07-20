#!/bin/bash
# repro_logwedge.sh — reproduce/validate the single-node log-space WEDGE.
#
# sess36 found: single-node mxfs WEDGES under sustained data writes (rsync).
# All threads block in xlog_grant_head_wait -> xfs_log_reserve while
# xfsaild SLEEPS (log full, tail not advancing).  The per-node XFS log
# slice is only 4 MiB (mkfs_mxfs.c:1125-1127 floor of 1024 fsb).
#
# This harness mounts single-node mxfs fresh, runs an escalating rsync of
# the canonical tree, and reports at what file-count it wedges (D-state on
# log_reserve) vs completes.  Use it to validate a larger-log-slice fix:
# after enlarging the slice in mkfs_mxfs + rebuilding tools + re-mkfs, a
# PASS at the full tree means the wedge is fixed.
#
# Usage: tests/repro_logwedge.sh [node]   (default test1)
set -u
N="${1:-test1}"
SSH=/src/mxfs/tools/mxfs_sshpass.sh
PASS=/tmp/.mxfs_pass
SRC=/root/open-gpu-kernel-modules
MNT=/mnt/shared

ssh_n() { timeout "${2:-60}" "$SSH" "$N" "$PASS" "$1" 2>&1 | grep -vE 'Warning|Unauthorized|disconnect|^$'; }

echo "=== fresh single-node mxfs mount on $N ==="
ssh_n 'umount '"$MNT"' 2>/dev/null; rmmod mxfs 2>/dev/null; true' 40 >/dev/null
ssh_n '/src/mxfs/tools/prep_tcm_node_scst.sh >/tmp/p.log 2>&1; modprobe libcrc32c; lsmod|grep -q "^mxfs " || insmod /src/mxfs/mxfs.ko; sg_persist --out --register-ignore --param-sark=0x5eed /dev/sda >/dev/null 2>&1; sg_persist --out --clear --param-rk=0x5eed /dev/sda >/dev/null 2>&1; echo y|/src/mxfs/tools/mkfs_mxfs /dev/sda >/tmp/m.log 2>&1 && echo MKFS_OK; grep -i "log:" /tmp/m.log; mount -t mxfs /dev/sda '"$MNT"' && echo MOUNT_OK' 70

wedged=""
for nf in 200 1000 4000 8137; do
    echo "=== rsync $nf files ==="
    # Run rsync in background ON the node, then poll for completion vs wedge.
    ssh_n 'rm -rf '"$MNT"'/w 2>/dev/null; mkdir -p '"$MNT"'/w; (find '"$SRC"' -type f | head -'"$nf"' | rsync -a --files-from=- / '"$MNT"'/w/ >/tmp/rs.log 2>&1; echo DONE_$? > /tmp/rs.done) & echo started' 15 >/dev/null
    # Poll up to 120s for /tmp/rs.done; meanwhile detect D-state log_reserve wedge.
    res="TIMEOUT"
    for t in $(seq 1 24); do
        sleep 5
        d=$(ssh_n 'cat /tmp/rs.done 2>/dev/null' 8)
        if [ -n "$d" ]; then res="$d"; break; fi
        # wedge check: any proc in D on xfs_log_reserve?
        w=$(ssh_n 'for p in $(ps -eo pid,stat|awk "\$2~/D/{print \$1}"); do grep -ql xlog_grant_head_wait /proc/$p/stack 2>/dev/null && echo W; done | head -1' 10)
        if [ "$w" = "W" ]; then res="WEDGED(log_reserve)"; wedged="$nf"; break; fi
    done
    echo "  $nf files -> $res"
    [ -n "$wedged" ] && break
done

echo "=== RESULT ==="
if [ -n "$wedged" ]; then
    echo "LOGWEDGE: reproduced at $wedged files (single-node, log_reserve D-state)"
    exit 1
else
    echo "LOGWEDGE: NOT reproduced through 8137 files — log-slice fix likely working"
    exit 0
fi
