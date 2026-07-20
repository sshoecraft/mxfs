#!/bin/bash
# RULE-4 decisive test: is the tcp_dlm_scaling MODE-B resurrection a TCP dir-EX
# DOUBLE-GRANT (two nodes hold the shared-dir inode EX overlapping) or a
# serialized-but-stale modify-reload?  Uses the non-perturbing lock-free P-LKT
# ring (mxfs.lockwr=1 via module load param) dumped post-mortem via lktdump.
#
# Foreground only (no run_in_background — see feedback-never-background-wait-poll).
#   usage: tests/tcp_lkt_doublegrant.sh [max_iters]
set -u
cd /src/mxfs
SSH=tools/mxfs_sshpass.sh; P=/tmp/.mxfs_pass
T1=$(getent hosts test1 | awk '{print $1}')
T2=$(getent hosts test2 | awk '{print $1}')
MAX="${1:-10}"

for i in $(seq 1 "$MAX"); do
    echo "==================== ITER $i ===================="
    for h in "$T1" "$T2"; do timeout 8 "$SSH" "$h" "$P" 'dmesg -C' >/dev/null 2>&1; done
    out=$(MXFS_EXTRA_MODARGS='lockwr=1' timeout 300 ./run.sh 2 tcp tcp_dlm_scaling 2>&1)
    echo "$out" | grep -E 'tcp_dlm_scaling|done:|PREP FAIL|ABORT'
    if echo "$out" | grep -q 'FAIL  tcp_dlm_scaling'; then
        echo ">>>>> FAILURE iter $i — capturing P-LKT ring <<<<<"
        # shared dir inode (varies per mkfs)
        dino=$(timeout 8 "$SSH" "$T1" "$P" 'stat -c %i /mnt/shared/.tcp_dlm_scaling 2>/dev/null' 2>/dev/null | tr -dc 0-9)
        echo "shared dir ino=$dino"
        echo "--- leftover dir contents ---"
        timeout 8 "$SSH" "$T1" "$P" 'ls -la /mnt/shared/.tcp_dlm_scaling 2>/dev/null' 2>&1 | grep -vE 'Warning|Unauth|If you|Pseudo'
        for h in "$T1" "$T2"; do
            tag=$([ "$h" = "$T1" ] && echo test1 || echo test2)
            # confirm lockwr was actually on, then dump the ring for this ino (master side has it)
            timeout 8 "$SSH" "$h" "$P" "echo lockwr=\$(cat /sys/module/mxfs/parameters/lockwr); echo ${dino:-0} > /sys/module/mxfs/parameters/lktdump" >/dev/null 2>&1
            echo "----- $tag P-LKT ring (ino=$dino) -----"
            timeout 10 "$SSH" "$h" "$P" "dmesg | grep -aE 'P-LKT|P-CONVBLK|REAFFIRM' | tail -80" 2>&1 | grep -vE 'Warning|Unauth|If you|Pseudo'
        done
        exit 0
    fi
done
echo "no failure in $MAX iters (lockwr recording was on; race may need more iters)"
