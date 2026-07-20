#!/bin/bash
# RULE-4: capture the SHARED-DIR inode's clean cross-node P-LKT timeline at a
# tcp_dlm_scaling failure.  tcp_dlm_scaling.sh now pins lkt_ino to the dir inode
# (both nodes) and dumps on the rank1 drain-fail while still mounted, so the ring
# holds only the dir's cross-node grant/release events (no child flood).
# This driver runs with lockwr=1 and, on failure, dumps both nodes' rings.
# Foreground only (no run_in_background — feedback-never-background-wait-poll).
#   usage: tests/tcp_lkt_dirtrace.sh [max_iters]
set -u
cd /src/mxfs
SSH=tools/mxfs_sshpass.sh; P=/tmp/.mxfs_pass
T1=$(getent hosts test1 | awk '{print $1}')
T2=$(getent hosts test2 | awk '{print $1}')
MAX="${1:-12}"
PARAM=/sys/module/mxfs/parameters

for i in $(seq 1 "$MAX"); do
    echo "==================== ITER $i ===================="
    for h in "$T1" "$T2"; do timeout 8 "$SSH" "$h" "$P" 'dmesg -C' >/dev/null 2>&1; done
    out=$(MXFS_EXTRA_MODARGS='lockwr=1' timeout 300 ./run.sh 2 tcp tcp_dlm_scaling 2>&1)
    echo "$out" | grep -E 'tcp_dlm_scaling|done:|PREP FAIL|ABORT'
    if echo "$out" | grep -q 'FAIL  tcp_dlm_scaling'; then
        echo ">>>>> FAILURE iter $i <<<<<"
        # dir ino from the test-internal TDS-LEFTOVER line (captured while mounted)
        dino=$(timeout 8 "$SSH" "$T1" "$P" "dmesg | grep -a TDS-LEFTOVER | tail -1" 2>/dev/null | grep -oE 'ino=[0-9]+' | head -1 | tr -dc 0-9)
        echo "shared dir ino=$dino"
        timeout 8 "$SSH" "$T1" "$P" 'dmesg | grep -a TDS-LEFTOVER | tail -2' 2>&1 | grep -vE 'Warning|Unauth|If you|Pseudo'
        for h in "$T1" "$T2"; do
            tag=$([ "$h" = "$T1" ] && echo test1 || echo test2)
            # ring is already dir-filtered (lkt_ino set by the test) → dump all
            timeout 8 "$SSH" "$h" "$P" "echo 0 > $PARAM/lktdump" >/dev/null 2>&1
            echo "----- $tag P-LKT dir timeline -----"
            timeout 10 "$SSH" "$h" "$P" "dmesg | grep -aE 'P-LKT seq=' | tail -70" 2>&1 | grep -vE 'Warning|Unauth|If you|Pseudo'
            echo "----- $tag P-DIR-SEQ/P34D/P58/P-SFREL/CONVBLK -----"
            timeout 10 "$SSH" "$h" "$P" "dmesg | grep -aE 'P-DIR-SEQ|P34D-RELOAD|P58-STALE-BASE-ADD|P-SFREL|P-SF-DURABLE-FAIL|P-CONVBLK|DOUBLEGRANT' | tail -20" 2>&1 | grep -vE 'Warning|Unauth|If you|Pseudo'
        done
        exit 0
    fi
done
echo "no failure in $MAX iters"
