#!/bin/bash
# Repro tcp_dlm_scaling failure and capture always-on DLM detectors from both
# nodes' dmesg at the failing run.  RULE-4 evidence collector.
#   usage: tests/tcp_scaling_capture.sh [max_iters]
set -u
cd /src/mxfs
SSH=tools/mxfs_sshpass.sh; P=/tmp/.mxfs_pass
T1=$(getent hosts test1 | awk '{print $1}')
T2=$(getent hosts test2 | awk '{print $1}')
MAX="${1:-8}"
DETECT='P58-STALE-BASE-ADD|P58-SELFSKIP-STALE-DIR|P91-RELOAD-PROTECT|P36-RELOAD-SELFSKIP|P-CONVBLK|P106|drained|got='

for i in $(seq 1 "$MAX"); do
    echo "==================== ITER $i ===================="
    # clear dmesg on both nodes
    for h in "$T1" "$T2"; do timeout 8 "$SSH" "$h" "$P" 'dmesg -C' >/dev/null 2>&1; done
    out=$(timeout 300 ./run.sh 2 tcp tcp_dlm_scaling 2>&1)
    verdict=$(echo "$out" | grep -E 'tcp_dlm_scaling|done:')
    echo "$verdict"
    if echo "$out" | grep -q 'FAIL  tcp_dlm_scaling'; then
        echo ">>>>> FAILURE at iter $i — dumping detectors <<<<<"
        # Trigger blocked-task dump while (hopefully) still wedged.
        for h in "$T1" "$T2"; do timeout 8 "$SSH" "$h" "$P" 'echo w > /proc/sysrq-trigger' >/dev/null 2>&1; done
        for h in "$T1" "$T2"; do
            tag=$([ "$h" = "$T1" ] && echo test1 || echo test2)
            echo "----- $tag dmesg detectors -----"
            timeout 10 "$SSH" "$h" "$P" "dmesg | grep -aE '$DETECT' | tail -40" 2>&1 | grep -vE 'Warning|Unauth|If you|Pseudo'
            echo "----- $tag blocked-task stacks (rm/mv/echo/touch) -----"
            timeout 10 "$SSH" "$h" "$P" "dmesg | grep -aA20 'sysrq.*Show Blocked\|blocked for more' | grep -aE 'task:|Call Trace|mxfs_|xfs_|ag_dlm|inode_lock|pending_wait|__schedule|D stack|task:(rm|mv|echo|touch)' | tail -60" 2>&1 | grep -vE 'Warning|Unauth|If you|Pseudo'
        done
        echo "----- shared dir contents (test1) -----"
        timeout 10 "$SSH" "$T1" "$P" 'ls -la /mnt/shared/.tcp_dlm_scaling 2>/dev/null; stat -c "%n nlink=%h" /mnt/shared/.tcp_dlm_scaling/* 2>/dev/null' 2>&1 | grep -vE 'Warning|Unauth|If you|Pseudo'
        exit 0
    fi
done
echo "no failure in $MAX iters"
