#!/bin/bash
# capture_agdeadlock.sh — reproduce the xfs_remove AG-DLM ABBA deadlock and
# capture blocked-task stacks on BOTH nodes during the P36-RETRY timeout window.
#
# The deadlock: a node in xfs_remove holds the shared dir's ILOCK_EXCL (and DLM
# EX) and blocks acquiring an AG DLM lock (type=3) for up to ~34s (P36-RETRY
# budget) before -ETIMEDOUT -> xfs_trans_cancel of a dirty trans -> shutdown.
# We catch it mid-stall and dump every D-state task on both nodes so the
# wait-for cycle (which thread holds what, waits on what) is direct evidence.
#
# Run ON clyde:  MXFS_PASS=/tmp/.mxfs_pass bash tests/tcp/capture_agdeadlock.sh [rounds] [iters]
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
S="$REPO/tools/mxfs_sshpass.sh"; P="${MXFS_PASS:-/tmp/.mxfs_pass}"
N1=test1; N2=test2
ROUNDS="${1:-150}"; ITERS="${2:-8}"
sshn() { timeout 30 bash "$S" "$1" "$P" "$2" 2>&1 | grep -vE '^Warning:|^Unauthorized|^If you'; }

echo "=== enable sysrq on both nodes ==="
for n in "$N1" "$N2"; do sshn "$n" "echo 1 > /proc/sys/kernel/sysrq"; done

echo "=== launch repro in background ($ROUNDS rounds x $ITERS iters) ==="
( timeout 300 bash "$REPO/tests/tcp/repro_rename_drain.sh" "$ROUNDS" "$ITERS" > /tmp/repro_agdl.log 2>&1 ) &
RPID=$!

echo "=== poll for P36-RETRY window ==="
CAPTURED=0
for i in $(seq 1 150); do
    h1=$(sshn "$N1" "dmesg | grep -c P36-RETRY" | grep -oE '[0-9]+' | tail -1)
    h2=$(sshn "$N2" "dmesg | grep -c P36-RETRY" | grep -oE '[0-9]+' | tail -1)
    if [ "${h1:-0}" -ge 3 ] || [ "${h2:-0}" -ge 3 ]; then
        echo "*** P36-RETRY window detected (n1=$h1 n2=$h2) at poll $i ***"
        for n in "$N1" "$N2"; do
            echo "================= $n ALL BLOCKED (D-state) TASKS ================="
            sshn "$n" "echo w > /proc/sysrq-trigger; sleep 1; dmesg | sed -n '/Show Blocked State/,\$p' | tail -300"
            echo "================= $n sysrq-t task stacks touching ag/inactive/ifree/inode_lock ================="
            sshn "$n" "echo t > /proc/sysrq-trigger; sleep 2; dmesg | grep -A18 -E 'mxfs_ag_dlm_lock|__mxfs_ag_dlm|mxfs_v5_dlm_ag|xfs_inactive|xfs_ifree|xfs_inodegc|mxfs_dlm_ag_bast|mxfs_ag_dlm_wait_demote' | grep -vE 'RIP|Code:|R[A-Z0-9]+:|CR2|PKRU|FS:|GS:|CS:' | head -120"
            echo "================= $n AG/dir P-state markers ================="
            sshn "$n" "dmesg | grep -E 'P36-RETRY|P102-ACQ|DLM AG lock|P51-REL|P119-NONEX|P58-DIRPIN|INACT|inodegc' | tail -25"
        done
        CAPTURED=1
        break
    fi
    sleep 2
done
[ "$CAPTURED" = 0 ] && echo "!!! no P36-RETRY window seen — repro may have leaked/shutdown another way; check /tmp/repro_agdl.log"
echo "=== repro log tail ==="
tail -15 /tmp/repro_agdl.log
kill "$RPID" 2>/dev/null
wait "$RPID" 2>/dev/null
echo "=== done ==="
