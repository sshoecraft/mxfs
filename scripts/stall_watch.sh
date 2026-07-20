#!/bin/bash
# stall_watch.sh — node-side stall watcher (sess7 ccloop 8ba7ae5c).
#
# Runs ON a test node in the background.  Polls dmesg for the AG-drain stall
# signature (P67-AG-BAST-STALL / hung-task) and, on first detection, fires
# sysrq-w (dump all blocked/D-state tasks) so the folio-lock HOLDER's stack is
# captured in the kernel journal alongside the waiter stacks.  One shot per
# invocation (sysrq-w is expensive; a second dump adds nothing).
#
# Usage (from clyde):  ssh testN 'nohup /tmp/stall_watch.sh <secs> >/dev/null 2>&1 &'
DUR="${1:-420}"
END=$(( $(date +%s) + DUR ))
echo 1 > /proc/sys/kernel/sysrq 2>/dev/null
while [ "$(date +%s)" -lt "$END" ]; do
    if dmesg | tail -80 | grep -qE 'P67-AG-BAST-STALL|blocked for more than'; then
        echo "mxfs-stall-watch: signature seen, firing sysrq-w" > /dev/kmsg
        echo w > /proc/sysrq-trigger
        sleep 2
        # also dump workqueue + locks state for good measure (harmless if absent)
        echo t > /dev/null   # (sysrq-t too heavy; skip)
        exit 0
    fi
    sleep 5
done
exit 0
