#!/bin/bash
# drc_hardhang_capture.sh — capture the kernel stack of a HARD-HUNG mxfs node
# (sess5 ccloop a864: reproducible spinlock deadlock, one CPU busy-spinning,
# network dead → SSH "No route to host" while virsh domstate=running).
#
# The VMs have no PMU (nmi_watchdog=0) so the hard-lockup detector can't fire.
# With kernel.unknown_nmi_panic=1 (pre-installed on all nodes), a QEMU-injected
# NMI forces a PANIC that dumps ALL CPU stacks (incl. the spinning one → the
# mxfs lock caller) to the serial console, captured at
# /var/log/libvirt/qemu/<node>-serial.log (append='on', survives the reboot).
#
# Usage: drc_hardhang_capture.sh <node>   (e.g. drc_hardhang_capture.sh test27)
set -u
NODE="${1:?usage: drc_hardhang_capture.sh <node>}"
SLOG="/var/log/libvirt/qemu/${NODE}-serial.log"

echo "=== $NODE domstate: $(virsh -c qemu:///system domstate "$NODE" 2>&1) ==="
pre=$(wc -c < "$SLOG" 2>/dev/null || echo 0)
echo "serial log pre-size=$pre bytes"

echo "=== injecting NMI (→ unknown_nmi_panic → stack dump) ==="
virsh -c qemu:///system inject-nmi "$NODE" 2>&1
# panic prints synchronously then waits kernel.panic secs before reboot
for w in 1 2 3 4 5 6 7 8; do
  sleep 1
  now=$(wc -c < "$SLOG" 2>/dev/null || echo 0)
  [ "$now" -gt "$pre" ] && break
done

echo "=== NEW serial output (panic backtrace) ==="
# print everything appended since pre, strip CRs
tail -c +$((pre+1)) "$SLOG" 2>/dev/null | tr -d '\r' | \
  grep -aE "Kernel panic|NMI|RIP:|Call Trace|mxfs|xfs_|dlm_|caw_|spin|rcu|__schedule|native_queued|<TASK>|CPU:|Hardware|lock|Code:" | head -80
echo "=== (full new output in $SLOG) ==="
