#!/bin/bash
# tune_iscsi_tcp.sh — fix the concurrent-large-transfer collapse on the
# iSCSI test fabric (sess22, ccloop 14d31183, scaling_curve root cause).
#
# SYMPTOM: a single initiator stream reads the shared LUN at ~950 MB/s,
# but ANY two concurrent >=512KB-class streams (same node or different
# nodes, even a loopback initiator on the SCST host) collapse to
# ~60-130 MB/s EACH — per-command latency inflates ~9x.  Reproducer:
#   dd if=/dev/sda of=/dev/null bs=1M count=512 iflag=direct   (x2 in parallel)
#
# ROOT CAUSE (proven via ss -ti on the iSCSI connection): open-iscsi
# sets an explicit SO_RCVBUF/SO_SNDBUF (node.conn[0].tcp.window_size,
# default 512KB).  An explicit setsockopt is clamped by
# net.core.rmem_max/wmem_max (Ubuntu default 212992) AND disables TCP
# receive-window autotuning.  The advertised window pins at ~91-418KB
# (1-2 jumbo segments on loopback), so >=1MB of in-flight data thrashes
# on zero-window stalls, delayed ACKs (ato:40) and retransmits.  One
# QD1 stream stays inside the window and never notices.
#
# FIX: raise the kernel socket-buffer caps to 16MB and tell open-iscsi
# to request a 16MB window, on the SCST host and every initiator node.
# After this, dual-stream aggregate scales (1.9 GB/s observed).
#
# Usage: scripts/tune_iscsi_tcp.sh [node ...]   (default test1..test16)
# Idempotent.  Nodes need an iSCSI session re-login (or reboot) for the
# new window to take effect — fresh_cluster_mount/cluster_reset reboots
# or the next session re-login picks it up; this script re-logs the
# session itself when the LUN is not in use.
set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/../tests/criteria/lib.sh"

NODES_LIST=("$@")
[ ${#NODES_LIST[@]} -gt 0 ] || NODES_LIST=(test1 test2 test3 test4 test5 test6 test7 test8 test9 test10 test11 test12 test13 test14 test15 test16)

SYSCTL_FILE=/etc/sysctl.d/99-mxfs-iscsi-tcp.conf
SYSCTL_BODY='net.core.rmem_max = 16777216
net.core.wmem_max = 16777216'

for n in "${NODES_LIST[@]}"; do
    echo "=== $n ==="
    ssh_node "$n" "
        printf '%s\n' '$SYSCTL_BODY' > $SYSCTL_FILE
        sysctl -p $SYSCTL_FILE >/dev/null
        # request a 16MB window for future logins
        if grep -q '^node.conn\[0\].tcp.window_size' /etc/iscsi/iscsid.conf 2>/dev/null; then
            sed -i 's/^node.conn\[0\].tcp.window_size.*/node.conn[0].tcp.window_size = 16777216/' /etc/iscsi/iscsid.conf
        else
            echo 'node.conn[0].tcp.window_size = 16777216' >> /etc/iscsi/iscsid.conf
        fi
        # update existing node records (they snapshot settings at discovery)
        for rec in \$(iscsiadm -m node 2>/dev/null | awk '{print \$2}'); do
            iscsiadm -m node -T \$rec -o update -n node.conn[0].tcp.window_size -v 16777216 2>/dev/null
        done
        # re-login only if the LUN is idle (no mounted FS / no mxfs module)
        if ! mountpoint -q ${MXFS_MOUNT:-/mnt/shared} && ! lsmod | grep -q '^mxfs'; then
            for s in \$(iscsiadm -m session 2>/dev/null | grep -oE 'iqn[^ ]+'); do
                p=\$(iscsiadm -m session 2>/dev/null | grep \"\$s\" | grep -oE '[0-9.]+:3260' | head -1)
                iscsiadm -m node -T \$s -p \$p --logout >/dev/null 2>&1
                sleep 1
                iscsiadm -m node -T \$s -p \$p --login >/dev/null 2>&1
            done
            echo RELOGGED
        else
            echo 'LUN-IN-USE (window applies on next re-login/reboot)'
        fi
        echo OK
    " | tail -2
done
