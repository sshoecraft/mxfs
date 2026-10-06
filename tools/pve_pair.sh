#!/bin/bash
#
# pve_pair.sh — inspect and drive the two physical Proxmox hosts that run MXFS
# on DRBD dual-primary (2/net/mesh/drbd on real hardware, not the rig).
#
# Usage:
#   tools/pve_pair.sh status                one summary block per host
#   tools/pve_pair.sh exec '<cmd>'          run <cmd> on every host in parallel;
#                                           each host's output and exit code are
#                                           printed under its own header
#   tools/pve_pair.sh on <host> '<cmd>'     run <cmd> on one host
#   tools/pve_pair.sh klog <host> [since]   counts of the kernel log since <since>
#                                           (journalctl syntax, default: this boot)
#
# Hosts: PVE_PAIR (default "192.168.1.80 192.168.1.81").  Credentials come from
# the lab secrets store through tools/mxfs_sshpass.sh; nothing here holds one.
# Every ssh is bounded by PVE_PAIR_TIMEOUT seconds (default 60): a host that
# does not answer in that time is reported as rc=124, never waited on.

PAIR="${PVE_PAIR:-192.168.1.80 192.168.1.81}"
TMO="${PVE_PAIR_TIMEOUT:-60}"
HERE="$(cd "$(dirname "$0")" && pwd)"
SSHP="$HERE/mxfs_sshpass.sh"

on_host() {  # <host> <cmd>
    timeout "$TMO" "$SSHP" "$1" "$2" 2>&1 | grep -v '^Warning: Permanently added'
    return "${PIPESTATUS[0]}"
}

on_all() {  # <cmd>
    # Each host's lines carry its address as a prefix, so the stable sort
    # groups them per host while keeping each host's own order; the last
    # line of each group is that host's exit code.
    local h
    for h in $PAIR; do
        (
            out="$(on_host "$h" "$1")"
            rc=$?
            printf '%s\n' "$out" | sed "s|^|$h  |"
            echo "$h  rc=$rc"
        ) &
    done | sort -s -k1,1
}

STATUS_CMD='
echo "host=$(hostname) up=$(cut -d. -f1 /proc/uptime)s load=$(cut -d" " -f1-3 /proc/loadavg)"
free -m | awk "/^Mem:/{printf \"mem used=%d/%d MiB (%.0f%%) avail=%d MiB\n\", \$3, \$2, 100*\$3/\$2, \$7}"
free -m | awk "/^Swap:/{printf \"swap used=%d/%d MiB\n\", \$3, \$2}"
echo "mxfs loaded=$(cat /sys/module/mxfs/srcversion 2>/dev/null || echo none) refcnt=$(cat /sys/module/mxfs/refcnt 2>/dev/null || echo -) installed=$(modinfo -F srcversion mxfs 2>/dev/null || echo none)"
echo "tree VERSION=$(cat /root/mxfs/VERSION 2>/dev/null || echo none)"
echo "drbd module=$(cat /sys/module/drbd/version 2>/dev/null || echo none)"
grep -E "^ *[0-9]+:" /proc/drbd 2>/dev/null || echo "drbd: no device"
ls /etc/drbd.d/ 2>/dev/null | tr "\n" " "; echo
grep -h -E "^ *(disk|device|address|fencing|protocol)" /etc/drbd.d/*.res 2>/dev/null | sed "s/^ */  res: /"
awk "\$3==\"mxfs\"{print \"mount: \" \$1 \" on \" \$2 \" \" \$4}" /proc/mounts
for u in mxfs-drbd@mxfs mxfs-drbd-guard watchdog-mux pve-ha-lrm pve-ha-crm corosync proxlb; do printf "%s=%s " "$u" "$(systemctl is-active "$u" 2>/dev/null)"; done; echo
nft list tables 2>/dev/null | tr "\n" " "; echo
ls /var/lib/mxfs/ 2>/dev/null | sed "s/^/  varlib: /"
ls -la /var/lib/systemd/pstore/ 2>/dev/null | tail -n +4 | sed "s/^/  pstore: /"
ls /sys/fs/pstore/ 2>/dev/null | sed "s/^/  sysfs-pstore: /"
cat /sys/class/watchdog/watchdog0/identity /sys/class/watchdog/watchdog0/timeout 2>/dev/null | tr "\n" " "; echo "(watchdog0 identity/timeout)"
qm list 2>/dev/null | awk "NR>1{print \"  vm: \" \$1, \$2, \$3, \$4\"M\"}"
journalctl -k -b 0 --no-pager -o cat 2>/dev/null | awk "{n++} /mxfs/{m++} /WARNING:|BUG:|Oops|hung_task|blocked for more than|Out of memory/{w++} END{printf \"klog this boot: lines=%d mxfs=%d warn/bug/oom/hung=%d\n\", n, m, w}"
'

case "${1:-status}" in
    status)
        on_all "$STATUS_CMD" ;;
    exec)
        on_all "${2:?command}" ;;
    on)
        on_host "${2:?host}" "${3:?command}"; exit $? ;;
    klog)
        H="${2:?host}"
        S="${3:+--since \"$3\"}"
        [ -n "$S" ] || S="-b 0"
        on_host "$H" "journalctl -k $S --no-pager -o cat | awk '{n++} /mxfs/{m++} /drbd/{d++} /WARNING:|BUG:|Oops|hung_task|blocked for more than|Out of memory|oom-kill/{w++} END{printf \"lines=%d mxfs=%d drbd=%d warn/bug/oom/hung=%d\n\", n, m, d, w}'; journalctl -k $S --no-pager -o cat | grep -o -E 'mxfs: [A-Za-z0-9_-]+' | sort | uniq -c | sort -rn | head -25"
        exit $? ;;
    *)
        echo "usage: $0 {status|exec <cmd>|on <host> <cmd>|klog <host> [since]}" >&2
        exit 2 ;;
esac
