#!/bin/bash
# node_disk_hygiene.sh — reclaim + cap local-disk log growth on test VMs.
#
# ccloop46ef sess2: nodes 9-32 have 6.1G root disks; days of mxfs marker
# floods filled them via TRIPLICATED kernel logging (rsyslog writes both
# /var/log/syslog and /var/log/kern.log, journald keeps a persistent copy).
# A full root FS silently breaks the TEST HARNESS on that node (dd to /tmp
# writes 0 bytes -> "empty cwr file", mktemp/sort fail, journald stops) and
# fabricates "coherency victim" failures that look like mxfs bugs.
#
# Actions per node:
#  - stop+disable rsyslog (journald alone keeps kernel logs; tests harvest
#    via journalctl/dmesg)
#  - truncate/remove the rsyslog files + rotated copies
#  - cap persistent journald at 200M and vacuum to it
#  - remove /root/drc_* forensic dumps and stray big files in /root and /tmp
#
# Usage: node_disk_hygiene.sh [N]   (default 32)
set -u
N="${1:-32}"
REPO=/src/mxfs
SSH="$REPO/tools/mxfs_sshpass.sh"; PF=/tmp/.mxfs_pass
RS=$(mktemp)
cat > "$RS" <<'EOF'
#!/bin/bash
systemctl disable --now rsyslog >/dev/null 2>&1
systemctl mask rsyslog >/dev/null 2>&1
rm -f /var/log/syslog* /var/log/kern.log* /var/log/auth.log.* /var/log/dpkg.log.*
mkdir -p /etc/systemd/journald.conf.d
printf '[Journal]\nSystemMaxUse=200M\nRuntimeMaxUse=400M\nRateLimitBurst=0\nRateLimitIntervalSec=0\n' > /etc/systemd/journald.conf.d/mxfs-test.conf
systemctl restart systemd-journald >/dev/null 2>&1
journalctl --vacuum-size=150M >/dev/null 2>&1
rm -rf /root/drc_* /root/dmesg.stream /tmp/mxfs_harvest.cap /tmp/cwr_* /tmp/s.bin /tmp/slotregion.bin
df -h / | tail -1 | awk '{print "ROOT_FREE " $4 " " $5}'
EOF
pids=()
for i in $(seq 1 "$N"); do
    ( sshpass -f "$PF" scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$RS" "root@test$i:/tmp/hygiene.sh" >/dev/null 2>&1 && \
      out=$("$SSH" "test$i" "$PF" "bash /tmp/hygiene.sh" 2>/dev/null | grep ROOT_FREE); echo "test$i: $out" ) &
    pids+=($!)
done
for p in "${pids[@]}"; do wait "$p"; done
rm -f "$RS"
echo "=== hygiene done on $N nodes ==="
