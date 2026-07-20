#!/bin/bash
# clyde_boot_recover.sh — one-shot @reboot recovery for the clyde dev host.
#
# Written sess14 (2026-06-10) when the SCST target stack wedged unrecoverably:
# leaked D-state iscsi_conn_cleanup kernel threads pinned per-device command
# counts so every strictly-serialized SCSI cmd (CAW, WRITE SAME) blocked
# forever in EXEC_CHECK_BLOCKING; scst.service hung "deactivating"; only a
# host reboot clears kernel-thread state.
#
# Installed as a steve @reboot crontab entry by the session that reboots the
# host.  SELF-DISARMS (removes its own crontab line) on first run, then:
#   1. waits for scst.service + the disk1b iSCSI target
#   2. re-establishes the host iSCSI session (node.startup=manual)
#   3. waits for the /src NFS mount
#   4. resumes the ccloop run given as $1 (or the RUN_ID baked below)
RUN_ID="${1:-14d31183-faba-4a50-9608-1cd024839b53}"
LOG=/home/steve/clyde_boot_recover.log
exec >>"$LOG" 2>&1
echo "=== clyde_boot_recover $(date -u +%Y-%m-%dT%H:%M:%SZ) run=$RUN_ID ==="

# self-disarm immediately so a failure below can't loop on every boot
crontab -l 2>/dev/null | grep -v clyde_boot_recover.sh | crontab -

# 1. SCST up with the disk1b target
for i in $(seq 1 60); do
    systemctl is-active --quiet scst \
        && [ -d "/sys/kernel/scst_tgt/targets/iscsi/iqn.2026-05.local.mxfs:disk1b" ] \
        && break
    sleep 5
done
echo "scst: $(systemctl is-active scst)"

# 2. iSCSI sessions (idempotent) — disk1b for the host, plus disk1 +
#    disk1n2..disk1n16 which back the test1..test16 VM passthrough disks
#    (virsh start fails with "Cannot access storage file" without them)
for t in disk1b disk1 disk1n2 disk1n3 disk1n4 disk1n5 disk1n6 disk1n7 \
         disk1n8 disk1n9 disk1n10 disk1n11 disk1n12 disk1n13 disk1n14 \
         disk1n15 disk1n16; do
    if ! sudo iscsiadm -m session 2>/dev/null | grep -q ":$t$"; then
        sudo iscsiadm -m node -T iqn.2026-05.local.mxfs:$t -p 127.0.0.1:3260 --login &
    fi
done
wait
sleep 5
ls -l /dev/disk/by-path/ 2>/dev/null | grep -c "127.0.0.1:3260.*lun-0"

# 3. /src NFS
for i in $(seq 1 60); do
    [ -d /src/mxfs/.ccloop/runs ] && break
    sleep 5
done
echo "nfs: $(df -h /src/mxfs 2>/dev/null | tail -1)"

# 4. resume the ccloop run headlessly
cd /src/mxfs || exit 1
export PATH="$HOME/.local/bin:$HOME/bin:/usr/local/bin:/usr/bin:/bin"
setsid nohup ccloop --resume-run "$RUN_ID" >/home/steve/ccloop_resume.log 2>&1 &
echo "ccloop resume launched (pid $!)"
