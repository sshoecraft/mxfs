#!/bin/bash
# pve_power.sh — power a host of the physical Proxmox pair off, and on again,
# for the failover steps that keep a host down (tests/pve_pair_failover.sh's
# PVE_POWER_OFF and PVE_POWER_ON).  The pair are workstations with no BMC and
# no remotely switchable power, and neither Wake-on-LAN nor an RTC alarm has
# been shown to start one from soft-off, so a power-off is emulated on the host
# itself, in the two ways its peer can tell a host is off:
#
#   off  The host is reset at once (sysrq b: nothing synced, no unit stopped,
#        no message to its peer), exactly as at a power cut.  The boot that
#        follows starts neither DRBD nor the MXFS units, and drops every packet
#        to and from its peer from before the network comes up: to the peer it
#        stays dead (no ping, ssh, DRBD or corosync), and its replica stays as
#        the reset left it, because nothing attaches it.  Units masked by the
#        caller stay masked; this only adds a condition beside them.
#   on   The isolation is removed and the host is reset again into an ordinary
#        boot, as it boots when powered on.  Returns once the host has stopped
#        answering, so the next boot id it answers with is the new boot's.
#   restore  The isolation is removed in place, with no reset, and the two
#        units an ordinary boot starts are started: the guard, then the mount
#        unit, which brings DRBD up itself.  This ends a run that stopped while
#        a host was off, without putting the host through another reset: the
#        pair are old workstations, and one reset already left a host powered
#        off for 37 minutes.  Returns once the mount unit is active.
#
# The host running this keeps reaching the host throughout: only the peer's
# address is dropped.
#
# Usage: tools/pve_power.sh off|on|restore <addr>
# Env:   PVE_PAIR  "<addr> <addr>" (default "192.168.1.80 192.168.1.81"); the
#                  peer is the one that is not <addr>
#        BOOT_BUDGET  seconds "on" waits for a host still in its isolated boot
#                  to answer (default 300, the pair's slowest measured boot)
#        RES       the DRBD resource, so the mount unit is mxfs-drbd@$RES
#                  (default mxfs)
#        REJOIN_BUDGET  seconds "restore" waits for the mount unit to become
#                  active (default 270: twice the slowest rejoin the failover
#                  suite has measured, 135 s from a unit start)
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
OP=${1:-}
ADDR=${2:-}
BOOT_BUDGET=${BOOT_BUDGET:-300}
RES=${RES:-mxfs}
REJOIN_BUDGET=${REJOIN_BUDGET:-270}
read -r -a PAIR <<<"${PVE_PAIR:-192.168.1.80 192.168.1.81}"
case "$OP" in off|on|restore) ;; *) echo "usage: tools/pve_power.sh off|on|restore <addr>"; exit 2 ;; esac
PEER=
for a in "${PAIR[@]}"; do [ "$a" != "$ADDR" ] && PEER=$a; done
[ "${#PAIR[@]}" = 2 ] && [ -n "$PEER" ] && [ "$PEER" != "$ADDR" ] \
    || { echo "pve_power: $ADDR is not one of PVE_PAIR (${PAIR[*]})"; exit 2; }

on() {  # <cmd> [timeout]
    timeout "${2:-60}" "$SSHP" "$ADDR" "$1" </dev/null 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you|^$'
    return "${PIPESTATUS[0]}"
}
# off and on reset the host: virtual machines only.  The physical pair are
# workstations over ten years old, and repeated resets killed one of them
# (2026-10-07).  restore never resets and stays allowed everywhere.
if [ "$OP" != restore ]; then
    v=$(on "systemd-detect-virt --vm" 15 | tail -1)
    case "$v" in ""|none) echo "pve_power: refusing to $OP $ADDR: it is not a virtual machine (systemd-detect-virt: ${v:-no answer}); use the nested pair"; exit 2 ;; esac
fi
# down: the host stops answering ping within 30 s of its reset being armed
down() {
    local i
    for i in $(seq 1 30); do
        ping -c 1 -W 1 "$ADDR" >/dev/null 2>&1 || return 0
        sleep 1
    done
    echo "pve_power: $ADDR still answers 30 s after its reset was armed"
    return 1
}
# The reset, one second after the ssh session ends, as the failover steps do it.
ARM="echo 1 > /proc/sys/kernel/sysrq; nohup setsid sh -c 'sleep 1; echo b > /proc/sysrq-trigger' >/dev/null 2>&1 < /dev/null &"
DROPINS="/etc/systemd/system/mxfs-drbd@.service.d /etc/systemd/system/mxfs-drbd-guard.service.d /etc/systemd/system/drbd.service.d"

if [ "$OP" = off ]; then
    # Only the root filesystem is synced (sync -f), so the files that make the
    # next boot an isolated one survive the reset while MXFS gets no sync.
    out=$(on "set -e
        printf 'table inet mxfs_powered_off {\n    chain in { type filter hook input priority -400; ip saddr $PEER drop; }\n    chain out { type filter hook output priority -400; ip daddr $PEER drop; }\n}\n' > /etc/mxfs-powered-off.nft
        printf '[Unit]\nDescription=MXFS failover test: this host is powered off as far as its peer can tell\nDefaultDependencies=no\nConditionPathExists=/etc/mxfs-powered-off.nft\nBefore=network-pre.target\nWants=network-pre.target\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/sbin/nft -f /etc/mxfs-powered-off.nft\n\n[Install]\nWantedBy=sysinit.target\n' > /etc/systemd/system/mxfs-powered-off.service
        for d in $DROPINS; do
            mkdir -p \$d
            printf '[Unit]\nConditionPathExists=!/etc/mxfs-powered-off.nft\n' > \$d/zz-mxfs-powered-off.conf
        done
        systemctl enable mxfs-powered-off.service >/dev/null 2>&1
        test -L /etc/systemd/system/sysinit.target.wants/mxfs-powered-off.service
        sync -f /etc/systemd/system
        $ARM
        echo OFF_ARMED" 30)
    grep -q OFF_ARMED <<<"$out" || { echo "pve_power: could not arm $ADDR's power-off: $out"; exit 1; }
    down || exit 1
    echo "pve_power: $ADDR is off (reset; its next boot is isolated from $PEER with DRBD and the MXFS units held)"
    exit 0
fi

if [ "$OP" = restore ]; then
    out=$(on "systemctl disable mxfs-powered-off.service >/dev/null 2>&1
        rm -f /etc/mxfs-powered-off.nft /etc/systemd/system/mxfs-powered-off.service
        for d in $DROPINS; do rm -f \$d/zz-mxfs-powered-off.conf; rmdir \$d 2>/dev/null; done
        nft delete table inet mxfs_powered_off 2>/dev/null
        systemctl daemon-reload
        test ! -e /etc/systemd/system/sysinit.target.wants/mxfs-powered-off.service || exit 1
        nft list table inet mxfs_powered_off >/dev/null 2>&1 && exit 1
        sync -f /etc/systemd/system
        systemctl start mxfs-drbd-guard.service || exit 1
        systemctl start --no-block mxfs-drbd@$RES.service || exit 1
        echo RESTORE_STARTED" 60)
    grep -q RESTORE_STARTED <<<"$out" || { echo "pve_power: could not lift $ADDR's isolation and start its units: $out"; exit 1; }
    t0=$(date +%s)
    while :; do
        st=$(on "systemctl is-active mxfs-drbd@$RES.service" 10)
        case "$st" in
            active) echo "pve_power: $ADDR restored without a reset: isolation lifted, mxfs-drbd@$RES active $(( $(date +%s) - t0 )) s after its start"; exit 0 ;;
            failed) echo "pve_power: $ADDR's mxfs-drbd@$RES failed $(( $(date +%s) - t0 )) s after its start"; exit 1 ;;
        esac
        [ $(( $(date +%s) - t0 )) -ge "$REJOIN_BUDGET" ] && { echo "pve_power: $ADDR's mxfs-drbd@$RES not active within ${REJOIN_BUDGET}s (state: $st)"; exit 1; }
        sleep 3
    done
fi

# on: a host reset into its isolated boot may still be booting
t0=$(date +%s)
until on "true" 10 >/dev/null; do
    [ $(( $(date +%s) - t0 )) -ge "$BOOT_BUDGET" ] && { echo "pve_power: $ADDR did not answer within ${BOOT_BUDGET}s"; exit 1; }
    sleep 5
done
out=$(on "systemctl disable mxfs-powered-off.service >/dev/null 2>&1
    rm -f /etc/mxfs-powered-off.nft /etc/systemd/system/mxfs-powered-off.service
    for d in $DROPINS; do rm -f \$d/zz-mxfs-powered-off.conf; rmdir \$d 2>/dev/null; done
    nft delete table inet mxfs_powered_off 2>/dev/null
    test ! -e /etc/systemd/system/sysinit.target.wants/mxfs-powered-off.service || exit 1
    sync -f /etc/systemd/system
    $ARM
    echo ON_ARMED" 30)
grep -q ON_ARMED <<<"$out" || { echo "pve_power: could not undo $ADDR's isolation: $out"; exit 1; }
down || exit 1
echo "pve_power: $ADDR is powering on (isolation removed, reset into an ordinary boot)"
