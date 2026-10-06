#!/bin/bash
#
# pve_crashdiag.sh — make a physical PVE host say why it died.
#
# WHY.  pve2 of the physical pair reset itself three times on 2026-10-05 with
# nothing in its journal: the hosts boot with kernel.panic=0 (a panic would
# hang, not reboot), have no pstore backend, and lose the journal's last
# ~25 s to the page cache on a hard reset.  Every PVE host runs watchdog-mux,
# which arms the softdog with a 10 s margin whether or not HA is in use; a
# softdog expiry restarts the host with no message at all, and it fires
# before the soft-lockup detector (20 s by default) could say which CPU was
# stuck.  `on` changes that, and nothing else:
#   - netconsole to clyde at every boot (a unit after network-online), so
#     the last lines leave the host before it dies;
#   - softdog soft_panic=1 and kernel.panic=10: a softdog expiry panics,
#     printing the reason and a backtrace to netconsole, then reboots 10 s
#     later as before;
#   - kernel.watchdog_thresh=4: a CPU stuck in the kernel is reported after
#     8 s, before the softdog's 10 s, with every CPU's backtrace;
#   - kernel.hung_task_timeout_secs=30: a task blocked 30 s is reported;
#   - a heat log: every 15 s one kernel-log line with every hwmon temperature
#     and fan, the thermal-throttle and machine-check counts, the SMI count
#     and the load, so netconsole carries the host's physical state up to the
#     moment it dies.  pve2 died silently 20+ times on 2026-10-05/06, often
#     right after a long full-CPU load (two image builds, a module compile),
#     and its last death came with C3/C6 disabled and left it hung, not reset.
# `off` removes every file and restores the defaults.  None of it changes
# what MXFS or DRBD do.
#
# `soak <seconds>` loads every CPU of the hosts for that long (a transient
# unit, stopped by systemd at the deadline or by `soak-stop`), to reproduce
# a death that follows heavy load with the heat log running.
#
# Usage:
#   tools/pve_crashdiag.sh on|off|status [host ...]
#   tools/pve_crashdiag.sh soak <seconds> [host ...]
#   tools/pve_crashdiag.sh soak-stop [host ...]
#
# Hosts: the ones named, else PVE_PAIR, else "192.168.1.80 192.168.1.81";
# host N of the whole pair sends to UDP port 6667+N-1 on clyde, where
# tools/pve_netconsole.sh start runs the listeners.

set -u
REPO=$(cd "$(dirname "$0")/.." && pwd)
# The port is the host's place in the whole pair (PVE_PAIR_ALL), so running
# this for one host keeps that host on its own port and log.
PAIR_ALL="${PVE_PAIR_ALL:-192.168.1.80 192.168.1.81}"
PAIR="${PVE_PAIR:-$PAIR_ALL}"
case "${1:-status}" in
    soak) [ $# -gt 2 ] && PAIR="${*:3}" ;;
    *)    [ $# -gt 1 ] && PAIR="${*:2}" ;;
esac
# pve_pair.sh exec runs on PVE_PAIR
export PVE_PAIR="$PAIR"
CLYDE_IP="${PVE_NETCONSOLE_TO:-192.168.1.166}"
CLYDE_IF="${PVE_NETCONSOLE_IF:-enp6s0}"
PAIRSH="$REPO/tools/pve_pair.sh"

on_cmd() {  # <port> <clyde-mac>
    cat <<EOF
set -e
cat > /usr/local/sbin/mxfs-diag-netconsole <<'NC'
#!/bin/sh
# installed by mxfs tools/pve_crashdiag.sh; removed by its "off"
modprobe netconsole 2>/dev/null || true
mountpoint -q /sys/kernel/config || mount -t configfs none /sys/kernel/config
T=/sys/kernel/config/netconsole/clyde
if [ -d \$T ]; then echo 0 > \$T/enabled; else mkdir \$T; fi
DEV=\$(ip route get $CLYDE_IP | sed -n 's/.* dev \([^ ]*\).*/\1/p')
SRC=\$(ip route get $CLYDE_IP | sed -n 's/.* src \([^ ]*\).*/\1/p')
echo \$DEV > \$T/dev_name
echo \$SRC > \$T/local_ip
echo $CLYDE_IP > \$T/remote_ip
echo $2 > \$T/remote_mac
echo $1 > \$T/remote_port
echo 1 > \$T/enabled
dmesg -n 7
echo "<4>mxfs-diag-netconsole: \$(hostname) boot \$(cat /proc/sys/kernel/random/boot_id) -> $CLYDE_IP:$1" > /dev/kmsg
NC
chmod 755 /usr/local/sbin/mxfs-diag-netconsole
cat > /etc/systemd/system/mxfs-diag-netconsole.service <<'UNIT'
[Unit]
Description=MXFS diagnostics: kernel log to clyde over netconsole (tools/pve_crashdiag.sh)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/mxfs-diag-netconsole

[Install]
WantedBy=multi-user.target
UNIT
cat > /usr/local/sbin/mxfs-diag-heatlog <<'HL'
#!/bin/sh
# installed by mxfs tools/pve_crashdiag.sh; removed by its "off"
modprobe msr 2>/dev/null || true
while :; do
    s=""
    for h in /sys/class/hwmon/hwmon*; do
        n=\$(cat \$h/name 2>/dev/null)
        t=\$(for f in \$h/temp*_input; do [ -r "\$f" ] && echo \$((\$(cat \$f) / 1000)); done | paste -s -d, -)
        f=\$(for f in \$h/fan*_input; do [ -r "\$f" ] && cat \$f; done | paste -s -d, -)
        [ -n "\$t" ] && s="\$s \$n=\$t"
        [ -n "\$f" ] && s="\$s \$n-fan=\$f"
    done
    thr=\$(cat /sys/devices/system/cpu/cpu*/thermal_throttle/core_throttle_count 2>/dev/null | awk '{s+=\$1} END{print s+0}')
    pthr=\$(cat /sys/devices/system/cpu/cpu*/thermal_throttle/package_throttle_count 2>/dev/null | awk '{s+=\$1} END{print s+0}')
    smi=\$(python3 -I -c "import os,struct; f=os.open('/dev/cpu/0/msr', os.O_RDONLY); print(struct.unpack('<Q', os.pread(f, 8, 0x34))[0])" 2>/dev/null || echo -)
    mce=\$(awk '/^ *MCE:/{s=0; for(i=2;i<=NF;i++) if (\$i ~ /^[0-9]+\$/) s+=\$i; print s}' /proc/interrupts)
    mhz=\$(awk '/^cpu MHz/{s+=\$4; n++} END{if (n) printf "%d", s/n}' /proc/cpuinfo)
    echo "<5>mxfs-diag-heat:\$s throttle=\$thr/\$pthr smi=\$smi mce=\$mce mhz=\$mhz load=\$(cut -d' ' -f1 /proc/loadavg)" > /dev/kmsg
    sleep 15
done
HL
chmod 755 /usr/local/sbin/mxfs-diag-heatlog
cat > /etc/systemd/system/mxfs-diag-heatlog.service <<'UNIT'
[Unit]
Description=MXFS diagnostics: temperatures and throttle/SMI/MCE counts to the kernel log (tools/pve_crashdiag.sh)
After=mxfs-diag-netconsole.service

[Service]
ExecStart=/usr/local/sbin/mxfs-diag-heatlog

[Install]
WantedBy=multi-user.target
UNIT
cat > /etc/modprobe.d/mxfs-diag-softdog.conf <<'SD'
# installed by mxfs tools/pve_crashdiag.sh: a softdog expiry panics (reason and
# backtrace on netconsole) instead of restarting silently; kernel.panic=10 reboots
options softdog soft_panic=1
SD
cat > /etc/sysctl.d/90-mxfs-diag.conf <<'SC'
# installed by mxfs tools/pve_crashdiag.sh
kernel.panic = 10
kernel.watchdog_thresh = 4
kernel.softlockup_all_cpu_backtrace = 1
kernel.hardlockup_all_cpu_backtrace = 1
kernel.hung_task_timeout_secs = 30
kernel.hung_task_warnings = 20
SC
systemctl daemon-reload
systemctl enable mxfs-diag-netconsole.service >/dev/null 2>&1
# a oneshot that already ran is not run again by enable --now: restart it so
# a changed port or address takes effect now
systemctl restart mxfs-diag-netconsole.service
systemctl enable mxfs-diag-heatlog.service >/dev/null 2>&1
systemctl restart mxfs-diag-heatlog.service
sysctl -q -p /etc/sysctl.d/90-mxfs-diag.conf
# reload the softdog with soft_panic=1: watchdog-mux closes it cleanly on stop
# (no HA resource is configured on this pair, so nothing depends on it meanwhile)
systemctl stop watchdog-mux
rmmod softdog 2>/dev/null || true
modprobe softdog
systemctl start watchdog-mux
echo "\$(hostname) crashdiag on: softdog \$(dmesg | grep 'softdog: initialized' | tail -1 | grep -o 'soft_panic=[0-9]') panic=\$(cat /proc/sys/kernel/panic) thresh=\$(cat /proc/sys/kernel/watchdog_thresh) hung=\$(cat /proc/sys/kernel/hung_task_timeout_secs) netconsole=\$(cat /sys/kernel/config/netconsole/clyde/enabled) heatlog=\$(systemctl is-active mxfs-diag-heatlog) watchdog-mux=\$(systemctl is-active watchdog-mux)"
EOF
}

OFF_CMD='
systemctl stop mxfs-diag-soak.service >/dev/null 2>&1
systemctl disable --now mxfs-diag-heatlog.service >/dev/null 2>&1
systemctl disable --now mxfs-diag-netconsole.service >/dev/null 2>&1
rm -f /etc/systemd/system/mxfs-diag-netconsole.service /usr/local/sbin/mxfs-diag-netconsole /etc/systemd/system/mxfs-diag-heatlog.service /usr/local/sbin/mxfs-diag-heatlog /etc/modprobe.d/mxfs-diag-softdog.conf /etc/sysctl.d/90-mxfs-diag.conf
systemctl daemon-reload
T=/sys/kernel/config/netconsole/clyde
[ -d $T ] && echo 0 > $T/enabled && rmdir $T
sysctl -q -w kernel.panic=0 kernel.watchdog_thresh=10 kernel.softlockup_all_cpu_backtrace=0 kernel.hardlockup_all_cpu_backtrace=0 kernel.hung_task_timeout_secs=120 kernel.hung_task_warnings=10
dmesg -n 4
systemctl stop watchdog-mux
rmmod softdog 2>/dev/null || true
modprobe softdog
systemctl start watchdog-mux
echo "$(hostname) crashdiag off: panic=$(cat /proc/sys/kernel/panic) thresh=$(cat /proc/sys/kernel/watchdog_thresh) watchdog-mux=$(systemctl is-active watchdog-mux)"
'

STATUS_CMD='
echo "$(hostname) unit=$(systemctl is-enabled mxfs-diag-netconsole.service 2>/dev/null)/$(systemctl is-active mxfs-diag-netconsole.service 2>/dev/null) heatlog=$(systemctl is-active mxfs-diag-heatlog.service 2>/dev/null) soak=$(systemctl is-active mxfs-diag-soak.service 2>/dev/null) netconsole=$(cat /sys/kernel/config/netconsole/clyde/enabled 2>/dev/null || echo none) softdog_conf=$(cat /etc/modprobe.d/mxfs-diag-softdog.conf 2>/dev/null | grep -c options) $(dmesg | grep "softdog: initialized" | tail -1 | grep -o "soft_panic=[0-9]") panic=$(cat /proc/sys/kernel/panic) thresh=$(cat /proc/sys/kernel/watchdog_thresh) hung=$(cat /proc/sys/kernel/hung_task_timeout_secs) loglevel=$(cut -f1 /proc/sys/kernel/printk)"
'

case "${1:-status}" in
    on)
        MAC=$(cat "/sys/class/net/$CLYDE_IF/address")
        for h in $PAIR; do
            i=0
            for a in $PAIR_ALL; do
                [ "$a" = "$h" ] && break
                i=$((i + 1))
            done
            "$PAIRSH" on "$h" "$(on_cmd $((6667 + i)) "$MAC")"
            echo "$h port=$((6667 + i)) rc=$?"
        done
        ;;
    off)
        "$PAIRSH" exec "$OFF_CMD" ;;
    status)
        "$PAIRSH" exec "$STATUS_CMD" ;;
    soak)
        SECS="${2:?seconds}"
        case "$SECS" in *[!0-9]*|'') echo "soak: seconds must be a number" >&2; exit 2 ;; esac
        "$PAIRSH" exec "systemctl stop mxfs-diag-soak.service >/dev/null 2>&1; systemctl reset-failed mxfs-diag-soak.service >/dev/null 2>&1; systemd-run --quiet --unit=mxfs-diag-soak --collect -p RuntimeMaxSec=$SECS sh -c 'echo \"<4>mxfs-diag-soak: \$(nproc) CPU burners for $SECS s\" > /dev/kmsg; for i in \$(seq \$(nproc)); do sha256sum /dev/zero & done; wait'; echo \"\$(hostname) soak=\$(systemctl is-active mxfs-diag-soak.service) for ${SECS}s\"" ;;
    soak-stop)
        "$PAIRSH" exec 'systemctl stop mxfs-diag-soak.service 2>/dev/null; echo "<4>mxfs-diag-soak: stopped" > /dev/kmsg; echo "$(hostname) soak=$(systemctl is-active mxfs-diag-soak.service)"' ;;
    *)
        echo "usage: $0 on|off|status|soak <seconds>|soak-stop" >&2
        exit 2 ;;
esac
