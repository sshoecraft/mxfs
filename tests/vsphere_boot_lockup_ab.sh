#!/bin/bash
#
# vsphere_boot_lockup_ab.sh — does a vSphere guest soft-lock with or without
# the mxfs module loaded?
#
# vstest1 (Ubuntu 24.04, 6.8.0-53, nested ESXi on VMware Workstation) has been
# seen soft-locking on every CPU — idle tasks included — during boot, while
# idle and unmounted, and while mounted.  CPU 0 of one such boot was inside
# systemd-modules-load, which is where the package loads mxfs.  This runs the
# same boot N times in one arm:
#
#   with     mxfs loads at boot (as the package installs it)
#   without  /etc/modules-load.d/mxfs.conf moved aside, so nothing loads it
#
# and records, per boot, whether ssh came back inside its budget and how many
# soft-lockup / hung-task / RCU-stall lines the kernel printed during the boot
# and an idle hold afterwards.  The kernel log is streamed to clyde over ssh as
# it is written, so a guest that hangs mid-hold still leaves its record here.
#
# Usage: tests/vsphere_boot_lockup_ab.sh with|without [boots] [hold_seconds]
#
# Budgets: a clean boot reached ssh in 25-27 s every time it was measured, so
# 60 s (2x the worst clean boot, rounded up) is the ready budget; a boot that
# misses it is recorded as HUNG with a console capture, never waited out.
#
set -u

ARM="${1:?usage: $0 with|without [boots] [hold_seconds]}"
BOOTS="${2:-5}"
HOLD_S="${3:-90}"
VM=vstest1
IP=192.168.120.177
READY_S=60
case "$ARM" in with|without) ;; *) echo "arm must be with or without" >&2; exit 2 ;; esac

HERE="$(cd "$(dirname "$0")/.." && pwd)"
SSH="$HERE/tools/mxfs_sshpass.sh"
EV="$HERE/tests/evidence/vsphere_boot_lockup_ab/$(date +%Y%m%dT%H%M%S)_$ARM"
mkdir -p "$EV"
exec > >(tee -a "$EV/run.log") 2>&1
say() { echo "[$(date +%T)] $*"; }
on() { local t=$1; shift; timeout "$t" "$SSH" "$IP" "$@" 2>&1 | grep --line-buffered -v -E "^Warning: Permanently|^$|Unauthorized access|authorized user, disconnect"; return "${PIPESTATUS[0]}"; }

SECRETS="${OSIMAGER_SECRETS:-$HOME/.config/osimager/secrets}"
eval "$(python3 - "$SECRETS" <<'EOF'
import re, shlex, sys
for line in open(sys.argv[1]):
    if line.startswith("vsphere/lab"):
        f = dict(re.findall(r"(\w+)=(\S+)", line))
        print("export GOVC_URL=%s" % shlex.quote("https://" + f["server"] + "/sdk"))
        print("export GOVC_USERNAME=%s" % shlex.quote(f["username"]))
        print("export GOVC_PASSWORD=%s" % shlex.quote(f["password"]))
        break
else:
    sys.exit("no vsphere/lab entry in " + sys.argv[1])
EOF
)"
export GOVC_INSECURE=1
VMP=$(timeout 30 govc find / -type m -name "$VM" | head -1)
[ -n "$VMP" ] || { say "FAIL: $VM not in vCenter"; exit 1; }

wait_ready() {
    local t0
    t0=$(date +%s)
    until on 10 true >/dev/null; do
        [ $(( $(date +%s) - t0 )) -lt "$READY_S" ] || return 1
        sleep 3
    done
    echo $(( $(date +%s) - t0 ))
}

# Put the guest into the arm's configuration (needs one reachable boot).
say "arm=$ARM boots=$BOOTS hold=${HOLD_S}s evidence=$EV"
if ! wait_ready >/dev/null; then
    timeout 60 govc vm.power -reset "$VMP" >/dev/null
    wait_ready >/dev/null || { say "FAIL: $VM unreachable before the arm could be set"; exit 1; }
fi
if [ "$ARM" = without ]; then
    on 20 "[ -f /etc/modules-load.d/mxfs.conf ] && mv /etc/modules-load.d/mxfs.conf /root/mxfs-modules-load.conf.aside; ls /etc/modules-load.d/"
else
    on 20 "[ -f /root/mxfs-modules-load.conf.aside ] && mv /root/mxfs-modules-load.conf.aside /etc/modules-load.d/mxfs.conf; ls /etc/modules-load.d/"
fi

printf "boot\tready_s\tmxfs_loaded\tlockup_lines\tstall_lines\thung_lines\tverdict\n" > "$EV/summary.tsv"
for i in $(seq 1 "$BOOTS"); do
    timeout 60 govc vm.power -reset "$VMP" >/dev/null
    say "boot $i: reset"
    if ! r=$(wait_ready); then
        timeout 60 govc vm.console -capture "$EV/console_boot$i.png" "$VMP" >/dev/null 2>&1
        q=$(timeout 30 govc vm.info -json "$VMP" | python3 -c 'import json,sys; print(json.load(sys.stdin)["virtualMachines"][0]["summary"]["quickStats"].get("overallCpuUsage"))')
        say "boot $i: HUNG — no ssh within ${READY_S} s; cpu_mhz=$q; console saved"
        printf "%s\t-\t-\t-\t-\t-\tHUNG_AT_BOOT cpu_mhz=%s\n" "$i" "$q" >> "$EV/summary.tsv"
        continue
    fi
    on 20 "sysctl -q kernel.hung_task_timeout_secs=10 kernel.softlockup_all_cpu_backtrace=1"
    # The whole ring from boot onward, then everything printed during the hold.
    on $(( HOLD_S + 30 )) "dmesg -w" > "$EV/dmesg_boot$i.log" &
    spid=$!
    sleep "$HOLD_S"
    alive=yes
    on 10 true >/dev/null || alive=no
    kill "$spid" 2>/dev/null
    wait "$spid" 2>/dev/null
    loaded=$(grep -c 'mxfs: loading out-of-tree module' "$EV/dmesg_boot$i.log")
    lk=$(grep -c 'soft lockup' "$EV/dmesg_boot$i.log")
    st=$(grep -c -E 'rcu_sched self-detected stall|rcu: INFO: .*stall' "$EV/dmesg_boot$i.log")
    hg=$(grep -c 'blocked for more than' "$EV/dmesg_boot$i.log")
    v=clean
    [ "$lk$st$hg" = 000 ] || v=LOCKUP
    [ "$alive" = yes ] || { v="$v HUNG_IN_HOLD"; timeout 60 govc vm.console -capture "$EV/console_boot$i.png" "$VMP" >/dev/null 2>&1; }
    say "boot $i: ready=${r}s mxfs_loaded=$loaded lockup=$lk stall=$st hung=$hg alive_after_hold=$alive -> $v"
    printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\n" "$i" "$r" "$loaded" "$lk" "$st" "$hg" "$v" >> "$EV/summary.tsv"
done
cat "$EV/summary.tsv"
say "done: $EV"
