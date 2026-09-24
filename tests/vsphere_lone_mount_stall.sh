#!/bin/bash
#
# vsphere_lone_mount_stall.sh — reproduce a lone TCP mount on the vSphere
# Ubuntu pair and record, on two independent clocks, whether the guest itself
# stopped running or only the MXFS threads did.
#
# The defect this measures: vstest1 mounted alone (peer=vstest2), its first
# heartbeat landed at 146.8 s, and then NOTHING was logged until 394 s, when
# the authority lease — due at 176.8 s — was finally found expired.  The PR
# worker asks the lease gate every 250 ms and the heartbeat watchdog logs a
# stuck cycle every 30 s, and both were silent too; a work item queued at
# mount ran at the same instant the gate fired.  Two explanations fit, and
# they call for opposite fixes:
#
#   guest stall   the hypervisor did not run the VM, and its boottime clock
#                 jumped forward on resume, so every deadline was already past
#   thread stall  the guest kept running while every MXFS thread was blocked
#                 on something they share
#
# The in-guest sampler writes wall clock + uptime every second together with
# the kernel stack of every mxfs-worker thread; the clyde-side probe asks the
# guest for its uptime every 2 s over ssh.  A guest stall shows as a gap in
# BOTH records over the same interval; a thread stall shows as a sampler that
# keeps ticking while the heartbeat thread's stack stops changing.
#
# Usage: tests/vsphere_lone_mount_stall.sh [watch_seconds] [join_after_seconds]
#   With join_after_seconds, vstest2 mounts (peer=vstest1) that many seconds
#   after vstest1's mount returned — the original round's order, 12 s apart —
#   and both nodes are sampled.  Without it vstest2 stays up and unmounted.
#   Evidence lands in tests/evidence/vsphere_lone_mount_stall/<timestamp>/.
#
# Budgets (derived, not padded): guest reset to ssh-ready was measured under a
# minute on esxhost2 -> 120 s; iSCSI login + reservation clear + format are
# seconds each -> 60 s; the mount took 4.3 s in the original round -> 30 s.
# The watch window is an observation period, not a performance budget: the
# original self-fence fired 247 s after the mount, so the default is 300 s.
#
set -u

WATCH_S="${1:-300}"
JOIN_AFTER_S="${2:-}"
N1=192.168.120.177          # vstest1: mounts alone
N2=192.168.120.150          # vstest2: up, logged in, never mounted
DEV=/dev/sdb
MNT=/mnt/mxfs
QNAP_PORTAL=192.168.1.4
QNAP_TGT="iqn.2004-04.com.qnap:ts-453pro:iscsi.target-0.f35772"
SCRATCH_KEY=0x5eed

HERE="$(cd "$(dirname "$0")/.." && pwd)"
SSH="$HERE/tools/mxfs_sshpass.sh"
EV="$HERE/tests/evidence/vsphere_lone_mount_stall/$(date +%Y%m%dT%H%M%S)"
mkdir -p "$EV"
exec > >(tee -a "$EV/run.log") 2>&1

say() { echo "[$(date +%T)] $*"; }
fail() { say "FAIL: $*"; exit 1; }
on() { local ip=$1 t=$2; shift 2; timeout "$t" "$SSH" "$ip" "$@" 2>&1 | grep --line-buffered -v -E "^Warning: Permanently|^$|Unauthorized access|authorized user, disconnect"; return "${PIPESTATUS[0]}"; }

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

vmpath() { timeout 30 govc find / -type m -name "$1" | head -1; }
placement() {
    local vm p
    for vm in vstest1 vstest2 alma-97; do
        p=$(vmpath "$vm")
        [ -n "$p" ] || { echo "$vm: not found"; continue; }
        timeout 30 govc vm.info -json "$p" | python3 -c '
import json, sys
v = json.load(sys.stdin)["virtualMachines"][0]
print("%s power=%s host=%s vcpu=%s cpu_mhz=%s" % (sys.argv[1], v["runtime"]["powerState"],
      v["runtime"]["host"]["value"], v["config"]["hardware"]["numCPU"],
      v["summary"]["quickStats"].get("overallCpuUsage")))' "$vm"
    done
    paste <(timeout 30 govc find -i / -type h) <(timeout 30 govc find / -type h)
}

say "evidence: $EV"
say "--- placement before"
placement | tee "$EV/placement_before.txt"

# The QNAP LUN is shared with the libvirt rig; nothing there may be mounted
# from it while this run formats it.
for vm in $(virsh -c qemu:///system list --name 2>/dev/null | grep -E '^test[0-9]+$'); do
    ip=$(getent hosts "$vm" | awk '{print $1}')
    [ -n "$ip" ] || fail "running rig VM $vm has no address to check for an MXFS mount"
    m=$(on "$ip" 20 "grep -c ' mxfs ' /proc/mounts; true")
    [ "$m" = 0 ] || fail "rig VM $vm ($ip) has MXFS mounted or did not answer (got '$m')"
    say "rig VM $vm is running with nothing mounted"
done

# --- 1. reset both guests (lab VMs, disposable) and wait for ssh
for vm in vstest1 vstest2; do
    p=$(vmpath "$vm"); [ -n "$p" ] || fail "$vm not in vCenter"
    timeout 60 govc vm.power -reset "$p" || fail "$vm reset refused"
    say "$vm reset"
done
t0=$(date +%s)
for ip in $N1 $N2; do
    until on "$ip" 10 "systemctl is-system-running --wait >/dev/null 2>&1; uptime" >/dev/null; do
        [ $(( $(date +%s) - t0 )) -lt 120 ] || fail "$ip not ssh-ready 120 s after reset (budget)"
        sleep 3
    done
    say "$ip ready at +$(( $(date +%s) - t0 )) s: $(on "$ip" 10 uptime)"
done

# --- 2. iSCSI login on both, with the rig's hardening, and unique initiator names
for ip in $N1 $N2; do
    on "$ip" 60 "
        grep -q mxfs-node /etc/iscsi/initiatorname.iscsi || echo NO_UNIQUE_IQN
        cat /etc/iscsi/initiatorname.iscsi | grep -v '^#'
        for kv in 'node.conn[0].timeo.noop_out_timeout 30' 'node.conn[0].timeo.noop_out_interval 10' 'node.session.timeo.replacement_timeout 120'; do
            set -- \$kv
            iscsiadm -m node -T $QNAP_TGT -p $QNAP_PORTAL -o update -n \$1 -v \$2 2>/dev/null
        done
        iscsiadm -m session 2>/dev/null | grep -q f35772 || iscsiadm -m node -T $QNAP_TGT -p $QNAP_PORTAL --login
        for i in 1 2 3 4 5 6 7 8 9 10; do lsblk -S -o NAME,VENDOR | grep -q QNAP && break; sleep 1; done
        lsblk -S -o NAME,VENDOR,MODEL | grep QNAP
        echo login_rc=\$?
    " | tee "$EV/login_$ip.txt"
    grep -q NO_UNIQUE_IQN "$EV/login_$ip.txt" && fail "$ip still carries the template's shared initiator name"
    grep -q 'login_rc=0' "$EV/login_$ip.txt" || fail "$ip: QNAP LUN not visible"
done
on $N1 10 "lsblk -S -o NAME,VENDOR | awk '/QNAP/{print \"/dev/\"\$1}'" | grep -qx "$DEV" || fail "vstest1: QNAP LUN is not $DEV"

# --- 3. clear stale reservations (scratch key) and format, from vstest1
on $N1 60 "
    sg_persist --out --register-ignore --param-sark=$SCRATCH_KEY $DEV >/dev/null 2>&1; echo reg_rc=\$?
    sg_persist --out --clear --param-rk=$SCRATCH_KEY $DEV >/dev/null 2>&1; echo clear_rc=\$?
    sg_persist --in --read-keys $DEV 2>&1 | tail -3
    mkfs.mxfs -f $DEV 2>&1 | tail -3; echo mkfs_rc=\${PIPESTATUS[0]}
    uname -r; modinfo -F version mxfs; modinfo -F srcversion mxfs
    clocksource=\$(cat /sys/devices/system/clocksource/clocksource0/current_clocksource); echo clocksource=\$clocksource
" | tee "$EV/format.txt"
grep -q 'mkfs_rc=0' "$EV/format.txt" || fail "format failed"

# --- 4. instruments that leave the guest as they are written.  A hung guest
# loses its unflushed page cache on reset (measured: up to 30 s of a file
# follower's tail), so nothing here is written to the guest's own disk.
#   - sampler and dmesg -w stream over ssh sessions held open from clyde
#   - vstest1 also sends kernel messages to clyde with netconsole, which the
#     kernel emits itself and so survives userspace and sshd stopping; its
#     console loglevel is 5 (warning and worse — every stall reporter and
#     every MXFS ERR/WARN line) so the VGA console is not flooded
#   - hung-task reports after 10 s, soft lockups dump every CPU
CLYDE_IP=192.168.120.1
NETCON_PORT=6661
STREAM_S=$(( WATCH_S + ${JOIN_AFTER_S:-0} + 180 ))
NODES="$N1"
[ -n "$JOIN_AFTER_S" ] && NODES="$N1 $N2"
BGPIDS=""
socat -u UDP-RECV:$NETCON_PORT,reuseaddr OPEN:"$EV/netconsole_$N1.log",creat,append &
BGPIDS="$BGPIDS $!"
for ip in $NODES; do
    on $ip 30 "
        sysctl -q kernel.hung_task_timeout_secs=10 kernel.softlockup_all_cpu_backtrace=1 kernel.hung_task_warnings=-1
        if [ $ip = $N1 ]; then
            gwmac=\$(ip neigh show $CLYDE_IP | awk '{print \$5; exit}')
            modprobe -r netconsole 2>/dev/null
            modprobe netconsole netconsole=@/eth0,$NETCON_PORT@$CLYDE_IP/\$gwmac && echo netconsole_loaded mac=\$gwmac
            dmesg -n 5
            echo '<4>mxfs-harness: netconsole check $ip' > /dev/kmsg
        fi
    "
    on $ip "$STREAM_S" "dmesg -w" > "$EV/dmesg_$ip.log" &
    BGPIDS="$BGPIDS $!"
    on $ip "$STREAM_S" '
        while :; do
            # jiffies and each CPU'"'"'s local-timer interrupt count (LOC) say
            # whether the guest'"'"'s tick ran: a sleeping kernel thread is woken
            # by a jiffies timer, while this loop'"'"'s own sleep is an hrtimer, so
            # the loop can keep ticking over a stalled timer wheel.
            echo "T $(date +%s.%N) up=$(cut -d" " -f1 /proc/uptime) jiffies=$(awk "/^jiffies:/{print \$2; exit}" /proc/timer_list) LOC=$(awk "\$1==\"LOC:\"{s=\$2; for(i=3;i<=NF && \$i ~ /^[0-9]+\$/;i++) s=s\"/\"\$i; print s}" /proc/interrupts)"
            for c in /proc/[0-9]*/comm; do
                read -r n < $c 2>/dev/null || continue
                [ "$n" = mxfs-worker ] || [ "$n" = mount ] || continue
                d=${c%/comm}
                # state, last CPU (stat field 39) and voluntary context
                # switches: a thread whose count is flat did not wake
                echo "  ${d#/proc/} $n $(cut -d" " -f3,39 $d/stat 2>/dev/null) vcsw=$(awk "/^voluntary_ctxt_switches/{print \$2}" $d/status 2>/dev/null) $(head -3 $d/stack 2>/dev/null | cut -d" " -f2 | tr "\n" " ")"
            done
            sleep 1
        done' > "$EV/sampler_$ip.log" &
    BGPIDS="$BGPIDS $!"
done
sleep 3
grep -q "netconsole check $N1" "$EV/netconsole_$N1.log" || fail "netconsole from $N1 is not reaching clyde"
say "netconsole from $N1 verified; streams: $BGPIDS"
sleep 2
mount_on() { # ip peer label
    local a b
    a=$(date +%s.%N)
    on $1 "$MOUNT_BUDGET_S" "mkdir -p $MNT; mount -t mxfs -o peer=$2 $DEV $MNT; echo mount_rc=\$?; cut -d' ' -f1 /proc/uptime" | tee "$EV/mount_$3.txt"
    b=$(date +%s.%N)
    say "$3 mount wall: $(python3 -c "print('%.1f s' % ($b - $a))")"
    grep -q 'mount_rc=0' "$EV/mount_$3.txt"
}
# The original lone mount took 4.3 s; a joiner's pre-join survivor scan can
# legitimately run its full 62.5 s window, so the join gets that plus the
# same 30 s mount allowance.
MOUNT_BUDGET_S=30
mount_on $N1 $N2 vstest1 || fail "vstest1 mount failed"
if [ -n "$JOIN_AFTER_S" ]; then
    sleep "$JOIN_AFTER_S"
    MOUNT_BUDGET_S=93
    # In the background: a join that wedges must not stop the probes that
    # are the whole point of this run.
    ( mount_on $N2 $N1 vstest2 || say "vstest2 mount FAILED or exceeded ${MOUNT_BUDGET_S} s" ) &
    JOINPID=$!
fi

# --- 5. clyde-side probe: each guest's uptime every 2 s against clyde's clock
say "watching for $WATCH_S s"
wend=$(( $(date +%s) + WATCH_S ))
while [ "$(date +%s)" -lt "$wend" ]; do
    for ip in $NODES; do
        s=$(date +%s.%N)
        r=$(on $ip 5 "cut -d' ' -f1 /proc/uptime")
        rc=$?
        e=$(date +%s.%N)
        echo "$s rc=$rc rtt=$(python3 -c "print('%.2f' % ($e - $s))") $(echo $r)" >> "$EV/clyde_probe_$ip.log"
    done
    sleep 2
done
[ -n "${JOINPID:-}" ] && wait "$JOINPID"
say "--- placement after"
placement | tee "$EV/placement_after.txt"

# --- 6. stop the streams; the mounts are left as they are for inspection
kill $BGPIDS 2>/dev/null
wait $BGPIDS 2>/dev/null   # never a bare wait: it would also wait for the exec'd tee, which only exits with this script
for ip in $NODES; do
    on $ip 20 "grep ' mxfs ' /proc/mounts; true" > "$EV/mounts_at_end_$ip.txt"
done

# Gaps: the largest step between consecutive sampler ticks (guest wall and
# guest uptime) and between consecutive answered clyde probes, per node.
python3 - "$EV" $NODES <<'EOF' | tee "$EV/verdict.txt"
import sys, re
ev = sys.argv[1]
for ip in sys.argv[2:]:
    ticks = []
    for l in open("%s/sampler_%s.log" % (ev, ip)):
        m = re.match(r"T (\S+) up=(\S+)", l)
        if m:
            ticks.append((float(m.group(1)), float(m.group(2))))
    gw = max(((b[0] - a[0], a) for a, b in zip(ticks, ticks[1:])), default=(0, None))
    gu = max(((b[1] - a[1], a) for a, b in zip(ticks, ticks[1:])), default=(0, None))
    print("%s sampler ticks=%d  max_wall_gap=%.1f s at up=%s  max_uptime_gap=%.1f s at up=%s"
          % (ip, len(ticks), gw[0], gw[1] and gw[1][1], gu[0], gu[1] and gu[1][1]))
    # Timer stall: the longest run of consecutive ticks over which jiffies,
    # or one CPU's LOC count, did not move while uptime advanced.
    rows = []
    for l in open("%s/sampler_%s.log" % (ev, ip)):
        m = re.match(r"T \S+ up=(\S+) jiffies=(\d+) LOC=(\S+)", l)
        if m:
            rows.append((float(m.group(1)), int(m.group(2)), [int(x) for x in m.group(3).split("/")]))
    def longest_flat(key):
        best, start = (0.0, None), None
        for a, b in zip(rows, rows[1:]):
            if key(a) == key(b):
                start = a[0] if start is None else start
                if b[0] - start > best[0]:
                    best = (b[0] - start, start)
            else:
                start = None
        return best
    if rows:
        j = longest_flat(lambda r: r[1])
        print("%s jiffies flat longest=%.1f s from up=%s" % (ip, j[0], j[1]))
        for cpu in range(len(rows[0][2])):
            c = longest_flat(lambda r: r[2][cpu] if cpu < len(r[2]) else None)
            print("%s cpu%d LOC flat longest=%.1f s from up=%s" % (ip, cpu, c[0], c[1]))
    ans, miss = [], 0
    for l in open("%s/clyde_probe_%s.log" % (ev, ip)):
        f = l.split()
        if f[1] == "rc=0" and len(f) > 3:
            ans.append((float(f[0]), float(f[3])))
        else:
            miss += 1
    g = max(((b[0] - a[0], b[1] - a[1], a[1]) for a, b in zip(ans, ans[1:])), default=(0, 0, None))
    print("%s clyde probes answered=%d unanswered=%d  max_gap clyde=%.1f s guest_uptime=%.1f s at up=%s"
          % (ip, len(ans), miss, g[0], g[1], g[2]))
    if ans:
        drift = (ans[-1][1] - ans[0][1]) - (ans[-1][0] - ans[0][0])
        print("%s guest uptime advance minus clyde wall advance: %+.1f s" % (ip, drift))
EOF
for ip in $NODES; do
    echo "== $ip"
    grep -h -E 'P290-AUTH|P131-SELF-FENCE|P278-HB-STALL|P-HB-SLOW|heartbeat write failed|AUTH-HB-STOP|soft lockup|hung_task|blocked for more|P-DEPART-WORK|P-BOOT-SCAN|P-BOOT-CLAIM|MEMBERSHIP|handshake' "$EV/dmesg_$ip.log" "$EV/netconsole_$ip.log" 2>/dev/null | cut -c1-240
done
say "done: $EV"
