#!/bin/bash
#
# vsphere_nfs_control.sh — the vSphere Ubuntu pair under I/O load with the
# mxfs module unable to load: does the guest still hang?
#
# Every hang seen on vstest1/vstest2 so far (soft lockups on every CPU at boot,
# an idle unmounted guest going silent, a mounted guest stuck in a user page
# fault walking its maple tree) happened with mxfs loaded, on guests nested two
# hypervisors deep (Ubuntu 6.8.0-53 -> ESXi -> VMware Workstation on clyde).
# This removes mxfs and nothing else:
#   - the module file itself is moved aside (modinfo -n mxfs -> /root) and
#     depmod rerun, so no path can load it — a modprobe.d "install mxfs
#     /bin/false" block was measured NOT to stop it loading at boot on vstest2;
#     the run refuses to start unless lsmod shows it absent after the reset
#   - same hosts, same vCPU count, iSCSI still logged in to the QNAP
#   - load on the same routed path to the QNAP the MXFS runs used: 256 MB
#     writes with fsync + read-back and 500-file create/delete on its NFS
#     export (/data/tmp), plus direct raw reads of the iSCSI LUN (read-only)
#   - the same off-guest instruments: dmesg -w streamed over ssh, netconsole
#     from each guest, and clyde-side uptime probes every 2 s
#
# Usage: tests/vsphere_nfs_control.sh [load_seconds] [restore]
#   restore: put the module file back on both guests and exit.
#
# Budgets: reset to ssh measured 25-35 s -> 60 s; the load window is an
# observation period: the MXFS runs hung 70-250 s after mount, so the default
# 600 s is more than twice the latest one.
#
set -u

LOAD_S="${1:-600}"
N1=192.168.120.177
N2=192.168.120.150
NFS_SRC=192.168.1.4:/data
CLYDE_IP=192.168.120.1
READY_S=60

HERE="$(cd "$(dirname "$0")/.." && pwd)"
SSH="$HERE/tools/mxfs_sshpass.sh"
on() { local ip=$1 t=$2; shift 2; timeout "$t" "$SSH" "$ip" "$@" 2>&1 | grep --line-buffered -v -E "^Warning: Permanently|^$|Unauthorized access|authorized user, disconnect"; return "${PIPESTATUS[0]}"; }
name() { case $1 in $N1) echo vstest1 ;; $N2) echo vstest2 ;; esac; }
port() { case $1 in $N1) echo 6661 ;; $N2) echo 6662 ;; esac; }

if [ "${2:-}" = restore ]; then
    for ip in $N1 $N2; do on $ip 60 "rm -f /etc/modprobe.d/zz-mxfs-off.conf; [ -s /root/mxfs-ko-aside.path ] && mv /root/mxfs-ko-aside \$(cat /root/mxfs-ko-aside.path) && rm -f /root/mxfs-ko-aside.path && depmod -a; modinfo -n mxfs"; done
    exit 0
fi

EV="$HERE/tests/evidence/vsphere_nfs_control/$(date +%Y%m%dT%H%M%S)"
mkdir -p "$EV"
exec > >(tee -a "$EV/run.log") 2>&1
say() { echo "[$(date +%T)] $*"; }
fail() { say "FAIL: $*"; exit 1; }

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
    local vm
    for vm in vstest1 vstest2; do
        timeout 30 govc vm.info -json "$(vmpath $vm)" | python3 -c '
import json, sys
v = json.load(sys.stdin)["virtualMachines"][0]
print("%s power=%s host=%s vcpu=%s cpu_mhz=%s" % (sys.argv[1], v["runtime"]["powerState"],
      v["runtime"]["host"]["value"], v["config"]["hardware"]["numCPU"],
      v["summary"]["quickStats"].get("overallCpuUsage")))' "$vm"
    done
}
wait_ready() {
    local t0
    t0=$(date +%s)
    until on $1 10 true >/dev/null; do
        [ $(( $(date +%s) - t0 )) -lt "$READY_S" ] || return 1
        sleep 3
    done
    echo $(( $(date +%s) - t0 ))
}

say "evidence: $EV load=${LOAD_S}s"
placement | tee "$EV/placement_before.txt"

# --- 1. block mxfs on both guests (reset first if a guest is unreachable)
for ip in $N1 $N2; do
    if ! wait_ready $ip >/dev/null; then
        timeout 60 govc vm.power -reset "$(vmpath $(name $ip))" >/dev/null
        wait_ready $ip >/dev/null || fail "$(name $ip) unreachable before the block could be installed"
    fi
    on $ip 180 "
        command -v mount.nfs >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get install -y -q nfs-common >/dev/null 2>&1
        command -v mount.nfs || echo NO_MOUNT_NFS
        rm -f /etc/modprobe.d/zz-mxfs-off.conf
        if [ ! -f /root/mxfs-ko-aside.path ]; then
            f=\$(modinfo -n mxfs 2>/dev/null)
            [ -n \"\$f\" ] && [ -f \"\$f\" ] && echo \$f > /root/mxfs-ko-aside.path && mv \$f /root/mxfs-ko-aside && depmod -a
        fi
        echo aside=\$(cat /root/mxfs-ko-aside.path); modinfo -n mxfs 2>&1 | head -1
    " | tee "$EV/block_$(name $ip).txt"
    grep -q NO_MOUNT_NFS "$EV/block_$(name $ip).txt" && fail "$(name $ip): nfs-common could not be installed"
done
for ip in $N1 $N2; do timeout 60 govc vm.power -reset "$(vmpath $(name $ip))" >/dev/null; say "$(name $ip) reset"; done
for ip in $N1 $N2; do
    r=$(wait_ready $ip) || { timeout 60 govc vm.console -capture "$EV/console_boot_$(name $ip).png" "$(vmpath $(name $ip))" >/dev/null 2>&1; fail "$(name $ip) not ssh-ready ${READY_S} s after reset (console saved)"; }
    say "$(name $ip) ready at +${r} s"
    on $ip 20 "lsmod | grep -c '^mxfs'; true" > "$EV/lsmod_$(name $ip).txt"
    [ "$(cat "$EV/lsmod_$(name $ip).txt")" = 0 ] || fail "$(name $ip): mxfs is loaded despite the block"
    on $ip 60 "
        uname -r
        iscsiadm -m session 2>/dev/null | grep -q f35772 || iscsiadm -m node -T iqn.2004-04.com.qnap:ts-453pro:iscsi.target-0.f35772 -p 192.168.1.4 --login >/dev/null 2>&1
        for i in 1 2 3 4 5 6 7 8 9 10; do lsblk -S -o NAME,VENDOR | grep -q QNAP && break; sleep 1; done
        iscsiadm -m session 2>&1 | head -2
        lsblk -S -o NAME,VENDOR | awk '/QNAP/{print \"/dev/\"\$1}'
        mkdir -p /mnt/data && { mountpoint -q /mnt/data || mount -t nfs -o rw,vers=3,soft,timeo=100,retrans=5,tcp $NFS_SRC /mnt/data; }
        mountpoint -q /mnt/data && mkdir -p /mnt/data/tmp/mxfs-control/$(name $ip) && echo nfs_ok
    " | tee "$EV/prep_$(name $ip).txt"
    grep -q nfs_ok "$EV/prep_$(name $ip).txt" || fail "$(name $ip): NFS /data not writable"
done
say "mxfs absent on both guests (lsmod) and blocked from loading"

# --- 2. off-guest instruments
BGPIDS=""
for ip in $N1 $N2; do
    socat -u UDP-RECV:$(port $ip),reuseaddr OPEN:"$EV/netconsole_$(name $ip).log",creat,append &
    BGPIDS="$BGPIDS $!"
    on $ip 30 "
        sysctl -q kernel.hung_task_timeout_secs=10 kernel.softlockup_all_cpu_backtrace=1 kernel.hung_task_warnings=-1
        gwmac=\$(ip neigh show $CLYDE_IP | awk '{print \$5; exit}')
        modprobe -r netconsole 2>/dev/null
        modprobe netconsole netconsole=@/eth0,$(port $ip)@$CLYDE_IP/\$gwmac
        dmesg -n 5
        echo '<4>mxfs-harness: netconsole check $ip' > /dev/kmsg
    "
    on $ip $(( LOAD_S + 120 )) "dmesg -w" > "$EV/dmesg_$(name $ip).log" &
    BGPIDS="$BGPIDS $!"
done
sleep 3
for ip in $N1 $N2; do
    grep -q "netconsole check $ip" "$EV/netconsole_$(name $ip).log" || fail "netconsole from $(name $ip) is not reaching clyde"
done

# --- 3. the load: runs on each guest for LOAD_S, one line per iteration
for ip in $N1 $N2; do
    n=$(name $ip)
    on $ip $(( LOAD_S + 60 )) "
        dev=\$(lsblk -S -o NAME,VENDOR | awk '/QNAP/{print \"/dev/\"\$1; exit}')
        d=/mnt/data/tmp/mxfs-control/$n
        end=\$(( \$(date +%s) + $LOAD_S )); i=0
        while [ \$(date +%s) -lt \$end ]; do
            i=\$((i+1)); t0=\$(date +%s.%N)
            dd if=/dev/zero of=\$d/big bs=1M count=256 conv=fsync status=none; w=\$?
            dd if=\$d/big of=/dev/null bs=1M status=none; r=\$?
            mkdir -p \$d/small; for f in \$(seq 1 500); do echo \$f > \$d/small/f\$f; done; sync \$d/small; rm -rf \$d/small; s=\$?
            dd if=\$dev of=/dev/null bs=1M count=64 skip=\$(( (i * 64) % 40000 )) iflag=direct status=none; l=\$?
            echo \"iter=\$i up=\$(cut -d' ' -f1 /proc/uptime) secs=\$(awk -v a=\$t0 -v b=\$(date +%s.%N) 'BEGIN{printf \"%.1f\", b-a}') nfs_w=\$w nfs_r=\$r small=\$s lun_r=\$l\"
        done
        rm -f \$d/big; echo load_done
    " > "$EV/load_$n.log" &
    BGPIDS="$BGPIDS $!"
done
say "load running on both guests for ${LOAD_S} s"

# --- 4. clyde-side probes
wend=$(( $(date +%s) + LOAD_S ))
while [ "$(date +%s)" -lt "$wend" ]; do
    for ip in $N1 $N2; do
        s=$(date +%s.%N)
        r=$(on $ip 5 "cut -d' ' -f1 /proc/uptime")
        rc=$?
        e=$(date +%s.%N)
        echo "$s rc=$rc rtt=$(python3 -c "print('%.2f' % ($e - $s))") $(echo $r)" >> "$EV/clyde_probe_$(name $ip).log"
    done
    sleep 2
done
sleep 30        # let the last iteration finish
placement | tee "$EV/placement_after.txt"
kill $BGPIDS 2>/dev/null

# --- 5. verdict
python3 - "$EV" <<'EOF' | tee "$EV/verdict.txt"
import sys, re
ev = sys.argv[1]
for n in ("vstest1", "vstest2"):
    ans, miss = [], 0
    for l in open("%s/clyde_probe_%s.log" % (ev, n)):
        f = l.split()
        if f[1] == "rc=0" and len(f) > 3:
            ans.append((float(f[0]), float(f[3])))
        else:
            miss += 1
    g = max(((b[0] - a[0], b[1] - a[1]) for a, b in zip(ans, ans[1:])), default=(0, 0))
    drift = ((ans[-1][1] - ans[0][1]) - (ans[-1][0] - ans[0][0])) if len(ans) > 1 else 0
    it = [l for l in open("%s/load_%s.log" % (ev, n)) if l.startswith("iter=")]
    bad = [l for l in it if re.search(r"(nfs_w|nfs_r|small|lun_r)=[1-9]", l)]
    secs = [float(re.search(r"secs=([\d.]+)", l).group(1)) for l in it if re.search(r"secs=([\d.]+)", l)]
    lk = 0
    for f in ("dmesg", "netconsole"):
        try:
            lk += sum(1 for l in open("%s/%s_%s.log" % (ev, f, n)) if re.search(r"soft lockup|blocked for more than|rcu.*stall", l))
        except OSError:
            pass
    print("%s probes answered=%d unanswered=%d max_gap=%.1f s uptime_drift=%+.1f s | load iters=%d failed=%d iter_secs max=%.1f | lockup/hung/stall lines=%d"
          % (n, len(ans), miss, g[0], drift, len(it), len(bad), max(secs, default=0), lk))
EOF
say "done: $EV"
