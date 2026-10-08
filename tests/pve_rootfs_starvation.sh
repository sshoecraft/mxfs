#!/bin/bash
# pve_rootfs_starvation.sh — does the host that RECEIVES a peer's MXFS writes
# keep its own root filesystem usable?
#
# On the physical DRBD pair the backing volume and the host's root filesystem
# share one SATA disk.  While participant 0 writes to MXFS, every one of its
# writes is also written on participant 1's disk by DRBD's receiver; measured
# 2026-10-06, participant 1's root-filesystem fsync then took 857 ms at the
# median and an ssh command 14-20 s to start (D-DRBD-PAIR-HOSTS-WRITE-ONE-AT-
# A-TIME-THE-SECOND-WAITS-FOR-THE-FIRST), and turning writeback throttling off
# on that disk once cut the fsync to 54 ms.
#
# Each arm: participant 0 runs LOAD_S of fio (JOBS O_DIRECT writers, 1 MiB,
# QD16) in a directory of its own on the storage; meanwhile, every PERIOD_S,
# participant 1 times a 4 KiB write + fsync on its root filesystem, and this
# host times an ssh `true` to participant 1.  Arms alternate wbt at the disk's
# default and wbt off (queue/wbt_lat_usec = 0) on participant 1's DRBD
# backing disk, ARMS_EACH times each; the disk's own value is put back after.
#
# Usage: tests/pve_rootfs_starvation.sh
# Env:
#   PVE_PAIR   "<addr> <addr>" (default the physical pair); participant 0 writes
#   LOAD_S     seconds of load per arm (60)
#   JOBS       fio writers (4)
#   PERIOD_S   seconds between samples (2)
#   ARMS_EACH  arms per wbt setting (2)
#   FSYNC_BUDGET_MS  the median root fsync under load that passes (100: an
#              idle SATA SSD fsyncs a 4 KiB write in a few ms, so 100 ms is far
#              past twice that; the 2026-10-06 figure was 857)
#   SSH_BUDGET_MS    the worst ssh `true` that passes (3000: ~0.3-0.5 s idle)
# Output: per arm, the root fsync median / p90 / max and the ssh median / max.
# Exit 0 when the default-wbt arms meet both budgets.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
read -r -a H <<<"${PVE_PAIR:-192.168.1.80 192.168.1.81}"
LOAD_S=${LOAD_S:-60}
JOBS=${JOBS:-4}
PERIOD_S=${PERIOD_S:-2}
ARMS_EACH=${ARMS_EACH:-2}
FS_BUDGET=${FSYNC_BUDGET_MS:-100}
SSH_BUDGET=${SSH_BUDGET_MS:-3000}
MNT=/mnt/shared
EVID="$REPO/tests/evidence/pve_rootfs_starvation/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$EVID" || exit 1
bad=0

on() {  # <host> <cmd> <timeout>
    timeout "$3" "$SSHP" "$1" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you|^$'
    return "${PIPESTATUS[0]}"
}
say() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$EVID/log"; }
stats() {  # <file of numbers> -> "median p90 max n"
    sort -n "$1" | awk '{a[NR]=$1} END {if (NR == 0) {print "- - - 0"; exit}
        m=a[int((NR+1)/2)]; p=a[int(NR*0.9 + 0.999)]; if (p == "") p=a[NR];
        print m, p, a[NR], NR}'
}

# participant 1's DRBD backing disk: the whole disk under the backing LV
DISK=$(on "${H[1]}" "lsblk -slno NAME,TYPE \$(readlink -f /dev/pve/mxfs) | awk '\$2 == \"disk\" {print \$1}' | head -1" 30 | tail -1)
[ -n "$DISK" ] || { say "cannot find participant 1's backing disk"; exit 1; }
ORIG=$(on "${H[1]}" "cat /sys/block/$DISK/queue/wbt_lat_usec" 30)
say "evidence $EVID; participant 1 ${H[1]} backing disk $DISK wbt_lat_usec=$ORIG"
for h in "${H[@]}"; do
    say "$(on "$h" "echo \$(uname -n) build=\$(cat /sys/module/mxfs/srcversion)" 30)"
done

arm() {  # <tag> <wbt value to set>
    local tag=$1 val=$2 t_end d f s
    on "${H[1]}" "echo $val > /sys/block/$DISK/queue/wbt_lat_usec; cat /sys/block/$DISK/queue/wbt_lat_usec" 30 > "$EVID/$tag.wbt"
    d=$MNT/rootstarve/$(date -u +%H%M%S)-$tag
    on "${H[0]}" "mkdir -p $d && fio --name=load --directory=$d --numjobs=$JOBS --size=1G --bs=1M --rw=write --direct=1 --ioengine=libaio --iodepth=16 --time_based --runtime=$LOAD_S --group_reporting --output-format=terse > /dev/null 2>&1; echo FIO_RC=\$?; rm -rf $d" $(( LOAD_S + 120 )) > "$EVID/$tag.fio" 2>&1 &
    local fpid=$!
    sleep 5
    f="$EVID/$tag.fsync_ms"; s="$EVID/$tag.ssh_ms"; : > "$f"; : > "$s"
    t_end=$(( $(date +%s) + LOAD_S - 10 ))
    while [ "$(date +%s)" -lt "$t_end" ]; do
        local t0 out
        t0=$(date +%s%N)
        out=$(on "${H[1]}" "a=\$(date +%s%N); dd if=/dev/zero of=/var/tmp/rootstarve.probe bs=4k count=1 conv=fsync 2>/dev/null; echo FS_MS=\$(( (\$(date +%s%N) - a) / 1000000 ))" 120)
        echo $(( ($(date +%s%N) - t0) / 1000000 )) >> "$s"
        grep -o 'FS_MS=[0-9]*' <<<"$out" | cut -d= -f2 >> "$f"
        sleep "$PERIOD_S"
    done
    wait "$fpid"
    on "${H[1]}" "rm -f /var/tmp/rootstarve.probe" 30 > /dev/null
    read -r fm fp fx fn <<<"$(stats "$f")"
    read -r sm sp sx sn <<<"$(stats "$s")"
    say "$tag wbt=$(cat "$EVID/$tag.wbt") $(tr '\n' ' ' < "$EVID/$tag.fio")root fsync ms median=$fm p90=$fp max=$fx n=$fn; ssh ms median=$sm max=$sx"
    if [ "$val" = -1 ]; then
        if [ "$fm" = - ] || [ "$fm" -gt "$FS_BUDGET" ] || [ "$sx" -gt "$SSH_BUDGET" ]; then
            say "$tag over budget (root fsync median <= ${FS_BUDGET} ms, ssh <= ${SSH_BUDGET} ms)"
            bad=1
        fi
    fi
}

for i in $(seq 1 "$ARMS_EACH"); do
    arm "default-$i" -1
    arm "wbtoff-$i" 0
done
on "${H[1]}" "echo $ORIG > /sys/block/$DISK/queue/wbt_lat_usec; cat /sys/block/$DISK/queue/wbt_lat_usec" 30 | sed "s/^/restored wbt_lat_usec=/" | tee -a "$EVID/log"
[ "$bad" = 0 ] && say "RESULT PASS" || say "RESULT FAIL"
exit "$bad"
