#!/bin/bash
# pve_concurrent_dio_upgrade.sh — one host runs a VM disk's I/O pattern on a
# file in MXFS (several io_uring workers doing direct reads, and direct writes
# that allocate into holes, all at once) while the other host keeps the same
# file's inode lock shared by statting it, as Proxmox's pvestatd does for every
# image on shared storage.
#
# For D-PVE-PHYS-DRBD-NODE-DIED-IN-A-LOCK-RELEASE-SPIN.  On 2026-10-05 the
# physical pair's pve2 cycled, on one image file, a refused upgrade of the
# inode lock to EX ('DLM inode lock failed: mode=5 rc=-35', P79-STALEBAST-CLEAR
# req=5 granted=3) and an aborted release of its PR ('P15-REL-ABORT ...
# holder re-acquired during drain'), with qemu's io workers admitted as nested
# PR holders meanwhile (P79-NESTADMIT comm=iou-wrk), for 252 s.  An allocating
# direct write upgrades the lock its own IOLOCK hold has at PR; the master
# refuses the upgrade while the peer holds PR, and the writer's own host must
# drop its PR first, which every other worker's hold keeps from completing.
# tests/drbd_dio_upgrade.sh times one such write alone; this runs them
# concurrently, the way qemu issues them.
#
# The spin's own lines are dynamic-debug probes: they are turned on for the run
# on the writer (and off again after), and counted per inode.
#
# Usage: tests/pve_concurrent_dio_upgrade.sh
# Env:
#   PVE_PAIR   "<writer> <peer>" (default "192.168.120.211 192.168.120.212",
#              nested pair B)
#   RUN_S      fio runtime in seconds (120)
#   WRITERS / READERS   io_uring jobs (4 / 2), iodepth 8 each, 64 KiB blocks
#   STAT_MS    the peer's stat period (100)
#   SIZE       the sparse file's size (4G): writes land in holes all run long
# Exit 0 only if fio finished on time, no filesystem shut down, both hosts are
# still mounted, and no 'EDEADLK retry livelock' was logged.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
PAIR_S=${PVE_PAIR:-192.168.120.211 192.168.120.212}
read -r -a PAIR <<<"$PAIR_S"
[ "${#PAIR[@]}" = 2 ] || { echo "pve_concurrent_dio_upgrade: PVE_PAIR must name two hosts"; exit 2; }
W=${PAIR[0]}; P=${PAIR[1]}
MNT=/mnt/shared
RUN_S=${RUN_S:-120}
WRITERS=${WRITERS:-4}
READERS=${READERS:-2}
STAT_MS=${STAT_MS:-100}
SIZE=${SIZE:-4G}
EVID="$REPO/tests/evidence/pve_concurrent_dio_upgrade/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$EVID" || exit 1
PROBES="P15-REL-ABORT P79-STALEBAST-CLEAR P79-NESTADMIT P109-EDEADLK"

on() {  # <host> <cmd> [timeout]
    timeout "${3:-30}" "$SSHP" "$1" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you|^$'
    return "${PIPESTATUS[0]}"
}
say() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$EVID/log"; }
probes() {  # <host> +p|-p
    local f
    for f in $PROBES; do
        on "$1" "echo 'module mxfs format \"$f\" $2' > /proc/dynamic_debug/control" 15
    done
}

say "evidence $EVID writer=$W peer=$P"
for h in "$W" "$P"; do
    on "$h" "hostname; cat /sys/module/mxfs/version /sys/module/mxfs/srcversion; grep ' cs:' /proc/drbd; grep -c ' $MNT mxfs ' /proc/mounts" 15 | tr '\n' ' ' | sed "s/^/$h: /" | tee -a "$EVID/log"
    echo | tee -a "$EVID/log"
done
D=$MNT/diolap/$(date -u +%H%M%S)
F=$D/disk.raw
on "$W" "mkdir -p $D && truncate -s $SIZE $F && stat -c 'ino=%i size=%s' $F" 30 | sed 's/^/file /' | tee -a "$EVID/log"
on "$P" "stat -c %i $F" 30 >/dev/null
probes "$W" +p
on "$W" "grep -c '=p .*P15-REL-ABORT' /proc/dynamic_debug/control" 15 | sed 's/^/probe sites on: /' | tee -a "$EVID/log"
on "$W" "echo '<5>mxfs-test: concurrent dio upgrade start' > /dev/kmsg" 15

# the peer: a stat of the file every STAT_MS for the whole run
( on "$P" "end=\$((\$(date +%s) + $RUN_S + 5)); n=0; while [ \$(date +%s) -lt \$end ]; do stat -c %s $F >/dev/null || echo STAT_FAIL; du -s $D >/dev/null; n=\$((n+1)); sleep $(awk "BEGIN{print $STAT_MS/1000}"); done; echo PEER_STATS=\$n" $(( RUN_S + 60 )) > "$EVID/peer.out" 2>&1 ) &
peer_pid=$!

# the writer: qemu's shape, direct I/O through io_uring from several workers
JOBS="--name=w --rw=randwrite --numjobs=$WRITERS --name=r --rw=randread --numjobs=$READERS"
on "$W" "fio --filename=$F --direct=1 --ioengine=io_uring --iodepth=8 --bs=64k --size=$SIZE --time_based --runtime=$RUN_S --group_reporting=0 --output-format=normal $JOBS > /dev/shm/dioup.fio 2>&1; echo FIO_RC=\$?; grep -E 'clat.*(max|usec|msec)|iops|err=' /dev/shm/dioup.fio | head -40" $(( RUN_S + 90 )) > "$EVID/fio.out" 2>&1
fio_rc=$?
wait "$peer_pid"
probes "$W" -p
on "$W" "journalctl -k -b --no-pager | sed -n '/mxfs-test: concurrent dio upgrade start/,\$p' | grep -aE 'mxfs|XFS'" 60 > "$EVID/klog.writer"
on "$P" "journalctl -k -b --no-pager --since '-$(( RUN_S + 120 )) s' | grep -aE 'mxfs|XFS'" 60 > "$EVID/klog.peer"

say "fio: ssh rc=$fio_rc $(grep -o 'FIO_RC=[0-9]*' "$EVID/fio.out")  peer: $(grep -o 'PEER_STATS=[0-9]*' "$EVID/peer.out") stat failures $(grep -c STAT_FAIL "$EVID/peer.out")"
for f in $PROBES 'DLM inode lock failed' 'EDEADLK retry livelock' 'EDEADLK-NL retry livelock' 'Filesystem has been shut down\|force_shutdown\|xfs_do_force_shutdown'; do
    say "writer '$f': $(grep -ac "$f" "$EVID/klog.writer")  peer: $(grep -ac "$f" "$EVID/klog.peer")"
done
say "P15-REL-ABORT per inode (top 3): $(grep -ao 'P15-REL-ABORT ino=[0-9]*' "$EVID/klog.writer" | sort | uniq -c | sort -rn | head -3 | tr '\n' ';')"
grep -aE 'clat \(.sec\).*max=' "$EVID/fio.out" | head -8 | tee -a "$EVID/log"
ok=1
grep -q 'FIO_RC=0' "$EVID/fio.out" || ok=0
grep -aqE 'retry livelock|Filesystem has been shut down|xfs_do_force_shutdown' "$EVID/klog.writer" "$EVID/klog.peer" && ok=0
for h in "$W" "$P"; do
    [ "$(on "$h" "grep -c ' $MNT mxfs ' /proc/mounts" 15)" = 1 ] || { say "$h lost its mount"; ok=0; }
done
on "$W" "rm -rf $D" 120
[ "$ok" = 1 ] && { say "PASS"; exit 0; }
say "FAIL"
exit 1
