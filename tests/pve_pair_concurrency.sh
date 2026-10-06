#!/bin/bash
# pve_pair_concurrency.sh — do both hosts of an MXFS-on-DRBD Proxmox pair
# write at the same time, and when one waits, what does it wait on?
#
# tests/pve_pair_write_bound.sh found participant 1's writers starting
# 0.26-0.39 s after participant 0's ended, in every arm, so the pair ran at one
# host's speed.  That test starts the loads over ssh one host after the other,
# and an ssh command to participant 1 took 14-20 s to start while participant
# 0 wrote.  A load whose launch waited is not a load that waits on the other
# host's writes, so this takes the launch out of what is measured and samples
# what participant 1 waits on instead.
#
#  1. Each host lays out its own files (DIO_JOBS x FILE_MB MiB, written with
#     O_DIRECT and fsynced) in a directory of its own, before anything is timed.
#  2. Both loads are armed over ssh to start at one wall-clock second T, ARM_S
#     ahead, so every launch cost is paid before T (both hosts keep NTP time).
#     Each load overwrites its own laid-out files: DIO_JOBS x O_DIRECT QD16 x
#     1 MiB, time_based for RUN_S s, logging its bandwidth every second.
#  3. Participant 1 runs three samplers armed the same way, writing to /run
#     (tmpfs, so a sampler's own output queues behind nothing), each its own
#     loop so one that blocks cannot stop the others: a stat of its MXFS
#     directory, a 4 KiB O_DIRECT write + fsync on its root filesystem, and the
#     tasks in D with the top of their kernel stacks.
#  4. From here, an ssh `true` to participant 1 is timed every 2 s.
#
# Output: both hosts' per-second write bandwidth side by side, the seconds in
# which both wrote, participant 1's samples summarised, the ssh times.  It
# grades nothing; it is an instrument.
#
# Usage: tests/pve_pair_concurrency.sh
# Env:   PVE_PAIR (default "192.168.1.80 192.168.1.81"), MNT (/mnt/shared),
#        RUN_S (60), DIO_JOBS (4), FILE_MB (256), ARM_S (30)
# Evidence: tests/evidence/pve_pair_concurrency/<UTC stamp>/

set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
read -r -a PAIR <<<"${PVE_PAIR:-192.168.1.80 192.168.1.81}"
[ "${#PAIR[@]}" = 2 ] || { echo "pve_pair_concurrency: PVE_PAIR must name two hosts"; exit 2; }
MNT=${MNT:-/mnt/shared}
RUN_S=${RUN_S:-60}
DIO_JOBS=${DIO_JOBS:-4}
FILE_MB=${FILE_MB:-256}
ARM_S=${ARM_S:-30}
# The layout writes DIO_JOBS x FILE_MB on each host at once: 2 GiB through one
# gigabit link and two SATA disks the pair has measured at ~35 MB/s together
# with the write cap, ~60 s; four times that.
LAYOUT_BUDGET=240
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
# Named for the pair too, so two pairs' runs never share a directory.
EVID="$REPO/tests/evidence/pve_pair_concurrency/$STAMP-${PAIR[0]}"
mkdir -p "$EVID" || exit 1

say() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$EVID/log"; }
on() {  # <host> <cmd> [timeout]
    timeout "${3:-60}" "$SSHP" "$1" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you|^$'
    return "${PIPESTATUS[0]}"
}
if python3 -I -c 'import ipaddress, sys; sys.exit(0 if ipaddress.ip_address(sys.argv[1]) < ipaddress.ip_address(sys.argv[2]) else 1)' "${PAIR[0]}" "${PAIR[1]}"; then
    P0=${PAIR[0]}; P1=${PAIR[1]}
else
    P0=${PAIR[1]}; P1=${PAIR[0]}
fi
FIO="fio --name=conc --numjobs=$DIO_JOBS --size=${FILE_MB}M --bs=1M --rw=write --direct=1 --ioengine=libaio --iodepth=16"

declare -A NAME
for h in "$P0" "$P1"; do
    s=$(on "$h" "echo \"name=\$(hostname) mnt=\$(awk '\$2 == \"$MNT\" && \$3 == \"mxfs\" {print \$2}' /proc/mounts | head -1) role=\$(drbdadm role mxfs 2>/dev/null) cs=\$(drbdadm cstate mxfs 2>/dev/null) build=\$(cat /sys/module/mxfs/srcversion 2>/dev/null) kb=\$(cat /sys/module/mxfs/parameters/drbd_inflight_kb 2>/dev/null) fio=\$(command -v fio) ntp=\$(timedatectl show -p NTPSynchronized --value 2>/dev/null)\"" 20)
    say "$h: $s"
    case "$s" in *"mnt=$MNT "*"role=Primary/Primary cs=Connected"*"fio=/"*) ;; *) say "ABORT: $h is not a mounted, connected half of the pair with fio"; exit 1 ;; esac
    NAME[$h]=$(sed -n 's/^name=\([^ ]*\).*/\1/p' <<<"$s")
done

# Participant 1's samplers: <dir> <T> <end> <out prefix> <root fs probe file>.
# Each loop is its own process, so one blocked in the kernel stops only itself.
SAMPLER=$(cat <<'EOF'
d=$1; T=$2; end=$3; out=$4; probe=$5
python3 -I -c 'import sys, time; time.sleep(max(0.0, float(sys.argv[1]) - time.time()))' "$T"
( while [ "$(date +%s)" -lt "$end" ]; do
      a=$(date +%s%N); stat "$d" > /dev/null 2>&1; b=$(date +%s%N)
      echo "$a $(( (b - a) / 1000000 ))"; sleep 1
  done ) > "$out.stat" 2>&1 &
( while [ "$(date +%s)" -lt "$end" ]; do
      a=$(date +%s%N); dd if=/dev/zero of="$probe" bs=4k count=1 oflag=direct conv=fsync status=none; b=$(date +%s%N)
      echo "$a $(( (b - a) / 1000000 ))"; sleep 1
  done; rm -f "$probe" ) > "$out.rootfs" 2>&1 &
( while [ "$(date +%s)" -lt "$end" ]; do
      now=$(date +%s)
      for s in $(awk '{ i = index($0, ") "); split(substr($0, i + 2), f, " "); if (f[1] == "D") print FILENAME }' /proc/[0-9]*/stat 2>/dev/null); do
          p=${s%/stat}
          echo "$now ${p#/proc/} $(cat "$p/comm" 2>/dev/null) $(head -4 "$p/stack" 2>/dev/null | sed 's/^\[<[0-9a-f]*>\] //; s/+0x.*//' | tr '\n' ',')"
      done
      sleep 1
  done ) > "$out.dstate" 2>&1 &
wait
EOF
)

say "layout: $DIO_JOBS x $FILE_MB MiB per host, both hosts at once"
for h in "$P0" "$P1"; do
    on "$h" "d=$MNT/conc/$STAMP/\$(hostname); mkdir -p \$d && cd \$d && $FIO --end_fsync=1 --output-format=terse > /dev/null 2>&1; echo LAYOUT_RC=\$?" "$LAYOUT_BUDGET" > "$EVID/layout.$h" &
done
wait
for h in "$P0" "$P1"; do
    grep -q 'LAYOUT_RC=0' "$EVID/layout.$h" || { say "ABORT: $h's layout did not finish within ${LAYOUT_BUDGET}s: $(tail -1 "$EVID/layout.$h")"; exit 1; }
done

T=$(( $(date +%s) + ARM_S ))
WAIT_T="python3 -I -c 'import sys, time; time.sleep(max(0.0, float(sys.argv[1]) - time.time()))' $T"
END=$(( T + RUN_S + 5 ))
say "arming both loads for $(date -d @$T +%H:%M:%S) (T=$T), $RUN_S s each"
for h in "$P0" "$P1"; do
    on "$h" "d=$MNT/conc/$STAMP/\$(hostname); cd \$d || exit 1
        nohup setsid bash -c \"$WAIT_T; exec $FIO --time_based --runtime=$RUN_S --write_bw_log=/run/conc-$STAMP --log_avg_msec=1000 --log_unix_epoch=1 --output-format=json --output=/run/conc-$STAMP.json\" > /dev/null 2>&1 < /dev/null &
        echo ARMED" 30 | grep -q ARMED || { say "ABORT: could not arm $h"; exit 1; }
done
on "$P1" "echo $(base64 -w0 <<<"$SAMPLER") | base64 -d > /run/conc-$STAMP.sampler && nohup setsid bash /run/conc-$STAMP.sampler $MNT/conc/$STAMP/${NAME[$P1]} $T $END /run/conc-$STAMP /var/tmp/conc-$STAMP.probe > /dev/null 2>&1 < /dev/null &
    echo SAMPLERS_ARMED" 30 | grep -q SAMPLERS_ARMED || { say "ABORT: could not arm $P1's samplers"; exit 1; }

# ssh from here to participant 1, every 2 s across the run
python3 -I -c 'import sys, time; time.sleep(max(0.0, float(sys.argv[1]) - time.time()))' "$T"
say "T: both loads due now"
while [ "$(date +%s)" -lt "$END" ]; do
    a=$(date +%s%N); timeout 30 "$SSHP" "$P1" true </dev/null >/dev/null 2>&1; b=$(date +%s%N)
    echo "$(( a / 1000000000 )) $(( (b - a) / 1000000 ))" >> "$EVID/ssh_p1.txt"
    sleep 2
done
sleep 10

for h in "$P0" "$P1"; do
    on "$h" "cat /run/conc-${STAMP}_bw.*.log 2>/dev/null" 30 > "$EVID/bw.$h.log"
    on "$h" "cat /run/conc-$STAMP.json 2>/dev/null" 30 > "$EVID/fio.$h.json"
done
for k in stat rootfs dstate; do on "$P1" "cat /run/conc-$STAMP.$k 2>/dev/null" 30 > "$EVID/p1.$k"; done
on "$P0" "rm -f /run/conc-${STAMP}_bw.*.log /run/conc-$STAMP.json; rm -rf $MNT/conc/$STAMP" 120 >/dev/null
on "$P1" "rm -f /run/conc-${STAMP}_bw.*.log /run/conc-$STAMP.json /run/conc-$STAMP.stat /run/conc-$STAMP.rootfs /run/conc-$STAMP.dstate /run/conc-$STAMP.sampler" 30 >/dev/null

python3 -I - "$EVID" "$P0" "$P1" "$T" "$RUN_S" <<'EOF' | tee -a "$EVID/log"
import collections, statistics, sys
evid, p0, p1, t0, run = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5])
def bw(h):
    per = collections.Counter()
    for line in open(f"{evid}/bw.{h}.log"):
        f = [x.strip() for x in line.split(",")]
        if len(f) >= 2 and f[0].isdigit():
            per[int(f[0]) // 1000] += int(f[1])          # KiB/s, summed over jobs
    return per
a, b = bw(p0), bw(p1)
secs = range(t0, t0 + run + 3)
both = sum(1 for s in secs if a[s] > 1024 and b[s] > 1024)
only0 = sum(1 for s in secs if a[s] > 1024 and b[s] <= 1024)
only1 = sum(1 for s in secs if b[s] > 1024 and a[s] <= 1024)
print(f"per second, MiB/s written (T = {t0}):   {p0:>15} {p1:>15}")
for s in secs:
    print(f"  T+{s - t0:3d}  {a[s] / 1024:15.1f} {b[s] / 1024:15.1f}")
print(f"seconds both wrote: {both}; only {p0}: {only0}; only {p1}: {only1}; total MiB {sum(a.values()) / 1024:.0f} / {sum(b.values()) / 1024:.0f}")
def series(k):
    out = []
    for line in open(f"{evid}/p1.{k}"):
        f = line.split()
        if len(f) == 2 and f[1].isdigit():
            out.append((int(f[0]) // 10**9 - t0, int(f[1])))
    return out
for k, what in (("stat", "stat of its MXFS directory"), ("rootfs", "4 KiB write+fsync on its root fs")):
    v = series(k)
    if v:
        ms = [m for _, m in v]
        worst = sorted(v, key=lambda x: -x[1])[:5]
        print(f"{p1} {what}: n={len(ms)} p50={statistics.median(ms)} ms max={max(ms)} ms; worst at " + ", ".join(f"T+{t}:{m}ms" for t, m in worst))
    else:
        print(f"{p1} {what}: no samples")
d = collections.Counter()
for line in open(f"{evid}/p1.dstate"):
    f = line.split(" ", 3)
    if len(f) == 4:
        d[(f[2], f[3].strip())] += 1
print(f"{p1} tasks in D (samples, comm, top of stack):")
for (c, k), n in d.most_common(12):
    print(f"  {n:4d}  {c}  {k[:160]}")
ssh = [tuple(map(int, l.split())) for l in open(f"{evid}/ssh_p1.txt") if l.strip()]
if ssh:
    print(f"ssh true to {p1}: n={len(ssh)} p50={statistics.median([m for _, m in ssh])} ms max={max(m for _, m in ssh)} ms")
EOF
say "evidence $EVID"
