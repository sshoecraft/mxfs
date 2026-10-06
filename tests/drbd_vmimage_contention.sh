#!/bin/bash
# drbd_vmimage_contention.sh — VM disk images on MXFS, used from two nodes the
# way Proxmox uses them, with every I/O error counted.
#
# WHY.  On the physical PVE pair (2/net/mesh/drbd, 0.90.55) a VM whose disk
# was a file on /mnt/shared got I/O errors on reads and writes and its XFS
# shut down, while both nodes were up and DRBD was Connected
# (D-DRBD-GUEST-EIO-UNDER-LOAD-WHILE-CAS-WAITS-ON-PEER-TICKET).  The errors
# came in batches that failed together, and both hosts logged acquires on VM
# image inodes that had been abandoned (P-TAUTH-LOCAL-ORPHAN-RELEASE,
# P958-ACQ-IDLE-LOST).  What touches a running VM's image from the other node
# is a live migration (the target opens the image and reads its head) and the
# storage tools (`qemu-img info`, a content listing).  This puts exactly that
# beside a VM-like load and counts every error either side sees.
#
# Phases, each PHASE_S seconds of time_based load:
#   probe    node A runs the VM load on image A (fio: O_DIRECT, io_uring as
#            Proxmox 9 runs QEMU disks, so the first issue of each I/O is
#            non-blocking; 4 KiB random 60/40 read/write, QD16, on a sparse
#            file, so first writes allocate); node B opens image A with
#            O_DIRECT every 2 s, reads its
#            first 64 KiB and fstats it (qemu's open probe / `qemu-img info`).
#   handoff  the migration: node A's load on image A ends, node B's load on
#            image A starts at once (the target resumes the guest), and node A
#            probes image A as node B did.
#   pair     two VMs, one per node, on images A and B in one directory: node A
#            loads image B, node B loads image A, each probes the other's image.
#   bulk     the pair phase beside an image build: node A also writes a third
#            file sequentially (1 MiB, QD8, buffered then fsync'd, as an OS
#            installer's disk fills), so the replication link carries bulk
#            data while the lock traffic and DRBD's emulated compare-and-swap
#            (its register writes share DRBD's data stream) go on beside it.
#   storm    the bulk phase with an image build on BOTH nodes, each writing a
#            file of its own: the physical pair's evening, a VM installing on
#            each host while each also runs the other's image probe.
# The mount must already be up on both nodes (scripts/drbd_rig.sh up + mxfs,
# or any 2-node MXFS mount at MNT).
#
# CAP_MBIT=<n> shapes everything each node sends to the other to n Mbit/s for
# the run (htb on the interface that routes to the peer; traffic to any other
# host is untouched) and removes the shaping at exit.  The rig's two nodes
# talk over a virtio bridge many times faster than the physical pair's one
# gigabit NIC, which carries DRBD replication, the lock traffic and live
# migrations at once; CAP_MBIT=940 puts the rig's replication and lock traffic
# behind the same bottleneck.
#
# Verdict: PASS when no fio job and no probe saw an error.  For each node it
# also reports, from the node's own kernel log after this run's mark:
#   P912-ACQ-UNRECEIPTED   an acquire given up because the master had not
#                          receipted it (a debug line; armed here through
#                          dynamic debug for the run, and disarmed after)
#   P958-*                 a refused or abandoned acquire
#   P-TAUTH-LOCAL-ORPHAN-RELEASE  a durable grant to a requester that gave up
#   P-DRAINWB-STALL        a release drain stuck in its page flush
#   P240-*                 a recovery-blocked or quarantined refusal
#   P-DRBD-CAS-*           the DRBD compare-and-swap's waits and stats
#
# Usage:
#   tests/drbd_vmimage_contention.sh [PHASE_S]        (default 60)
# Env:
#   MXFS_GROUP   rig group whose two nodes are used (default g2)
#   MNT          the MXFS mount point on both nodes (default /mnt/shared)
#   NODES        "A B" instead of a rig group (e.g. the physical pair's IPs)
#   ENGINE       fio's ioengine for the load (default io_uring; libaio never
#                issues non-blocking)
#   PHASES       which phases, in order (default "probe handoff pair bulk";
#                storm runs only when named)
#   CAP_MBIT     shape the link between the two nodes to this many Mbit/s
#
# Evidence: tests/evidence/drbd_vmimage/<UTC stamp>/ — each node's fio json and
# probe log, and the kernel-log counts.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
. "$REPO/tools/mxfs_lab.sh"
SSH="$REPO/tools/mxfs_sshpass.sh"
PHASE_S=${1:-60}
case "$PHASE_S" in *[!0-9]*|'') echo "PHASE_S must be seconds" >&2; exit 2 ;; esac
GROUP=${MXFS_GROUP:-g2}
MNT=${MNT:-/mnt/shared}
ENGINE=${ENGINE:-io_uring}
PHASES=${PHASES:-probe handoff pair bulk}
CAP_MBIT=${CAP_MBIT:-}
case "$CAP_MBIT" in *[!0-9]*) echo "CAP_MBIT must be Mbit/s" >&2; exit 2 ;; esac
if [ -n "${NODES:-}" ]; then
    read -r -a NODE <<<"$NODES"
else
    read -r -a NODE <<<"$(lab_group "$GROUP")"
fi
[ "${#NODE[@]}" = 2 ] || { echo "need exactly two nodes, got: ${NODE[*]}"; exit 2; }
A=${NODE[0]}; B=${NODE[1]}
RUN=$(date -u +%Y%m%dT%H%M%SZ)
EVID="$REPO/tests/evidence/drbd_vmimage/$RUN"
mkdir -p "$EVID" || exit 1
DIR="$MNT/vmimage-$RUN"
# fio's own setup, the ssh round trip and the tail of a QD16 queue, twice over
STEP_SLACK=40

say() { echo "[$(date +%H:%M:%S)] $*"; }
addr() { case "$1" in *[!0-9.]*) lab_addr "$1" ;; *) echo "$1" ;; esac; }
on() {  # <node> <timeout> <command>: output on stdout, the command's rc
    timeout "$2" "$SSH" "$(addr "$1")" "$3" </dev/null 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you'
    return "${PIPESTATUS[0]}"
}

# The VM's load: fio on one image, its result as one line.
fio_cmd() {  # <image> <seconds> <json>
    cat <<EOF
fio --name=vm --filename=$1 --direct=1 --ioengine=$ENGINE --rw=randrw --rwmixread=60 \
    --bs=4k --iodepth=16 --size=4G --time_based --runtime=$2 \
    --output-format=json --output=$3 >/dev/null 2>$3.err
rc=\$?
python3 -I -c '
import json, sys
try:
    j = json.load(open(sys.argv[1]))["jobs"][0]
except Exception as e:
    print("FIO_RESULT rc=%s parse_error=%s err=%s" % (sys.argv[2], e, open(sys.argv[1] + ".err").read().strip()[-200:]))
    sys.exit(0)
r, w = j["read"], j["write"]
print("FIO_RESULT rc=%s error=%d read_ios=%d write_ios=%d read_mib=%.1f write_mib=%.1f lat_max_ms=%.0f err=%s" % (
    sys.argv[2], j.get("error", 0), r["total_ios"], w["total_ios"], r["io_bytes"] / 1048576.0,
    w["io_bytes"] / 1048576.0, max(r["lat_ns"]["max"], w["lat_ns"]["max"]) / 1e6,
    open(sys.argv[1] + ".err").read().strip().replace("\n", " | ")[-200:] or "-"))
' $3 \$rc
EOF
}

# An image build beside the VMs: sequential 1 MiB writes through the page
# cache with an fsync every 256 MiB, wrapping over a file of <size> (8 GiB for
# one build; the storm's two builds take 4 GiB each, so two builds and two
# images fit the rig's 20 GiB device).
bulk_cmd() {  # <file> <seconds> <json> <size>
    cat <<EOF
fio --name=build --filename=$1 --ioengine=psync --rw=write --bs=1M --size=$4 \
    --fsync=256 --time_based --runtime=$2 --output-format=json --output=$3 >/dev/null 2>$3.err
rc=\$?
python3 -I -c '
import json, sys
try:
    j = json.load(open(sys.argv[1]))["jobs"][0]
except Exception as e:
    print("FIO_RESULT rc=%s parse_error=%s" % (sys.argv[2], e)); sys.exit(0)
w = j["write"]
print("FIO_RESULT rc=%s error=%d read_ios=0 write_ios=%d write_mib=%.1f mib_s=%.1f lat_max_ms=%.0f err=%s" % (
    sys.argv[2], j.get("error", 0), w["total_ios"], w["io_bytes"] / 1048576.0,
    w["bw_bytes"] / 1048576.0, w["lat_ns"]["max"] / 1e6,
    open(sys.argv[1] + ".err").read().strip().replace("\n", " | ")[-200:] or "-"))
' $3 \$rc
EOF
}

# The other node's look at the image: open O_DIRECT, read the first 64 KiB,
# fstat, close, every 2 s; one line per error, then a summary line.
probe_cmd() {  # <image> <seconds>
    cat <<EOF
python3 -I - $1 $2 <<'PY'
import errno, mmap, os, sys, time
path, secs = sys.argv[1], float(sys.argv[2])
buf = mmap.mmap(-1, 65536)
end = time.monotonic() + secs
n = bad = 0
worst = 0.0
while time.monotonic() < end:
    t0 = time.monotonic()
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECT)
        try:
            os.preadv(fd, [buf], 0)
            os.fstat(fd)
        finally:
            os.close(fd)
    except OSError as e:
        bad += 1
        print("PROBE_ERR t=%.1f errno=%s %s" % (time.monotonic() - (end - secs), errno.errorcode.get(e.errno, e.errno), e.strerror), flush=True)
    dt = time.monotonic() - t0
    worst = max(worst, dt)
    n += 1
    time.sleep(max(0.0, 2.0 - dt))
print("PROBE_RESULT probes=%d errors=%d worst_ms=%.0f" % (n, bad, worst * 1000))
PY
EOF
}

TAGS='P912-ACQ-UNRECEIPTED|P958-[A-Z-]+|P-TAUTH-LOCAL-ORPHAN-RELEASE|P-DRAINWB-STALL|P240-[A-Z-]+|P-DRBD-CAS-[A-Z-]+|P-ACQ-LADDER-END|P-RBLK-[A-Z-]+|P-LKWAIT-LIVE|P36-RETRY|P-LKTIMEOUT-[A-Z]+|P960-[A-Z-]+|lock request failed|unrecoverable'
DYNDBG='for f in P912-ACQ-UNRECEIPTED P-DRBD-CAS-STATS; do echo "module mxfs format \"$f\" FLAG" > /proc/dynamic_debug/control; done'

say "nodes A=$A B=$B, mount $MNT, $PHASE_S s per phase, evidence $EVID"
for n in "$A" "$B"; do
    out=$(on "$n" 30 "awk '\$2 == \"$MNT\" {print \$3}' /proc/mounts; cat /sys/module/mxfs/srcversion; command -v fio >/dev/null && echo fio-ok")
    grep -qx mxfs <<<"$out" || { say "FAIL: $n has no MXFS mount at $MNT"; exit 1; }
    grep -qx fio-ok <<<"$out" || { say "FAIL: $n has no fio"; exit 1; }
    say "  $n: mxfs $(sed -n 2p <<<"$out")"
    on "$n" 20 "${DYNDBG//FLAG/+p}; echo '<5>mxfs-test: vmimage-contention $RUN start' > /dev/kmsg" >/dev/null
done
# The link shaping: one htb class, rate = ceil = CAP_MBIT, for every packet to
# the peer's address; everything else goes to a default class far above any
# rate the rig reaches.  fq_codel under the cap keeps the small lock messages
# from queueing behind one bulk flow, as fq_codel does on the PVE hosts' NICs.
cap_cmd() {  # <peer-ip> <mbit>
    cat <<EOF
dev=\$(ip route get $1 | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -1)
[ -n "\$dev" ] || { echo "CAP_FAIL no route to $1"; exit 1; }
tc qdisc del dev \$dev root 2>/dev/null
tc qdisc add dev \$dev root handle 1: htb default 20 &&
tc class add dev \$dev parent 1: classid 1:10 htb rate ${2}mbit ceil ${2}mbit quantum 60000 &&
tc class add dev \$dev parent 1: classid 1:20 htb rate 10gbit ceil 10gbit quantum 200000 &&
tc qdisc add dev \$dev parent 1:10 fq_codel &&
tc filter add dev \$dev parent 1: protocol ip prio 1 u32 match ip dst $1/32 flowid 1:10 &&
echo "CAP_ON dev=\$dev peer=$1 mbit=$2" || { tc qdisc del dev \$dev root 2>/dev/null; echo "CAP_FAIL dev=\$dev"; exit 1; }
EOF
}
uncap_cmd() {  # <peer-ip>
    cat <<EOF
dev=\$(ip route get $1 | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -1)
tc -s class show dev \$dev 2>/dev/null | grep -A2 'class htb 1:10 ' | tr -s ' \n' ' ' | sed 's/^/CAP_STATS /'; echo
tc qdisc del dev \$dev root 2>/dev/null
tc qdisc show dev \$dev | grep -q htb && echo "UNCAP_FAIL dev=\$dev" || echo "UNCAP_OK dev=\$dev"
EOF
}
uncap_all() {
    [ -n "$CAP_MBIT" ] || return 0
    on "$A" 30 "$(uncap_cmd "$(addr "$B")")" >> "$EVID/cap.$A"
    on "$B" 30 "$(uncap_cmd "$(addr "$A")")" >> "$EVID/cap.$B"
    say "  link shaping removed: $A $(grep -aoE 'UNCAP_[A-Z]+' "$EVID/cap.$A" | tail -1), $B $(grep -aoE 'UNCAP_[A-Z]+' "$EVID/cap.$B" | tail -1)"
}
if [ -n "$CAP_MBIT" ]; then
    trap uncap_all EXIT
    on "$A" 30 "$(cap_cmd "$(addr "$B")" "$CAP_MBIT")" > "$EVID/cap.$A"
    on "$B" 30 "$(cap_cmd "$(addr "$A")" "$CAP_MBIT")" > "$EVID/cap.$B"
    grep -aq '^CAP_ON' "$EVID/cap.$A" && grep -aq '^CAP_ON' "$EVID/cap.$B" \
        || { say "FAIL: link shaping: $(cat "$EVID/cap.$A" "$EVID/cap.$B" | tr '\n' ' ')"; exit 1; }
    say "link between $A and $B shaped to $CAP_MBIT Mbit/s ($(grep -a '^CAP_ON' "$EVID/cap.$A" | cut -c8-))"
fi

on "$A" 30 "mkdir -p $DIR && truncate -s 4G $DIR/a.raw $DIR/b.raw && ls -ls $DIR" > "$EVID/setup" \
    || { say "FAIL: setup on $A: $(tail -1 "$EVID/setup")"; exit 1; }

run_phase() {  # <name> <loader> <loaded-image> <prober> <probed-image> [<loader2> <image2> <prober2> <probed2>]
    local name=$1 pids=() i=0
    say "phase $name"
    shift
    local bsize=8G
    [ "$(wc -w <<<"${BULK_ON:-}")" -gt 1 ] && bsize=4G
    for b in ${BULK_ON:-}; do
        ( on "$b" $((PHASE_S + STEP_SLACK)) "$(bulk_cmd "$DIR/bulk-$b.raw" "$PHASE_S" "/root/vmimage-$RUN-$name-bulk.json" "$bsize")" \
              > "$EVID/$name.fio.$b.bulk" ) &
        pids+=($!)
    done
    while [ $# -ge 4 ]; do
        ( on "$1" $((PHASE_S + STEP_SLACK)) "$(fio_cmd "$2" "$PHASE_S" "/root/vmimage-$RUN-$name-$i.json")" \
              > "$EVID/$name.fio.$1.$i" ) &
        pids+=($!)
        ( on "$3" $((PHASE_S + STEP_SLACK)) "$(probe_cmd "$4" "$PHASE_S")" > "$EVID/$name.probe.$3.$i" ) &
        pids+=($!)
        i=$((i + 1))
        shift 4
    done
    wait "${pids[@]}"
    for f in "$EVID/$name".fio.* "$EVID/$name".probe.*; do
        say "  $(basename "$f"): $(grep -aE '^(FIO|PROBE)_RESULT' "$f" | tail -1 | cut -c1-200)"
        grep -a '^PROBE_ERR' "$f" | head -3 | sed 's/^/      /'
    done
}

for p in $PHASES; do
    case "$p" in
        probe)   run_phase probe   "$A" "$DIR/a.raw" "$B" "$DIR/a.raw" ;;
        handoff) run_phase handoff "$B" "$DIR/a.raw" "$A" "$DIR/a.raw" ;;
        pair)    run_phase pair    "$A" "$DIR/b.raw" "$B" "$DIR/b.raw"   "$B" "$DIR/a.raw" "$A" "$DIR/a.raw" ;;
        bulk)    BULK_ON=$A run_phase bulk "$A" "$DIR/b.raw" "$B" "$DIR/b.raw"   "$B" "$DIR/a.raw" "$A" "$DIR/a.raw" ;;
        storm)   BULK_ON="$A $B" run_phase storm "$A" "$DIR/b.raw" "$B" "$DIR/b.raw"   "$B" "$DIR/a.raw" "$A" "$DIR/a.raw" ;;
        *)       say "unknown phase $p"; exit 2 ;;
    esac
done

say "kernel log after the mark"
for n in "$A" "$B"; do
    # journald files "mxfs-test:" as the line's identifier, so the mark is
    # matched without it
    on "$n" 30 "journalctl -k --no-pager -o cat | sed -n '/vmimage-contention $RUN start/,\$p' | grep -oE '$TAGS' | sort | uniq -c | sort -rn" > "$EVID/klog.$n"
    on "$n" 20 "${DYNDBG//FLAG/-p}" >/dev/null
    say "  $n: $(tr -s ' \n' ' ' < "$EVID/klog.$n")"
done
on "$A" 60 "rm -rf $DIR" >/dev/null

errs=0
for f in "$EVID"/*.fio.*; do
    grep -aq '^FIO_RESULT rc=0 error=0 ' "$f" || errs=$((errs + 1))
done
for f in "$EVID"/*.probe.*; do
    grep -aq '^PROBE_RESULT .* errors=0 ' "$f" || errs=$((errs + 1))
done
if [ "$errs" = 0 ]; then
    say "PASS: no I/O error in any load or probe (evidence $EVID)"
    exit 0
fi
say "FAIL: $errs load(s)/probe(s) saw an error or gave no result (evidence $EVID)"
exit 1
