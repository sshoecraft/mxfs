#!/bin/bash
# pve_small_write_stall.sh — does a trickle of small synchronous writes make
# the pair's spare SSDs stall on cache flushes?
#
# Under MXFS the spare-disk DRBD device spent 60-85% of a guest-write run in
# gaps of a second or more with nothing issued to the disk, nearly all right
# after a cache flush; under XFS on the same device 8-31%.  Per flush, MXFS's
# flushes stalled ~20 times as often (tests/pve_bio_census.py).  What MXFS adds
# to the stream is about one 512-byte FUA or sync write a second per disk (its
# coordination registers), where every XFS write is 4 KiB or more, and the
# disks (KINGSTON SVP100S, no native FUA) report 512-byte physical sectors.
#
# This runs, on the raw DRBD device with no filesystem (as a guest's disk is
# a logical volume on DRBD), the installing-guest pattern of
# tests/pve_vmio_census.sh alone, then with one O_SYNC (FUA) write a second
# of SMALL_BS bytes beside it, for each SMALL_BS given, with
# tests/pve_bio_census.sh on both hosts each time.  If the stalls follow the
# 512-byte writes and not the 4 KiB ones, the fault is the write size.
#
# DESTROYS whatever is on the device: run it only on the spare-disk resource,
# with its filesystem unmounted on both hosts.
#
# Usage: tests/pve_small_write_stall.sh <outdir> [small_bs ...]   (default: 512 4096)
# Env:   PVE_PAIR ("192.168.1.80 192.168.1.81": the writer runs on the first,
#        which is made Primary; the second stays as it is)  RES (mxfssdb)
#        MINOR (2)  DISK (sdb)  SECS (60)  SMALL_IOPS (1)
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
OUT=${1:?outdir}; shift
SIZES=${*:-512 4096}
read -r -a PAIR <<<"${PVE_PAIR:-192.168.1.80 192.168.1.81}"
RES=${RES:-mxfssdb}; MINOR=${MINOR:-2}; DISK=${DISK:-sdb}; SECS=${SECS:-60}; SMALL_IOPS=${SMALL_IOPS:-1}
DEV=/dev/drbd$MINOR
mkdir -p "$OUT" || exit 1
say() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT/stall.log"; }
on() { timeout "${3:-60}" "$SSHP" "$1" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^$'; return "${PIPESTATUS[0]}"; }
for h in "${PAIR[@]}"; do
    on "$h" "grep -q '^$DEV ' /proc/mounts && { echo \"REFUSE: $DEV is mounted on \$(hostname)\"; exit 1; }; echo ok" 30 >/dev/null \
        || { say "REFUSE: $DEV is mounted on $h"; exit 1; }
done
on "${PAIR[0]}" "drbdadm primary $RES; echo \"ro=\$(drbdadm role $RES) ds=\$(drbdadm dstate $RES)\"" 60 | tee -a "$OUT/stall.log"
VMIO="--name=vmio --filename=$DEV --offset=0 --size=3g --rw=randwrite --bssplit=4k/35:64k/25:128k/20:256k/20 --direct=1 --ioengine=io_uring --iodepth=4 --fdatasync=3"
run() {     # <name> [small_bs]
    local name=$1 small=""
    [ -n "${2:-}" ] && small="--name=small --filename=$DEV --offset=8g --size=1m --rw=randwrite --bs=$2 --direct=1 --sync=1 --ioengine=psync --rate_iops=$SMALL_IOPS"
    say "$name: vmio${2:+ + one ${2}-byte O_SYNC write every $(( 1000 / SMALL_IOPS )) ms}, ${SECS}s"
    mkdir -p "$OUT/$name"
    for h in "${PAIR[@]}"; do
        "$REPO/tests/pve_bio_census.sh" "$h" "$SECS" "$OUT/$name" "$MINOR" "$DISK" > "$OUT/$name/census.$h.out" 2>&1 &
    done
    sleep 2
    on "${PAIR[0]}" "fio --time_based --runtime=$(( SECS - 6 )) --output-format=json $VMIO $small" $(( SECS + 60 )) > "$OUT/$name/fio.json"
    wait
    python3 -I - "$OUT/$name/fio.json" <<'PY' | tee -a "$OUT/stall.log"
import json, sys
t = open(sys.argv[1]).read()
for j in json.loads(t[t.index("{"):])["jobs"]:
    w = j["write"]; c = w["clat_ns"].get("percentile", {}); s = j["sync"]["lat_ns"]; sp = s.get("percentile", {})
    ms = lambda d, k: d.get(k, 0) / 1e6
    print(f"  {j['jobname']:5s} writes={w['total_ios']} MiB/s={w['bw_bytes'] / 2**20:.1f} write_ms p50={ms(c, '50.000000'):.1f} "
          f"p99={ms(c, '99.000000'):.1f} p99.9={ms(c, '99.900000'):.1f} max={w['clat_ns']['max'] / 1e6:.1f} "
          f"| syncs={s.get('N', 0)} sync_ms p50={ms(sp, '50.000000'):.1f} p99={ms(sp, '99.000000'):.1f}")
PY
    for h in "${PAIR[@]}"; do
        grep -h '^gaps of' "$OUT/$name/$h.census" 2>/dev/null | sed "s/^/  $h: /" | tee -a "$OUT/stall.log"
    done
}
run base
for b in $SIZES; do run "small$b" "$b"; done
run base2
on "${PAIR[0]}" "drbdadm secondary $RES; echo \"ro=\$(drbdadm role $RES)\"" 60 | tee -a "$OUT/stall.log"
say "done"
