#!/bin/bash
# pve_vmio_census.sh — one installing guest's write pattern on a mounted
# filesystem of the physical pair, with tests/pve_bio_census.sh tracing both
# hosts for exactly the timed part: what the filesystem sends to the DRBD
# device per guest write, and what each host's disk is asked to do.
#
# The writer is scripts/drbd_write_latency_probe.sh's vmio pattern: O_DIRECT
# random writes (io_uring, QD4) of 4/64/128/256 KiB in the proportion
# 35/25/20/20 with an fdatasync after every 3, into a 3 GiB file.
#
# Usage: tests/pve_vmio_census.sh <mountpoint> <sparse|prefill> <outdir>
# Env:   PVE_PAIR ("192.168.1.80 192.168.1.81": the writer runs on the first)
#        SECS (60)  MINOR (2)  DISK (sdb)
#   sparse:  the file starts empty, so writes allocate and convert, as into a
#            new raw image
#   prefill: the file is written out in full and synced first (not traced),
#            so the traced writes only overwrite written blocks
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
MNT=${1:?mountpoint}; MODE=${2:?sparse|prefill}; OUT=${3:?outdir}
read -r -a PAIR <<<"${PVE_PAIR:-192.168.1.80 192.168.1.81}"
SECS=${SECS:-60}; MINOR=${MINOR:-2}; DISK=${DISK:-sdb}
mkdir -p "$OUT" || exit 1
on() { timeout "${3:-60}" "$SSHP" "$1" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^$'; return "${PIPESTATUS[0]}"; }
F=$MNT/vmio_census/f
JOB="--rw=randwrite --bssplit=4k/35:64k/25:128k/20:256k/20 --direct=1 --ioengine=io_uring --iodepth=4 --fdatasync=3 --size=3g"
on "${PAIR[0]}" "mountpoint -q $MNT || { echo NOT_MOUNTED; exit 1; }; rm -rf $MNT/vmio_census; mkdir -p $MNT/vmio_census; echo \$(findmnt -n -o FSTYPE $MNT)" 60 | tee "$OUT/fstype" || exit 1
case "$MODE" in
    # 3 GiB through the replicated device at ~35 MB/s: ~90 s, budgeted at twice that
    prefill) on "${PAIR[0]}" "fio --name=layout --filename=$F --rw=write --bs=1m --size=3g --direct=1 --ioengine=libaio --iodepth=8 --end_fsync=1 >/dev/null 2>&1; echo LAYOUT_RC=\$?; stat -c 'size=%s blocks=%b' $F" 180 | tee "$OUT/layout" ;;
    sparse) on "${PAIR[0]}" "truncate -s 3g $F; stat -c 'size=%s blocks=%b' $F" 30 | tee "$OUT/layout" ;;
    *) echo "usage: tests/pve_vmio_census.sh <mountpoint> <sparse|prefill> <outdir>"; exit 2 ;;
esac
# PROFILE=1: tests/pve_pair_profile.sh on both hosts for the timed writes only
# (not the layout), its evidence in $OUT/profile; FNS passes through to it
PROF_PID=
if [ "${PROFILE:-0}" = 1 ]; then
    PVE_PAIR="${PAIR[*]}" EVID="$OUT/profile" SLOW_MS="${SLOW_MS:-100}" INTERVAL_S=$(( SECS + 30 )) \
        "$REPO/tests/pve_pair_profile.sh" "$SECS" > "$OUT/profile.out" 2>&1 &
    PROF_PID=$!
    for i in $(seq 1 90); do
        grep -q -E 'profiling until|ABORT' "$OUT/profile/summary.txt" 2>/dev/null && break
        sleep 2
    done
    grep -q 'profiling until' "$OUT/profile/summary.txt" 2>/dev/null \
        || { echo "the profile did not start: $(tail -2 "$OUT/profile.out" | tr '\n' ' ')"; kill "$PROF_PID" 2>/dev/null; exit 1; }
fi
for h in "${PAIR[@]}"; do
    "$REPO/tests/pve_bio_census.sh" "$h" "$SECS" "$OUT" "$MINOR" "$DISK" > "$OUT/census.$h.out" 2>&1 &
done
sleep 2
on "${PAIR[0]}" "fio --name=vmio --filename=$F $JOB --time_based --runtime=$(( SECS - 6 )) --output-format=json" $(( SECS + 60 )) > "$OUT/fio.json"
echo "fio rc=$?"
wait
python3 -I - "$OUT/fio.json" <<'PY' | tee "$OUT/fio.summary"
import json, sys
t = open(sys.argv[1]).read()
j = json.loads(t[t.index("{"):])["jobs"][0]
w, s = j["write"], j["sync"]["lat_ns"]
print(f"writes={w['total_ios']} MiB/s={w['bw_bytes'] / 2**20:.1f} write_ms mean={w['clat_ns']['mean'] / 1e6:.1f} syncs={s.get('N', 0)} sync_ms mean={s.get('mean', 0) / 1e6:.1f}")
PY
on "${PAIR[0]}" "rm -rf $MNT/vmio_census" 60
for h in "${PAIR[@]}"; do echo "===== $h"; cat "$OUT/$h.census" 2>/dev/null || cat "$OUT/census.$h.out"; done
[ -n "$PROF_PID" ] && sed -n '/: function, calls/,$p' "$OUT/profile/summary.txt"
