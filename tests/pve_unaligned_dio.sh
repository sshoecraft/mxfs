#!/bin/bash
# pve_unaligned_dio.sh — what a trickle of sub-block direct writes costs the
# aligned direct writes to the same file, as a VM disk image sees it.
#
# A guest whose disk has 512-byte sectors (the virtio default) writes its own
# filesystem's log and metadata in 512-byte multiples, and QEMU with
# cache=none passes them to the image file as O_DIRECT writes at 512-byte
# alignment unless the host filesystem tells it a larger one.  On XFS (so on
# MXFS) a direct write that does not cover whole filesystem blocks and lands on
# unwritten space takes the file's IO lock exclusively and waits for every
# direct write in flight on the file first (xfs_file_dio_write_unaligned,
# IOMAP_DIO_FORCE_WAIT); while it waits and writes, every other writer waits.
#
# Two arms on one host, each on a fresh sparse file in DIR, LOAD_S seconds:
#   aligned  one writer: sequential 256 KiB direct writes at queue depth 8 into
#            the file's holes (every write allocates), as an installing guest
#            fills its disk
#   mixed    the same writer, plus 512-byte direct writes at RATE per second
#            into other holes of the same file, one at a time
# Reports each arm's aligned throughput and latency, and the small writes'.
# Run it on MXFS and on a local filesystem of the same host to compare.
#
# Usage: tests/pve_unaligned_dio.sh <host> [dir]   (dir default /mnt/shared/pvedio)
# Env:   LOAD_S (default 30), RATE (default 2), EVID (default
#        tests/evidence/pve_unaligned_dio/<UTC stamp>)
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
HOST=${1:?usage: tests/pve_unaligned_dio.sh <host> [dir]}
DIR=${2:-/mnt/shared/pvedio}
LOAD_S=${LOAD_S:-30}
RATE=${RATE:-2}
EVID=${EVID:-$REPO/tests/evidence/pve_unaligned_dio/$(date -u +%Y%m%dT%H%M%SZ)}
mkdir -p "$EVID" || exit 1
say() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$EVID/summary.txt"; }
on() {  # <cmd> [timeout]
    timeout "${2:-60}" "$SSHP" "$HOST" "$1" </dev/null 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you|^$'
    return "${PIPESTATUS[0]}"
}

say "$HOST: $(on "echo \"\$(hostname) fs=\$(stat -f -c %T $DIR 2>/dev/null || stat -f -c %T \$(dirname $DIR)) mxfs=\$(cat /sys/module/mxfs/srcversion 2>/dev/null)\"" 20), dir $DIR, ${LOAD_S}s per arm, small writes at ${RATE}/s"
for arm in aligned mixed; do
    small=""
    [ "$arm" = mixed ] && small="--name=small --offset=4g --size=4g --rw=randwrite --bs=512 --iodepth=1 --rate_iops=$RATE"
    # a fresh sparse 8 GiB file per arm: the aligned writer fills [0, 4g), the
    # small writes land in [4g, 8g)
    on "command -v fio >/dev/null || { echo NO_FIO; exit 1; }
        mkdir -p $DIR && f=$DIR/dio.\$(hostname) && rm -f \$f && truncate -s 8G \$f || exit 1
        fio --filename=\$f --direct=1 --ioengine=io_uring --time_based --runtime=$LOAD_S --output-format=json \
            --name=aligned --offset=0 --size=4g --rw=write --bs=256k --iodepth=8 $small > /root/pve_unaligned_dio.json 2>/root/pve_unaligned_dio.err
        echo FIO_RC=\$?; rm -f \$f" $(( LOAD_S + 90 )) > "$EVID/$arm.run"
    on "cat /root/pve_unaligned_dio.json" 30 > "$EVID/$arm.json"
    grep -q 'FIO_RC=0' "$EVID/$arm.run" || { say "ABORT: $arm: $(tr '\n' ' ' < "$EVID/$arm.run") $(on 'tail -3 /root/pve_unaligned_dio.err' 20 | tr '\n' ' ')"; exit 1; }
    python3 -I - "$EVID/$arm.json" "$arm" <<'PY' | tee -a "$EVID/summary.txt"
import json, sys
j = json.load(open(sys.argv[1]))
for job in j["jobs"]:
    w = job["write"]
    c = w.get("clat_ns", {})
    print(f"  {sys.argv[2]:7s} {job['jobname']:7s} err={job['error']} writes={w['total_ios']:6d} "
          f"MiB/s={w['bw_bytes'] / 2**20:7.1f} lat_mean_ms={c.get('mean', 0) / 1e6:8.1f} "
          f"lat_max_ms={c.get('max', 0) / 1e6:8.1f}")
PY
done
