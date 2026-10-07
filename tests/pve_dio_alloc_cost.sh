#!/bin/bash
# pve_dio_alloc_cost.sh — what a direct write costs by what it writes into:
# a hole, an unwritten (fallocated) extent, or blocks already written.  A VM
# image on a Proxmox directory storage is a sparse raw file, so an installing
# guest's writes mostly fill holes; the same writes to a written file allocate
# nothing.  The difference between the arms is what allocation costs, separated
# from what the device costs.
#
# Three arms on one host, each a fresh file in DIR and one writer for LOAD_S
# seconds: sequential 256 KiB O_DIRECT writes at queue depth 8 (io_uring)
# across the file's first 4 GiB:
#   hole       the file is sparse (truncate)
#   unwritten  the file is fallocated (fallocate -l), so its extents exist
#              and every write converts one from unwritten to written
#   overwrite  the file was written in full first (FILL_MB, default 1024, with
#              the writer confined to that range), so nothing is allocated
# Reports each arm's throughput and latency.  Run it on MXFS and on a local
# filesystem of the same host to compare.
#
# Usage: tests/pve_dio_alloc_cost.sh <host> [dir]   (dir default /mnt/shared/pvedio)
# Env:   LOAD_S (default 30), FILL_MB (default 1024), ARMS (default
#        "hole unwritten overwrite"), EVID (default
#        tests/evidence/pve_dio_alloc_cost/<UTC stamp>)
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
HOST=${1:?usage: tests/pve_dio_alloc_cost.sh <host> [dir]}
DIR=${2:-/mnt/shared/pvedio}
LOAD_S=${LOAD_S:-30}
FILL_MB=${FILL_MB:-1024}
read -r -a ARMS <<<"${ARMS:-hole unwritten overwrite}"
EVID=${EVID:-$REPO/tests/evidence/pve_dio_alloc_cost/$(date -u +%Y%m%dT%H%M%SZ)}
mkdir -p "$EVID" || exit 1
say() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$EVID/summary.txt"; }
on() {  # <cmd> [timeout]
    timeout "${2:-60}" "$SSHP" "$HOST" "$1" </dev/null 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you|^$'
    return "${PIPESTATUS[0]}"
}

say "$HOST: $(on "echo \"\$(hostname) fs=\$(stat -f -c %T \$(dirname $DIR)) mxfs=\$(cat /sys/module/mxfs/srcversion 2>/dev/null)\"" 20), dir $DIR, ${LOAD_S}s per arm"
for arm in "${ARMS[@]}"; do
    size=4g
    case "$arm" in
        hole)      prep="truncate -s 4G \$f" ;;
        unwritten) prep="fallocate -l 4G \$f" ;;
        # written in full beforehand with large buffered writes and an fsync,
        # so the arm's writes find every block written and allocate nothing
        overwrite) prep="dd if=/dev/zero of=\$f bs=4M count=$(( FILL_MB / 4 )) conv=fsync status=none"; size=${FILL_MB}m ;;
        *) say "ABORT: unknown arm $arm"; exit 2 ;;
    esac
    t0=$(date +%s)
    on "command -v fio >/dev/null || { echo NO_FIO; exit 1; }
        mkdir -p $DIR && f=$DIR/alloc.\$(hostname) && rm -f \$f && $prep || exit 1
        echo PREP_DONE
        fio --filename=\$f --direct=1 --ioengine=io_uring --time_based --runtime=$LOAD_S --output-format=json \
            --name=$arm --offset=0 --size=$size --rw=write --bs=256k --iodepth=8 > /root/pve_dio_alloc_cost.json 2>/root/pve_dio_alloc_cost.err
        echo FIO_RC=\$?; rm -f \$f" $(( LOAD_S + 300 )) > "$EVID/$arm.run"
    on "cat /root/pve_dio_alloc_cost.json" 30 > "$EVID/$arm.json"
    grep -q 'FIO_RC=0' "$EVID/$arm.run" || { say "ABORT: $arm: $(tr '\n' ' ' < "$EVID/$arm.run") $(on 'tail -3 /root/pve_dio_alloc_cost.err' 20 | tr '\n' ' ')"; exit 1; }
    python3 -I - "$EVID/$arm.json" "$arm" "$(( $(date +%s) - t0 ))" <<'PY' | tee -a "$EVID/summary.txt"
import json, sys
j = json.load(open(sys.argv[1]))
for job in j["jobs"]:
    w = job["write"]
    c = w.get("clat_ns", {})
    print(f"  {sys.argv[2]:9s} err={job['error']} writes={w['total_ios']:6d} MiB/s={w['bw_bytes'] / 2**20:7.1f} "
          f"lat_mean_ms={c.get('mean', 0) / 1e6:8.1f} lat_max_ms={c.get('max', 0) / 1e6:8.1f} (arm wall {sys.argv[3]} s with its preparation)")
PY
done
