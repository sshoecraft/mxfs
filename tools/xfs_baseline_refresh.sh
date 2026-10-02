#!/bin/bash
# xfs_baseline_refresh.sh — re-measure the native-XFS fio yardsticks that
# fio_perf_vs_xfs grades every MXFS board against, on one rig node and a pool
# LUN, one per release configuration.  Run it whenever the rig's VM shape
# (vCPUs, memory) or the LUN backing changes: the yardstick is only a ceiling
# for runs made on the same shape.
#
# Usage: tools/xfs_baseline_refresh.sh <evidence-tag> [node]   (node default test1)
#   EXPECT_CPUS (default 2)  the guest must report this many CPUs, or nothing runs
#   RUNS (default 5)         fio_perf runs per configuration; each field of the
#                            yardstick is the median of them
#
# One run is not a yardstick.  The 2-vCPU capture of 0.90.39 ran native XFS
# twice on the same node, LUN and workload, once per configuration, and read
# seqW 1673 and 968 MiB/s: the device's cache-absorption regime decides a single
# sequential-write sample.  Graded against the 1673, 4/net/mesh/direct's 1150
# MiB/s failed at 68%.  The runs of every capture are kept in the evidence
# directory next to the log.
#
# The previous yardsticks are kept as .xfs_fio_baseline.<cfg>.scst-fio.json.backup.
# Each run is itself the best of fio_perf's FIO_PASSES passes (see
# tests/suite/fio_perf.sh), so the yardstick is the median of RUNS bests.
# Budget: node boot ~60 s, prep ~1 s, each fio_perf ~30 s (manifest 120 s).
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO" || exit 1
TAG="${1:?usage: xfs_baseline_refresh.sh <evidence-tag> [node]}"
NODE="${2:-test1}"
EXPECT_CPUS="${EXPECT_CPUS:-2}"
RUNS="${RUNS:-5}"
[[ "$RUNS" =~ ^[1-9][0-9]*$ ]] || { echo "RUNS must be a positive integer (got '$RUNS')"; exit 2; }
CONFIGS="net-mesh-direct disk-caw-direct"
E="tests/evidence/xfs_baseline_$TAG.log"
RD="tests/evidence/xfs_baseline_${TAG}_runs"
mkdir -p "$RD"
SSH=tools/mxfs_sshpass.sh

scripts/lab_power.sh up "$NODE" >>"$E" 2>&1 || { echo "ABORT: $NODE did not come up (see $E)"; exit 3; }
cpus=$(timeout 20 "$SSH" "$NODE" nproc 2>/dev/null | tr -d '\r' | tail -1)
[ "$cpus" = "$EXPECT_CPUS" ] || { echo "ABORT: $NODE reports nproc=$cpus, want $EXPECT_CPUS"; exit 3; }
echo "=== $NODE nproc=$cpus" >>"$E"

for s in $CONFIGS; do
    [ -e ".xfs_fio_baseline.$s.scst-fio.json" ] &&
        mv ".xfs_fio_baseline.$s.scst-fio.json" ".xfs_fio_baseline.$s.scst-fio.json.backup"
done
t0=$(date +%s)
{
    line=$(tools/lun_pool.sh alloc --owner $$ --what "yardstick capture $TAG" --size 20G "$NODE")
    echo "$line"
    dev=$(sed -n 's/.* dev=\([^ ]*\).*/\1/p' <<<"$line")
    MXFS_DEV=$dev ./run.sh 1/xfs prep_cluster; echo "=== rc=$? prep 1/xfs"
    for s in $CONFIGS; do
        for ((i = 1; i <= RUNS; i++)); do
            MXFS_DEV=$dev MXFS_TEST_ENV="XFS_BASELINE=/src/mxfs/$RD/$s.run$i.json" \
                ./run.sh 1/xfs fio_perf
            echo "=== rc=$? fio_perf 1/xfs -> $s run $i/$RUNS"
        done
    done
} >>"$E" 2>&1
# Each run's file is written by the run as root; the median goes into the
# yardstick the boards read.
for s in $CONFIGS; do
    for ((i = 1; i <= RUNS; i++)); do
        sudo -n cat "$RD/$s.run$i.json" 2>/dev/null || cat "$RD/$s.run$i.json" 2>/dev/null
        echo
    done | python3 -c '
import json, statistics, sys
runs = [json.loads(l) for l in sys.stdin if l.strip()]
want = int(sys.argv[1])
if len(runs) != want:
    sys.exit("%s: %d of %d runs wrote a baseline" % (sys.argv[2], len(runs), want))
out = {}
for k, f in (("seq_write_1m", "bw_mib"), ("seq_read_1m", "bw_mib"),
             ("rand_write_4k", "iops"), ("rand_read_4k", "iops")):
    out[k] = {f: int(statistics.median(r[k][f] for r in runs))}
    print("%s %s %s runs=%s median=%d" % (sys.argv[2], k, f,
          ",".join(str(r[k][f]) for r in runs), out[k][f]), file=sys.stderr)
out["size"] = runs[0].get("size", "")
out["runs"] = want
json.dump(out, open(sys.argv[3], "w"), separators=(",", ":"))
' "$RUNS" "$s" ".xfs_fio_baseline.$s.scst-fio.json" 2>&1 | tee -a "$E"
done
echo "wall=$(( $(date +%s) - t0 ))s nproc=$cpus"
grep -aE '^=== rc|POOL_LUN|  (PASS|FAIL|TIMEOUT)' "$E" | cut -c1-160
rc=0
for s in $CONFIGS; do
    new=$(cat ".xfs_fio_baseline.$s.scst-fio.json" 2>/dev/null || sudo -n cat ".xfs_fio_baseline.$s.scst-fio.json" 2>/dev/null)
    [ -n "$new" ] || rc=1
    echo "$s new: ${new:-MISSING}"
    echo "$s old: $(cat ".xfs_fio_baseline.$s.scst-fio.json.backup" 2>/dev/null || sudo -n cat ".xfs_fio_baseline.$s.scst-fio.json.backup" 2>/dev/null)"
done
exit $rc
