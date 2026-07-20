#!/bin/bash
# fio_perf — FS throughput on the mount: the 4 canonical fio workloads (from
# bench/phase0_fio_multinode.sh): seq/rand x read/write, O_DIRECT, iodepth=32.
# Reports bw/iops. Agnostic ($1 = mount point).
#
# coord=barrier, any N. At N=1 this is exactly the old single-node behavior.
# At N>1, every node runs the SAME 4 workloads concurrently into its OWN
# private file (avoids cross-node contention on one file), publishes its own
# numbers via coord_put, and rank 1 SUMS them into an aggregate bandwidth/iops
# figure -- that aggregate (not any single node's number) is what gets
# recorded to bench.json and what fio_perf_vs_xfs.sh compares against the
# single-node xfs baseline.
#
# When run under the native-XFS condition (run.sh DLM=xfs, N=1 only;
# MXFS_EXPECT_FSTYPE=xfs), this script ALSO refreshes the single-node XFS
# baseline at $REPO/.xfs_fio_baseline.json — this run's own numbers ARE the
# reference. The pass/fail COMPARISON of a normal (mxfs) run against that
# baseline is a separate test: see fio_perf_vs_xfs.sh (reads this test's own
# bench.json entry, no duplicate fio workload run).

SUITE_TEST_NAME=fio_perf
MNT="${1:-/mnt/shared}"; NODES="${MXFS_NODES:-1}"
# 2026-07-18 (ccloop 72513a13 sess2) budget-bar reset: per-node volume scales
# INVERSELY with N so the AGGREGATE pushed through the one shared LUN is
# N-independent (~16GB across the 4 workloads x 2 passes).  The old flat
# 256m/node grew the wall linearly with N (32 nodes = 64GB = the 486s
# "healthy" wall; a bandwidth test needs steady-state seconds, not minutes
# of laydown).  Floor 64m keeps rand-4k statistically meaningful (16k IOs);
# FIO_SIZE env still overrides.
if [ -n "${FIO_SIZE:-}" ]; then
    SIZE="$FIO_SIZE"
else
    SZ_MB=$(( 2048 / NODES ))
    [ "$SZ_MB" -lt 64 ] && SZ_MB=64
    [ "$SZ_MB" -gt 1024 ] && SZ_MB=1024
    SIZE="${SZ_MB}m"
fi
# 2026-07-19 (ccloop 72513a13 sess9): rand workloads get their OWN volume,
# 128/N MB (floor 8m), instead of riding SIZE.  The 2048/N seq formula keeps
# the AGGREGATE at ~2GB/workload, which is bandwidth-bound fine (~3s/pass on
# every rig) but IOPS-bound catastrophic on transports whose 4k write path
# runs ~1100 aggregate iops (tcp rig): 2GB of 4k = 524288 IOs = ~470s/pass
# x2 passes — the recorded 813-1024s tcp walls vs the 120s manifest budget,
# with rand_write_4k alone >90% of the wall.  Steady-state iops is volume-
# independent past ~30s of IO (same physics as raw_fio_ceiling.sh's rand
# legs), so the smaller volume changes NOTHING about what the number means —
# 128MB aggregate at ~1100 iops ≈ 30s/pass, the whole 4-workload test fits
# its budget on iops-bound transports too.  FIO_RAND_SIZE env overrides.
if [ -n "${FIO_RAND_SIZE:-}" ]; then
    RSIZE="$FIO_RAND_SIZE"
else
    RSZ_MB=$(( 128 / NODES ))
    # sess10: floor 4 (was 8) — at N=32 the 8m floor doubled the designed
    # 128MB aggregate (256MB ≈ 60s/pass at the ~1200-iops device ceiling =
    # the 127-130s walls vs the 120s budget).  4m/node keeps the aggregate
    # at the design constant for every N ≤ 32; per-node steady-state is
    # still ~30s of continuous 4k IO (volume-independent iops physics).
    [ "$RSZ_MB" -lt 4 ] && RSZ_MB=4
    RSIZE="${RSZ_MB}m"
fi
FSTYPE="${MXFS_EXPECT_FSTYPE:-mxfs}"
BASE="${XFS_BASELINE:-/src/mxfs/.xfs_fio_baseline.json}"
HERE="$(dirname "$(readlink -f "$0")")"
source "$HERE/lib.sh"   # coord_barrier/coord_put/coord_get + RANK (own emit() kept below)
R="$RANK"; T="$NODES"

emit(){ echo "RESULT: $1 | test=$SUITE_TEST_NAME | nodes=$NODES | measured=$2 | reason=${3:-}"; }
command -v fio >/dev/null 2>&1 || { emit FAIL setup "fio not installed"; exit 1; }

W="$MNT/.suite_fio_perf.node${R}.$(hostname).$$"
rm -rf "$W" 2>/dev/null; mkdir -p "$W" || { emit FAIL setup "cannot mkdir $W"; exit 1; }
trap 'rm -rf "$W" /tmp/fio_perf.$$.* 2>/dev/null' EXIT
[ "$T" -gt 1 ] && coord_barrier "fio_perf_ready" >/dev/null

# run <name> <rw> <bs> -> "bw_mib iops"  (read+write summed; one side is 0)
#
# Runs the job TWICE against the SAME persistent file and reports only the
# SECOND pass. Sess 2026-07-14 finding: a first write to a never-before-
# written (unwritten) extent pays a real, large, filesystem-dependent
# conversion penalty completely separate from steady-state throughput --
# measured 2.85x on stock XFS vs only 1.45x on mxfs for the SAME workload.
# Since every prior single-shot capture was (unknowingly) measuring
# first-touch performance on both sides, comparisons were dominated by that
# mismatched penalty rather than real steady-state throughput. Discarding the
# first pass isolates steady-state performance, which is what actually
# matters for RULE 0 budgets and the vs-xfs comparison.
run(){
    local n="$1" rw="$2" bs="$3" j="/tmp/fio_perf.$$.$1.json" pass
    for pass in 1 2; do
        sync; echo 3 > /proc/sys/vm/drop_caches 2>/dev/null
        fio --name="$n" --filename="$W/$n.dat" --rw="$rw" --bs="$bs" --size="$SIZE" \
            --ioengine=libaio --direct=1 --iodepth=32 --output-format=json >"$j" 2>/dev/null
    done
    python3 - "$j" <<'PY'
import json,sys
try:
    j=json.load(open(sys.argv[1])); job=j['jobs'][0]
    bw=job['read']['bw_bytes']+job['write']['bw_bytes']
    iops=job['read']['iops']+job['write']['iops']
    print(int(bw/1048576), int(round(iops)))
except Exception:
    print("0 0")
PY
}

# sess8 (ccloop 72513a13): barrier between WORKLOADS at N>1.  With only the
# single ready-barrier, nodes drift across phases (double-pass + drop_caches
# skew) so one node's seq_write window overlaps another's rand_read storm —
# each node then measures a cross-contaminated number and the summed cluster
# aggregate craters (4/cawd measured seqW=816 vs 2078 when manually aligned;
# 42% false-FAIL against the vs-xfs 70% floor).  Aligning phases makes the
# aggregate mean what the baseline means: one workload at a time.
read sw_bw sw_io <<<"$(run seq_write_1m  write     1M)"
[ "$T" -gt 1 ] && coord_barrier "fio_ph_sw" >/dev/null
read sr_bw sr_io <<<"$(run seq_read_1m   read      1M)"
[ "$T" -gt 1 ] && coord_barrier "fio_ph_sr" >/dev/null
SIZE_SEQ="$SIZE"; SIZE="$RSIZE"
read rw_bw rw_io <<<"$(run rand_write_4k randwrite 4k)"
[ "$T" -gt 1 ] && coord_barrier "fio_ph_rw" >/dev/null
read rr_bw rr_io <<<"$(run rand_read_4k  randread  4k)"
SIZE="$SIZE_SEQ"

measured="seqW=${sw_bw}MiB/s seqR=${sr_bw}MiB/s randW=${rw_io}iops randR=${rr_io}iops"

# every workload must produce throughput
for v in "$sw_bw" "$sr_bw" "$rw_io" "$rr_io"; do
    [ "${v:-0}" -gt 0 ] 2>/dev/null || { emit FAIL "$measured" "a workload produced zero throughput"; exit 1; }
done

# Multi-node: publish this node's numbers, barrier, rank 1 sums the cluster
# aggregate. bench.json/baseline-capture below then operate on the AGGREGATE
# (rank 1 only) rather than any single node's number.
if [ "$T" -gt 1 ]; then
    coord_put "fp_sw_${R}" "$sw_bw"; coord_put "fp_sr_${R}" "$sr_bw"
    coord_put "fp_rw_${R}" "$rw_io"; coord_put "fp_rr_${R}" "$rr_io"
    coord_barrier "fio_perf_published" >/dev/null
    if [ "$R" = 1 ]; then
        agg_sw=0; agg_sr=0; agg_rw=0; agg_rr=0
        for n in $(seq 1 "$T"); do
            v=$(coord_get "fp_sw_${n}" 30 2>/dev/null); agg_sw=$((agg_sw + ${v:-0}))
            v=$(coord_get "fp_sr_${n}" 30 2>/dev/null); agg_sr=$((agg_sr + ${v:-0}))
            v=$(coord_get "fp_rw_${n}" 30 2>/dev/null); agg_rw=$((agg_rw + ${v:-0}))
            v=$(coord_get "fp_rr_${n}" 30 2>/dev/null); agg_rr=$((agg_rr + ${v:-0}))
        done
        sw_bw=$agg_sw; sr_bw=$agg_sr; rw_io=$agg_rw; rr_io=$agg_rr
        measured="seqW=${sw_bw}MiB/s seqR=${sr_bw}MiB/s randW=${rw_io}iops randR=${rr_io}iops"
    fi
fi

# Only rank 1 owns the baseline-capture / bench.json write (avoids N racing
# writers; at T=1, rank 1 IS the only node, so behavior is unchanged).
if [ "$R" = 1 ]; then
    if [ "$FSTYPE" = xfs ]; then
        # This run IS the baseline capture -- refresh it for every other
        # condition to compare against (same schema
        # tests/tooling/fio_vs_xfs_baseline.sh uses). /src/mxfs is NFS from
        # the coordinator with root-squash quirks: a direct `>` overwrite of
        # an EXISTING file can fail silently (2026-07-14 -- this exact bug
        # left a stale value in place with zero error surfaced). Write to a
        # new temp file + mv instead -- rename only needs dir write, which
        # isn't squashed, matching the workaround already used for bench.json
        # below.
        bstmp=$(mktemp 2>/dev/null)
        if [ -n "$bstmp" ]; then
            printf '{"seq_write_1m":{"bw_mib":%s},"seq_read_1m":{"bw_mib":%s},"rand_write_4k":{"iops":%s},"rand_read_4k":{"iops":%s},"size":"%s"}\n' \
                "$sw_bw" "$sr_bw" "$rw_io" "$rr_io" "$SIZE" > "$bstmp" && mv "$bstmp" "$BASE" 2>/dev/null
        fi
    fi

    # Append the raw (aggregate, at T>1) numbers to bench.json, keyed per condition.
    BENCH="${MXFS_BENCH:-/src/mxfs/bench.json}"; DLM="${MXFS_DLM:-tcp}"; FSLABEL="${MXFS_FS_LABEL:-mxfs}"
    [ -s "$BENCH" ] || echo '{}' > "$BENCH" 2>/dev/null
    btmp=$(mktemp 2>/dev/null) && jq \
      --arg l "fio_perf_${NODES}n_${DLM}_$(date +%s)" --arg ts "$(date -u +%FT%TZ)" \
      --argjson n "$NODES" --arg d "$DLM" --arg sz "$SIZE" --arg fs "$FSLABEL" \
      --argjson sw "${sw_bw:-0}" --argjson sr "${sr_bw:-0}" --argjson rw "${rw_io:-0}" --argjson rr "${rr_io:-0}" \
      '.[$l] = {ts:$ts, test:"fio_perf", nodes:$n, dlm:$d, fs:$fs, size:$sz,
                fio:{seq_write_1m:{bw_mib:$sw}, seq_read_1m:{bw_mib:$sr},
                     rand_write_4k:{iops:$rw}, rand_read_4k:{iops:$rr}}}' \
      "$BENCH" > "$btmp" 2>/dev/null && mv "$btmp" "$BENCH" 2>/dev/null
fi

emit PASS "$measured"
