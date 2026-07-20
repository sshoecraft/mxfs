#!/bin/bash
# Phase 0 multinode fio bench harness.  Runs the standard 4-workload
# suite from feedback_bench_format.md on N nodes concurrently against the
# mxfs mount, then parses bw/IOPS per node and emits a markdown table
# row-per-workload, column-per-node + aggregate.
#
# Usage: bench/phase0_fio_multinode.sh <label> <node-csv>
#   e.g. bench/phase0_fio_multinode.sh fcoh1 test1,test2,test3,test4
#
# The mxfs.force_coherent value is reported (read from sysfs) but NOT
# set here — set it via INSMOD_OPTS at fresh_cluster_mount time, or:
#   for h in $NODES; do tools/mxfs_sshpass.sh $h /tmp/.mxfs_pass \
#     "echo 1 > /sys/module/mxfs/parameters/force_coherent"; done
#
# Persistent script (per RULE 3 / feedback_scripts_in_tree).

set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd "$SCRIPT_DIR/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"
PASS="${MXFS_PASS:-/tmp/.mxfs_pass}"
MOUNT="${MXFS_MOUNT:-/mnt/shared}"
OUTDIR="${OUTDIR:-$REPO/phase0_runs}"
mkdir -p "$OUTDIR"

LABEL="${1:-phase0}"
NODES_CSV="${2:-test1,test2,test3,test4}"
IFS=',' read -r -a NODES <<< "$NODES_CSV"
N=${#NODES[@]}
SIZE="${SIZE:-512M}"
RUNTIME="${RUNTIME:-30}"
# Per-node bench dir lives ON the shared mount so the workload is truly
# cross-node contended (each node writes/reads from its own subdir under
# the same parent — exercises AG-DLM + inode-DLM + dir-block coherency).
BENCH_PARENT="${BENCH_PARENT:-$MOUNT/.phase0_bench}"

WORKLOADS=(
    "seq_write_1m  rw=write       bs=1M  size=$SIZE   ioengine=libaio direct=1 iodepth=32"
    "seq_read_1m   rw=read        bs=1M  size=$SIZE   ioengine=libaio direct=1 iodepth=32"
    "rand_write_4k rw=randwrite   bs=4K  size=$SIZE   ioengine=libaio direct=1 iodepth=32"
    "rand_read_4k  rw=randread    bs=4K  size=$SIZE   ioengine=libaio direct=1 iodepth=32"
)

# Sanity check: nodes reachable, mxfs mounted, fio installed.
for h in "${NODES[@]}"; do
    if ! timeout 5 "$SSH" "$h" "$PASS" "mount | grep -q ' $MOUNT type mxfs' && command -v fio >/dev/null"; then
        echo "ERR: $h: mxfs not mounted at $MOUNT or fio missing" >&2
        exit 1
    fi
done

# Report current force_coherent
FCOH=$(timeout 5 "$SSH" "${NODES[0]}" "$PASS" "cat /sys/module/mxfs/parameters/force_coherent 2>/dev/null || echo ?")
echo "label=$LABEL nodes=$NODES_CSV force_coherent=$FCOH size=$SIZE runtime=$RUNTIME"

# Pre-create per-node dirs from node[0] (single-writer, avoids the
# parent-dir create-race we're not testing here).
timeout 30 "$SSH" "${NODES[0]}" "$PASS" "rm -rf $BENCH_PARENT; mkdir -p $BENCH_PARENT && for i in $(seq 1 $N); do mkdir -p $BENCH_PARENT/n\$i; done && sync"

# Build a per-node fio job file uploaded into each node's bench subdir.
# All nodes run the SAME workload concurrently; we collect per-node bw.

declare -A RESULT  # RESULT[wl,host] = bw or iops string
TMP=$(mktemp -d -t phase0fio.XXXXXX)
trap 'rm -rf "$TMP"' EXIT

for spec in "${WORKLOADS[@]}"; do
    set -- $spec
    NAME="$1"; shift
    EXTRA="$*"
    echo
    echo "=== workload: $NAME ($EXTRA) ==="

    # Launch all nodes in parallel.
    pids=()
    for i in $(seq 0 $((N-1))); do
        H="${NODES[$i]}"
        SUB="$BENCH_PARENT/n$((i+1))"
        # output to /tmp on remote, copied back via cat-over-ssh.
        OUT="$TMP/${NAME}_${H}.json"
        (
            timeout 180 "$SSH" "$H" "$PASS" "
                cd $SUB
                fio --name=${NAME} --filename=${NAME}.dat \
                    --runtime=$RUNTIME --time_based --group_reporting \
                    --output-format=json --output=/tmp/phase0_${NAME}_${H}.json \
                    $EXTRA >/dev/null 2>&1
                cat /tmp/phase0_${NAME}_${H}.json
                rm -f /tmp/phase0_${NAME}_${H}.json ${NAME}.dat
            " > "$OUT"
        ) &
        pids+=($!)
    done
    for p in "${pids[@]}"; do wait "$p"; done

    # Parse per-node bw/IOPS.  bs=1M -> report bw (MiB/s).  bs=4K -> IOPS.
    AGG=0
    LINE="| $NAME |"
    for i in $(seq 0 $((N-1))); do
        H="${NODES[$i]}"
        F="$TMP/${NAME}_${H}.json"
        if [ ! -s "$F" ]; then
            LINE="$LINE n/a |"
            continue
        fi
        # jobs[0].read.bw_bytes + write.bw_bytes (one is 0 depending on rw).
        BW=$(python3 -c "
import json,sys
try:
    j=json.load(open('$F'))
    job=j['jobs'][0]
    r=job['read']; w=job['write']
    bw=r['bw_bytes']+w['bw_bytes']
    iops=r['iops']+w['iops']
    print(bw, iops)
except Exception as e:
    print('0 0')
")
        BW_BYTES=$(echo "$BW" | awk '{print $1}')
        IOPS=$(echo "$BW" | awk '{print $2}')
        case "$NAME" in
            seq_*)
                # MiB/s
                MIB=$(python3 -c "print(f'{$BW_BYTES/1048576:.1f}')")
                LINE="$LINE $MIB MiB/s |"
                AGG=$(python3 -c "print(f'{$AGG + $BW_BYTES/1048576:.1f}')")
                ;;
            rand_*)
                I=$(python3 -c "print(f'{$IOPS:.0f}')")
                LINE="$LINE $I IOPS |"
                AGG=$(python3 -c "print(f'{$AGG + $IOPS:.0f}')")
                ;;
        esac
    done
    case "$NAME" in
        seq_*)  LINE="$LINE $AGG MiB/s |" ;;
        rand_*) LINE="$LINE $AGG IOPS |" ;;
    esac
    echo "$LINE"
    echo "$LINE" >> "$OUTDIR/${LABEL}_table.md"
done

echo
echo "=== Summary table ==="
cat "$OUTDIR/${LABEL}_table.md"
echo
echo "Done.  Detailed json under $TMP (will be wiped at exit); summary at $OUTDIR/${LABEL}_table.md"

# Clean up bench dirs on shared mount (single-writer)
timeout 30 "$SSH" "${NODES[0]}" "$PASS" "rm -rf $BENCH_PARENT" >/dev/null 2>&1 || true
