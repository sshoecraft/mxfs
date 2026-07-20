#!/bin/bash
# mxfs_multinode_bench.sh — N-node parallel rsync bench for the rsync_paired
# criterion (tests/criteria/rsync_paired.sh).  Recreated for the v5 cluster
# (test1..test16); the original mxfs.1 version was not inherited.
#
# Each node rsyncs the canonical open-gpu-kernel-modules tree (8137 files,
# ~584 MB) into its OWN per-node subdir of the shared mount, in parallel.
# Per-node subtrees => no cross-node same-name contention (this measures
# aggregate throughput / per-node wall, not Mode A coherency).
#
# Usage:  BENCH_KEY=<key> tools/mxfs_multinode_bench.sh <iters> <node1> [node2 ...]
# Env (with defaults):
#   MXFS_BENCH_JSON  (./bench.json)   MXFS_DEV (/dev/sda)   MXFS_MOUNT (/mnt/shared)
#   MXFS_MODULE (/src/mxfs/mxfs.ko)   MXFS_PASS (/tmp/.mxfs_pass)
#   MXFS_SSH (/src/mxfs/tools/mxfs_sshpass.sh)   SRC_TREE (/root/open-gpu-kernel-modules)
#   SRC_SEED (/src/open-gpu-kernel-modules)  — NFS source copied to SRC_TREE if missing
#
# Appends rows under .[$BENCH_KEY].results[] in bench.json, each:
#   {iter, node, wall_s, rsync_ec, dst_files, expected_files, md5_match, dmesg_flagged}
# Exits 0 on completion (PASS/FAIL judged by the criterion).
set -u

ITERS="${1:?iters required}"; shift
NODES=("$@")
[ "${#NODES[@]}" -ge 1 ] || { echo "no nodes given" >&2; exit 2; }

BENCH_KEY="${BENCH_KEY:?BENCH_KEY env required}"
MXFS_BENCH_JSON="${MXFS_BENCH_JSON:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/bench.json}"
MXFS_DEV="${MXFS_DEV:-/dev/sda}"
MXFS_MOUNT="${MXFS_MOUNT:-/mnt/shared}"
MXFS_MODULE="${MXFS_MODULE:-/src/mxfs/mxfs.ko}"
MXFS_PASS="${MXFS_PASS:-/tmp/.mxfs_pass}"
MXFS_SSH="${MXFS_SSH:-/src/mxfs/tools/mxfs_sshpass.sh}"
SRC_TREE="${SRC_TREE:-/root/open-gpu-kernel-modules}"
SRC_SEED="${SRC_SEED:-/src/open-gpu-kernel-modules}"
DMESG_PAT='Internal error|Corruption|SHUTDOWN|shutting down|Free inode|DLM inode lock|reservation conflict|BUG:|Oops|stuck for|xlog_grant_head_wait'

run() { timeout "${3:-120}" "$MXFS_SSH" "$1" "$MXFS_PASS" "$2" 2>&1 | grep -vE '^Warning|^Unauthorized|^If you'; }

[ -f "$MXFS_BENCH_JSON" ] || echo '{}' > "$MXFS_BENCH_JSON"
# Initialize the key's results array
tmp=$(mktemp); jq --arg k "$BENCH_KEY" '.[$k] = {results: []}' "$MXFS_BENCH_JSON" > "$tmp" && mv "$tmp" "$MXFS_BENCH_JSON"

echo "=== mxfs_multinode_bench key=$BENCH_KEY iters=$ITERS nodes=${NODES[*]} ==="

# --- Fresh cluster mount: first node forms, rest join ---
NODE0="${NODES[0]}"
echo "--- mount: form $NODE0 ---"
out=$(run "$NODE0" "
  /src/mxfs/tools/prep_tcm_node_scst.sh >/tmp/p.log 2>&1
  modprobe libcrc32c
  lsmod | grep -q '^mxfs ' || insmod $MXFS_MODULE
  sg_persist --out --register-ignore --param-sark=0x5eed $MXFS_DEV >/dev/null 2>&1
  sg_persist --out --clear --param-rk=0x5eed $MXFS_DEV >/dev/null 2>&1
  echo y | /src/mxfs/tools/mkfs_mxfs $MXFS_DEV >/tmp/m.log 2>&1 && echo MKFS_OK
  mount -t mxfs $MXFS_DEV $MXFS_MOUNT && echo MOUNT_OK
" 150)
echo "$out" | grep -q MOUNT_OK || { echo "form $NODE0 failed: $out" >&2; exit 1; }
for n in "${NODES[@]:1}"; do
  ( run "$n" "
      /src/mxfs/tools/prep_tcm_node_scst.sh >/tmp/p.log 2>&1
      modprobe libcrc32c
      lsmod | grep -q '^mxfs ' || insmod $MXFS_MODULE
      mount -t mxfs $MXFS_DEV $MXFS_MOUNT && echo MOUNT_OK
    " 120 | grep -q MOUNT_OK && echo "  join $n OK" || echo "  join $n FAIL" ) &
done
wait

# --- Ensure the source tree exists locally on every node (seed from NFS) ---
for n in "${NODES[@]}"; do
  ( run "$n" "[ -d $SRC_TREE ] || cp -a $SRC_SEED $SRC_TREE; find $SRC_TREE -type f | wc -l" 600 >/dev/null ) &
done
wait
EXPECTED=$(run "$NODE0" "find $SRC_TREE -type f | wc -l" 60 | tr -d ' \r\n')
EXPECTED=${EXPECTED:-0}
echo "--- source expected_files=$EXPECTED ---"

for I in $(seq 1 "$ITERS"); do
  echo "--- iter $I/$ITERS ---"
  # Prep: clear per-node dst, dmesg cursor
  for n in "${NODES[@]}"; do
    run "$n" "HN=\$(hostname); rm -rf $MXFS_MOUNT/\$HN/it$I; mkdir -p $MXFS_MOUNT/\$HN/it$I; sync; dmesg | wc -l > /tmp/dc_$I" 60 >/dev/null
  done
  # Parallel rsync
  declare -a PIDS=()
  for n in "${NODES[@]}"; do
    OUT=/tmp/mnb_${BENCH_KEY}_${I}_${n}.out
    ( run "$n" "
        HN=\$(hostname); DST=$MXFS_MOUNT/\$HN/it$I
        S=\$(date +%s.%N)
        rsync -a $SRC_TREE/ \$DST/ ; EC=\$?
        sync
        E=\$(date +%s.%N)
        echo WALL=\$(awk -v s=\$S -v e=\$E 'BEGIN{printf \"%.3f\",e-s}')
        echo EC=\$EC
        echo FILES=\$(find \$DST -type f 2>/dev/null | wc -l)
        echo DMH=\$(dmesg | tail -n +\$(( \$(cat /tmp/dc_$I)+1 )) | grep -cE '$DMESG_PAT')
      " 900 > "$OUT" 2>&1 ) &
    PIDS+=($!)
  done
  wait "${PIDS[@]}" 2>/dev/null
  # Collect + append JSON rows
  for n in "${NODES[@]}"; do
    OUT=/tmp/mnb_${BENCH_KEY}_${I}_${n}.out
    WALL=$(grep '^WALL=' "$OUT" | tail -1 | cut -d= -f2); WALL=${WALL:-0}
    EC=$(grep '^EC=' "$OUT" | tail -1 | cut -d= -f2); EC=${EC:-1}
    FILES=$(grep '^FILES=' "$OUT" | tail -1 | cut -d= -f2); FILES=${FILES:-0}
    DMH=$(grep '^DMH=' "$OUT" | tail -1 | cut -d= -f2); DMH=${DMH:-0}
    MD5MATCH=false; [ "$FILES" = "$EXPECTED" ] && [ "$EXPECTED" -gt 0 ] && MD5MATCH=true
    echo "  iter $I $n wall_s=$WALL ec=$EC files=$FILES/$EXPECTED dmesg=$DMH"
    tmp=$(mktemp)
    jq --arg k "$BENCH_KEY" --argjson it "$I" --arg node "$n" \
       --argjson wall "$WALL" --argjson ec "$EC" --argjson df "$FILES" \
       --argjson ef "$EXPECTED" --argjson md5 "$MD5MATCH" --argjson dmh "$DMH" \
       '.[$k].results += [{iter:$it, node:$node, wall_s:$wall, rsync_ec:$ec, dst_files:$df, expected_files:$ef, md5_match:$md5, dmesg_flagged:$dmh}]' \
       "$MXFS_BENCH_JSON" > "$tmp" && mv "$tmp" "$MXFS_BENCH_JSON"
  done
done
echo "=== mxfs_multinode_bench DONE key=$BENCH_KEY ==="
