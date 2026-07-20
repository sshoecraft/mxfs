#!/bin/bash
# mxfs.1 rsync metadata bench — single-run executor.
# Usage: mxfs1_rsync_bench.sh <label> <hosts_csv> <iterations>
#
# Each host runs in parallel:
#   rsync -a /root/<src_tree>/ /mnt/shared/<hostname>/rsync_<label>_iter<N>/
#   followed by sync.  Wall time captured on each host.
#
# Hosts and per-host source trees are mapped by IP:
#   192.168.120.186 (test1) -> /root/open-gpu-kernel-modules (584MB, 8137 files)
#   192.168.120.182 (test2) -> /root/extjs                   (766MB, 39699 files)
#
# Per iter, captures: wall time, file/dir count match, dmesg interesting lines.
# Output: prints summary lines parseable as
#   ITER <i> <label> <host> <tree> wall_s=<f> match=<y/n> dmesg_hits=<n>
#
# Sources & destinations are different per node so DLM contention is minimal.
set -u
LABEL=${1:?label required}
HOSTS_CSV=${2:?hosts_csv required}
ITERS=${3:-3}
SSH=/src/mxfs/tools/mxfs_sshpass.sh
PF=/tmp/.mxfs_pass

IFS=',' read -r -a HOSTS <<<"$HOSTS_CSV"

src_for() {
  case "$1" in
    192.168.120.186) echo open-gpu-kernel-modules ;;
    192.168.120.182) echo element-web ;;
    *) echo UNKNOWN ;;
  esac
}
expected_files_for() {
  case "$1" in
    192.168.120.186) echo 8137 ;;
    192.168.120.182) echo 4385 ;;
    *) echo 0 ;;
  esac
}
expected_md5_for() {
  case "$1" in
    192.168.120.186) echo 69ba9fd89df634ba998df98078956d88 ;;
    192.168.120.182) echo 0e02fad34a23ad30cdc48a7c79d35134 ;;
    *) echo "" ;;
  esac
}

run() { "$SSH" "$1" "$PF" "$2" 2>&1 | grep -vE '^Warning|^Unauthorized|^If you'; }

# Ensure per-host destination subdir exists
for H in "${HOSTS[@]}"; do
  run "$H" "sudo mkdir -p /mnt/shared/\$(hostname) && sudo chmod 777 /mnt/shared/\$(hostname)" >/dev/null
done

DMESG_PATTERN='Internal error|Corruption|SHUTDOWN|Free inode|DLM inode lock|RIGHT-FAIL|LEFT-FAIL|init_special_inode: bogus|disk lock acquisition timed out|disk lock table full|cntbt/bnobt desync|stale sb|journal space low|journal full|stuck for'

echo "=== rsync bench label=$LABEL hosts=$HOSTS_CSV iters=$ITERS ==="

for I in $(seq 1 $ITERS); do
  echo "--- iter $I/$ITERS ---"
  # Pre-iter prep on every host: clear dst, drop caches, capture dmesg cursor
  for H in "${HOSTS[@]}"; do
    SRC=$(src_for "$H")
    run "$H" "
      DST=/mnt/shared/\$(hostname)/rsync_${LABEL}_iter${I}
      sudo rm -rf \$DST
      sudo mkdir -p \$DST
      sudo sync
      sudo bash -c 'echo 3 > /proc/sys/vm/drop_caches'
      sudo dmesg -T | wc -l > /tmp/dmesg_cursor_${LABEL}_iter${I}
    " >/dev/null
  done

  # Launch parallel rsync — each node syncs its own tree to its own dst
  declare -a PIDS=()
  declare -a OUTS=()
  for H in "${HOSTS[@]}"; do
    SRC=$(src_for "$H")
    OUT=/tmp/rsync_${LABEL}_iter${I}_${H}.out
    rm -f "$OUT"
    (
      run "$H" "
        DST=/mnt/shared/\$(hostname)/rsync_${LABEL}_iter${I}
        START=\$(date +%s.%N)
        sudo rsync -a /root/${SRC}/ \$DST/ 2>&1
        sudo sync
        END=\$(date +%s.%N)
        WALL=\$(awk -v s=\$START -v e=\$END 'BEGIN { printf \"%.3f\", e-s }')
        echo WALL_SECONDS=\$WALL
      " > "$OUT" 2>&1
    ) &
    PIDS+=($!)
    OUTS+=("$H:$OUT:$SRC")
  done
  wait "${PIDS[@]}"

  # Post-iter analysis per host
  for E in "${OUTS[@]}"; do
    IFS=':' read -r H OUT SRC <<<"$E"
    HN=$(run "$H" "hostname" | tr -d '\r\n ')
    EXPECTED=$(expected_files_for "$H")
    WALL=$(grep '^WALL_SECONDS=' "$OUT" | tail -1 | cut -d= -f2)
    if [ -z "$WALL" ]; then WALL=ERR; fi

    # File-count match
    DST_FILES=$(run "$H" "find /mnt/shared/$HN/rsync_${LABEL}_iter${I} -type f 2>/dev/null | wc -l" | tr -d '\r\n ')
    MATCH=N
    if [ "$DST_FILES" = "$EXPECTED" ]; then MATCH=Y; fi

    # Content fingerprint match: rebuild the same rollup md5 over the destination
    EXPECTED_MD5=$(expected_md5_for "$H")
    DST_MD5=$(run "$H" "
      cd /mnt/shared/$HN/rsync_${LABEL}_iter${I}
      find . -type f -print0 | sort -z | xargs -0 md5sum 2>/dev/null | md5sum | awk '{print \$1}'
    " | tail -1 | tr -d '\r\n ')
    MD5_OK=N
    if [ "$DST_MD5" = "$EXPECTED_MD5" ] && [ -n "$EXPECTED_MD5" ]; then MD5_OK=Y; fi

    # dmesg interesting lines since cursor
    DMESG_HITS=$(run "$H" "
      START=\$(cat /tmp/dmesg_cursor_${LABEL}_iter${I} 2>/dev/null || echo 0)
      sudo dmesg -T | tail -n +\$((START+1)) | grep -cE '$DMESG_PATTERN' || echo 0
    " | tail -1 | tr -d '\r\n ')

    echo "  ITER $I $LABEL $HN $SRC wall_s=$WALL files=$DST_FILES/$EXPECTED match=$MATCH md5=$MD5_OK dmesg_hits=$DMESG_HITS"

    if [ "$MD5_OK" = "N" ] && [ -n "$EXPECTED_MD5" ]; then
      echo "    MD5 MISMATCH: dst=$DST_MD5 expected=$EXPECTED_MD5"
      # Diff manifests to find the divergent file(s)
      run "$H" "
        cd /mnt/shared/$HN/rsync_${LABEL}_iter${I}
        find . -type f -print0 | sort -z | xargs -0 md5sum 2>/dev/null > /tmp/dst_manifest_${LABEL}_iter${I}
        diff /root/${SRC}.manifest /tmp/dst_manifest_${LABEL}_iter${I} 2>&1 | head -20
      " | sed 's/^/      /'
    fi

    if [ "$DMESG_HITS" != "0" ] && [ -n "$DMESG_HITS" ]; then
      echo "    dmesg sample:"
      run "$H" "
        START=\$(cat /tmp/dmesg_cursor_${LABEL}_iter${I} 2>/dev/null || echo 0)
        sudo dmesg -T | tail -n +\$((START+1)) | grep -E '$DMESG_PATTERN' | tail -10
      " | sed 's/^/      /'
    fi
  done
done

echo "=== rsync bench label=$LABEL DONE ==="
