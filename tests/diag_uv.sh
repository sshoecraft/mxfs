#!/bin/bash
# sess13 (ccloop 4eef1f39): deep diagnostic for test_unlink_visibility.
# 4 nodes each create FPN files in one shared block-format dir.  After the
# create barrier, capture on EVERY node: (a) ls breakdown by creator prefix,
# (b) dir inode size/format, (c) a COLD (drop_caches) ls breakdown = disk truth,
# (d) the uv-dir dmesg traces.  No rm phase — we want the post-create snapshot.
set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/criteria/lib.sh"

NODES_LIST=(test1 test2 test3 test4)
N=${#NODES_LIST[@]}
M="$MXFS_MOUNT"
FPN="${1:-30}"
D="$M/.mxfs_test/uv_diag"
TOTAL=$((N * FPN))

echo "=== teardown + fresh mkfs/mount (instr=0) ==="
teardown_all "${NODES_LIST[*]}"
INSMOD_OPTS="instr=0" fresh_cluster_mount "${NODES_LIST[0]}" "${NODES_LIST[@]:1}" \
    || { echo MOUNT_FAIL; exit 1; }
for n in "${NODES_LIST[@]}"; do ssh_node_quiet "$n" "dmesg -C"; done

ssh_node "${NODES_LIST[0]}" "mkdir -p $D" >/dev/null 2>&1
# DROP_ON: "" none, "creator" drop on test1, "peers" drop on test2-4, "all" everywhere
DROP_ON="${DROP_ON:-}"
if [ "$DROP_ON" = "creator" ] || [ "$DROP_ON" = "all" ]; then
    ssh_node "${NODES_LIST[0]}" "sync; echo 3 > /proc/sys/vm/drop_caches" >/dev/null 2>&1
    echo "[dropped caches on creator ${NODES_LIST[0]}]"
fi
if [ "$DROP_ON" = "peers" ] || [ "$DROP_ON" = "all" ]; then
    for n in "${NODES_LIST[@]:1}"; do ssh_node "$n" "sync; echo 3 > /proc/sys/vm/drop_caches" >/dev/null 2>&1; done
    echo "[dropped caches on peers]"
fi
echo "=== phase 1: each node creates $FPN files concurrently (CAPTURING errors) DROP_ON=$DROP_ON ==="
for i in $(seq 1 $N); do
    n="${NODES_LIST[$((i-1))]}"
    ssh_node "$n" "errs=0; first=''; diag=''; for j in \$(seq 1 $FPN); do e=\$( { echo d_${i}_\$j > $D/node${i}_file\$j; } 2>&1 ); if [ \$? -ne 0 ]; then errs=\$((errs+1)); if [ -z \"\$first\" ]; then first=\"\$e\"; mt=\$(stat -c %i $M 2>&1); a=\$(stat -c %i $M/.mxfs_test 2>&1); b=\$(stat -c %i $D 2>&1); diag=\"mnt=\$mt mxfs_test=\$a uv_diag=\$b\"; fi; fi; done; sync; echo \"NODE${i} create_errs=\$errs first_err=[\$first] resolve@firstfail{\$diag}\"" &
done
wait
sleep 1

echo "=== phase 2: WARM ls breakdown by creator (expect node1..node$N each =$FPN) ==="
for i in $(seq 1 $N); do
    n="${NODES_LIST[$((i-1))]}"
    echo "--- $n (warm) ---"
    timeout 12 bash tools/mxfs_sshpass.sh "$n" /tmp/.mxfs_pass \
        "ls $D 2>/dev/null | sed 's/_file.*//' | sort | uniq -c; echo total=\$(ls $D 2>/dev/null|wc -l); stat -c 'ino=%i size=%s' $D" 2>/dev/null
done

echo "=== phase 3: COLD ls breakdown (drop_caches = disk truth) ==="
for i in $(seq 1 $N); do
    n="${NODES_LIST[$((i-1))]}"
    echo "--- $n (cold) ---"
    timeout 15 bash tools/mxfs_sshpass.sh "$n" /tmp/.mxfs_pass \
        "sync; echo 3 > /proc/sys/vm/drop_caches; ls $D 2>/dev/null | sed 's/_file.*//' | sort | uniq -c; echo total=\$(ls $D 2>/dev/null|wc -l); stat -c 'ino=%i size=%s' $D" 2>/dev/null
done

echo "=== phase 4: uv-dir dmesg (ino=132 region) per node ==="
for i in $(seq 1 $N); do
    n="${NODES_LIST[$((i-1))]}"
    echo "--- $n dmesg ---"
    timeout 12 bash tools/mxfs_sshpass.sh "$n" /tmp/.mxfs_pass \
        "dmesg | grep -aE 'ino=132|P107-PUBLISH|STALE-EX|EXGRANT|EXREL' | grep -avE 'ino=12[089]|ino=13[01]' | tail -40" 2>/dev/null
done
echo "=== DONE ==="
