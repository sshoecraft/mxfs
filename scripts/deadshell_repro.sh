#!/bin/bash
# deadshell_repro.sh — DETERMINISTIC repro of the peer-freed dead-shell
# dialloc corruption (ccloop-4dd7; the pve "stale-inode dialloc corruption").
#
# Proven chain (vmrig ino 139 autopsy, tests/logs/vmrig_dialloc_*):
#   1. node A creates D/f (ino N; in-core live, mode!=0)
#   2. node B rm's D/f  -> B is the free authority: difree runs on B;
#      A's per-inode DLM is never BASTed
#   3. A evicts its dentry+inode (drop_caches) -> iput -> inactivation sees
#      coh_nlink=0, local_unlink=0, no authority -> INACT-SKIP-STALE ->
#      IRECLAIMABLE shell keeps mode!=0 (the missed local xfs_inode_uninit)
#   4. A creates again in D -> dialloc picks the genuinely-free N ->
#      iget cache-hits the dead shell -> pre-fix: xfs_iget_check_free_state
#      "Corruption detected! Free inode 0xN not marked free!" -> -117 ->
#      dirty trans_cancel -> cluster-wide shutdown.
#
# Post-fix (P-CR63-DEADSHELL-DEFER + P-RECYCLE-SANITIZE): the create reuses
# the sanitized shell; no corruption, no shutdown.
#
# Usage (from clyde):
#   N1=test1 N2=test2 MXFS_PASS=/tmp/.mxfs_pass scripts/deadshell_repro.sh [ITERS]
# Exit: 0 = all iterations clean; 42 = corruption/shutdown observed;
#       3 = infra failure (mount missing etc.)
set -u
N1=${N1:-test1}
N2=${N2:-test2}
PASS=${MXFS_PASS:-/tmp/.mxfs_pass}
SSH=${MXFS_SSH:-/src/mxfs/tools/mxfs_sshpass.sh}
MNT=${MXFS_MOUNT:-/mnt/shared}
ITERS=${1:-8}
D="$MNT/.deadshell"
SIG='Corruption detected|Shutting down filesystem|Internal error xfs|P-CR3-CANCEL|P-DIFREE-DBL|inobt record corruption'

ssh1() { "$SSH" "$N1" "$PASS" "$1" 2>/dev/null | grep -v "Permanently added\|authorized\|disconnect"; }
ssh2() { "$SSH" "$N2" "$PASS" "$1" 2>/dev/null | grep -v "Permanently added\|authorized\|disconnect"; }

# NOTE: ssh1/ssh2 pipe through grep, so the REMOTE exit status is swallowed
# (ccmemory runsh-ssh-node-pipeline-swallows-remote-exit-status) — use
# output-based checks only.
[ "$(ssh1 "mountpoint -q $MNT && echo MOUNTED")" = "MOUNTED" ] || { echo "DEADSHELL_INFRA_FAIL: $N1 not mounted"; exit 3; }
[ "$(ssh2 "mountpoint -q $MNT && echo MOUNTED")" = "MOUNTED" ] || { echo "DEADSHELL_INFRA_FAIL: $N2 not mounted"; exit 3; }
ssh1 "mkdir -p $D"

MARK="DEADSHELL_$(date +%s%N)"
ssh1 "echo $MARK > /dev/kmsg" ; ssh2 "echo $MARK > /dev/kmsg"

fail=0
for i in $(seq 1 "$ITERS"); do
    f="$D/f$i"
    # 1. A creates (ino N allocated on A; also fsync so the dirent is durable
    #    and B can resolve it via dir coherency).
    ino=$(ssh1 "echo x > $f && sync -f $MNT && stat -c %i $f")
    [ -n "$ino" ] || { echo "iter$i: create/stat failed on $N1"; fail=1; break; }
    # 2. B rm's it (B unlinks; B runs the authorized difree).
    ssh2 "rm -f $f"
    # 3. A drops its dentry+inode caches -> the dead shell forms via
    #    INACT-SKIP (inodegc is given a moment to run the inactivation).
    ssh1 "sync; echo 2 > /proc/sys/vm/drop_caches; sleep 1"
    # 4. A creates a burst in the same dir — dialloc reuses the freed ino N.
    ssh1 "for k in \$(seq 1 8); do echo y > $D/r${i}_\$k || echo CREATE_FAIL_\$k; done"
    # Check both nodes for the corruption signature after this iter.
    for pair in "1:$N1" "2:$N2"; do
        r=${pair%%:*}; node=${pair##*:}
        e=$("$SSH" "$node" "$PASS" "dmesg | awk -v m=$MARK 'f{print} \$0~m{f=1}' | grep -E '$SIG' | head -3" 2>/dev/null | grep -v "Permanently added")
        if [ -n "$e" ]; then
            echo "iter$i: >>> CORRUPTION on $node:"; echo "$e" | sed 's/^/    /'
            fail=1
        fi
    done
    [ "$fail" -ne 0 ] && break
    # cleanup this iter's files (from B, keeping cross-node churn realistic)
    ssh2 "rm -f $D/r${i}_* $f"
    echo "iter$i: clean (ino=$ino)"
done

echo "--- probe counts since $MARK ---"
for pair in "$N1" "$N2"; do
    c=$("$SSH" "$pair" "$PASS" "dmesg | awk -v m=$MARK 'f{print} \$0~m{f=1}' | grep -cE 'P-CR63-DEADSHELL-DEFER'" 2>/dev/null | tail -1)
    s=$("$SSH" "$pair" "$PASS" "dmesg | awk -v m=$MARK 'f{print} \$0~m{f=1}' | grep -cE 'P-RECYCLE-SANITIZE'" 2>/dev/null | tail -1)
    k=$("$SSH" "$pair" "$PASS" "dmesg | awk -v m=$MARK 'f{print} \$0~m{f=1}' | grep -cE 'INACT-SKIP-STALE'" 2>/dev/null | tail -1)
    echo "$pair: DEFER=$c SANITIZE=$s INACT-SKIP=$k"
done

if [ "$fail" -ne 0 ]; then
    echo "DEADSHELL_REPRO: CORRUPTION OBSERVED"
    exit 42
fi
echo "DEADSHELL_REPRO: all $ITERS iterations clean"
exit 0
