#!/bin/bash
# cc_inode_timeline.sh — reproduce the block-dir concurrent-create dirent LOSS
# and dump the FULL per-inode DLM event timeline from BOTH nodes for the
# clobbered dir inode, so the exact handoff sequence that produced the stale-base
# RMW is reconstructable.  Within one node, dmesg order is exact; across nodes
# the realns has clock skew but second-granularity interleave is fine.
# Requires dirwr=1.  Usage: cc_inode_timeline.sh [iters] [nfiles]
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/..
SSH="$REPO/tools/mxfs_sshpass.sh"; PF=/tmp/.mxfs_pass
MNT=/mnt/shared; ITERS="${1:-30}"; NF="${2:-50}"
r() { local n="$1"; shift; timeout 40 bash "$SSH" "$n" "$PF" "$*" 2>&1 | grep -vE '^Warning:|^Unauthorized|^If you'; }
mkfiles='D="$1"; R="$2"; NF="$3"; for i in $(seq 1 $NF); do dd if=/dev/urandom of=$D/node${R}_f$i bs=4096 count=$(((i%8)+1)) oflag=sync 2>/dev/null; done; sync; for i in $(seq 1 $NF); do md5sum $D/node${R}_f$i 2>/dev/null | awk "{print \$1}" > $D/node${R}_f$i.md5; done; sync'

for n in test1 test2; do r $n "dmesg --clear" >/dev/null; done

for it in $(seq 1 "$ITERS"); do
    D="$MNT/.tl_$it"
    r test1 "mkdir -p $D; sync" >/dev/null
    r test1 "bash -c '$mkfiles' x $D 1 $NF" >/dev/null &
    r test2 "bash -c '$mkfiles' x $D 2 $NF" >/dev/null &
    wait
    r test2 "sync" >/dev/null
    exp=$((4*NF))
    cnt0=$(r test1 "sync; echo 3 > /proc/sys/vm/drop_caches; sleep 1; ls $D/node*_f[0-9]* 2>/dev/null | wc -l" | tr -dc '0-9')
    echo "iter $it: test1 all=$cnt0/$exp"
    if [ "${cnt0:-0}" -lt "$exp" ]; then
        DINO=$(r test1 "stat -c %i $D" | tr -dc '0-9')
        miss=$(r test1 "for n in 1 2; do for i in \$(seq 1 $NF); do [ -e $D/node\${n}_f\$i ] || echo node\${n}_f\$i; [ -e $D/node\${n}_f\$i.md5 ] || echo node\${n}_f\$i.md5; done; done | tr '\n' ' '")
        echo "  >>> SHORT iter $it dir=$D ino=$DINO MISSING: $miss"
        for nn in 1 2; do
            echo "  ===== test$nn timeline for ino=$DINO (dmesg order) ====="
            r test$nn "dmesg | grep -aE 'ino=$DINO( |,)' | grep -aE 'P-DIR-SEQ|P106-EXGRANT|P106-EXREL|P106-MR-EVICT|P106-MR-SKIP|P104-MODIFY-REFRESH|P104-CONSUMER-REFRESH|P-RELFLUSH|P124-MHT-EXPIRE|P23-SLOWPATH|P105-ACQ-DIRINODE|P105-REL-DIRINODE' | sed -E 's/^.*mxfs: //'" | tail -100
        done
        exit 0
    fi
    r test1 "rm -rf $D" >/dev/null
done
echo "=== no short in $ITERS iters ==="
