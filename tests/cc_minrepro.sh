#!/bin/bash
# cc_minrepro.sh — scoped reproducer: each iter uses a FRESH never-reused dir and
# clears dmesg on both nodes JUST before the concurrent create, so when a loss
# happens the dmesg trace covers exactly ONE dir incarnation (no inode-reuse or
# cross-iter ratelimit contamination).  On the short, dumps P-RELFLUSH names +
# P34C-DIRGROW + P-H14 for the clobbered inode from both nodes.
# Requires dirwr=1.  Usage: cc_minrepro.sh [iters] [nfiles]
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/..
SSH="$REPO/tools/mxfs_sshpass.sh"; PF=/tmp/.mxfs_pass
MNT=/mnt/shared; ITERS="${1:-40}"; NF="${2:-50}"
r() { local n="$1"; shift; timeout 40 bash "$SSH" "$n" "$PF" "$*" 2>&1 | grep -vE '^Warning:|^Unauthorized|^If you'; }
mkfiles='D="$1"; R="$2"; NF="$3"; for i in $(seq 1 $NF); do dd if=/dev/urandom of=$D/node${R}_f$i bs=4096 count=$(((i%8)+1)) oflag=sync 2>/dev/null; done; sync; for i in $(seq 1 $NF); do md5sum $D/node${R}_f$i 2>/dev/null | awk "{print \$1}" > $D/node${R}_f$i.md5; done; sync'

for it in $(seq 1 "$ITERS"); do
    D="$MNT/.mr_$it"
    r test1 "mkdir -p $D; sync" >/dev/null
    for n in test1 test2; do r $n "dmesg --clear" >/dev/null; done
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
            echo "  ===== test$nn (ino=$DINO) P34C/P-H14/P-RELFLUSH ====="
            r test$nn "dmesg | grep -aE 'ino=$DINO( |,)' | grep -aE 'P34C-DIRGROW|P-H14-INSTR'" | sed -E 's/^.*mxfs: //; s/ realns=[0-9]*//'
            echo "    --- P-RELFLUSH daddr->names (unique) ---"
            r test$nn "dmesg | grep -aE 'P-RELFLUSH ino=$DINO '" | sed -E 's/^.*daddr=([0-9-]+).*names=\[([^]]*)\].*/daddr=\1 [\2]/' | sort -u
        done
        exit 0
    fi
done
echo "=== no short in $ITERS iters ==="
