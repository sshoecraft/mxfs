#!/bin/bash
# cc_dirgrow_probe.sh — reproduce the block-dir concurrent-create WHOLE-BLOCK loss
# and dump P34C-DIRGROW (dir-space grow: ino,startoff->fsb) from BOTH nodes for the
# clobbered dir inode.  Cross-node merge by (startoff): two nodes mapping the SAME
# dir startoff to DIFFERENT fsb = stale-bmap double-map (loser's block orphaned);
# two nodes mapping different startoff to the SAME fsb = allocator double-alloc.
# Requires dirwr=1.  Usage: cc_dirgrow_probe.sh [iters] [nfiles]
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/..
SSH="$REPO/tools/mxfs_sshpass.sh"; PF=/tmp/.mxfs_pass
MNT=/mnt/shared; ITERS="${1:-40}"; NF="${2:-50}"
r() { local n="$1"; shift; timeout 40 bash "$SSH" "$n" "$PF" "$*" 2>&1 | grep -vE '^Warning:|^Unauthorized|^If you'; }
mkfiles='D="$1"; R="$2"; NF="$3"; for i in $(seq 1 $NF); do dd if=/dev/urandom of=$D/node${R}_f$i bs=4096 count=$(((i%8)+1)) oflag=sync 2>/dev/null; done; sync; for i in $(seq 1 $NF); do md5sum $D/node${R}_f$i 2>/dev/null | awk "{print \$1}" > $D/node${R}_f$i.md5; done; sync'

for n in test1 test2; do r $n "dmesg --clear" >/dev/null; done

for it in $(seq 1 "$ITERS"); do
    D="$MNT/.gr_$it"
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
            echo "  ===== test$nn P34C-DIRGROW + P105 ACQ/REL for ino=$DINO (dmesg order) ====="
            r test$nn "dmesg | grep -aE 'ino=$DINO( |,)' | grep -aE 'P34C-DIRGROW|P105-ACQ-DIRINODE|P105-REL-DIRINODE|P-DIR-SEQ' | sed -E 's/^.*mxfs: //; s/ realns=[0-9]*//' | tail -40"
        done
        echo "  ===== merged by startoff (look for same startoff->diff fsb, or diff startoff->same fsb) ====="
        ( for nn in 1 2; do r test$nn "dmesg | grep -aE 'P34C-DIRGROW ino=$DINO '" | sed -E "s/^.*P34C-DIRGROW //; s/ realns=[0-9]*//; s/^/N$nn /"; done ) | \
          awk '{for(i=1;i<=NF;i++){if($i~/^startoff=/)so=$i; if($i~/^fsb=/)fsb=$i} print $1, so, fsb}' | sort -k2
        exit 0
    fi
    r test1 "rm -rf $D" >/dev/null
done
echo "=== no short in $ITERS iters ==="
