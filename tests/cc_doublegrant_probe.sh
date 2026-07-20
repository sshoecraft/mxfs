#!/bin/bash
# cc_doublegrant_probe.sh — test the DOUBLE-GRANT hypothesis for the block-dir
# concurrent-create durable dirent LOSS (2/tcp crash_consistency blocker).
#
# Each round: both nodes concurrently create NF data+NF md5 into ONE shared dir
# (=block format).  Then test1 readdir-counts.  On a SHORT count (lost dirent):
#   - resolve the dir inode number,
#   - pull P106-EXGRANT / P106-EXREL (realns brackets of the dir-inode EX-held
#     window) from BOTH nodes' dmesg for that inode,
#   - merge-sort by realns and flag any interval where node1 and node2 both hold
#     EX on the SAME dir inode OVERLAPPING (= double-grant => DLM mutual-exclusion
#     failure, not a cache-staleness bug).
# Requires dirwr=1 (P106 detectors gated on it).
# Usage: cc_doublegrant_probe.sh [iters] [nfiles]
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/..
SSH="$REPO/tools/mxfs_sshpass.sh"; PF=/tmp/.mxfs_pass
MNT=/mnt/shared; ITERS="${1:-30}"; NF="${2:-50}"
r() { local n="$1"; shift; timeout 40 bash "$SSH" "$n" "$PF" "$*" 2>&1 | grep -vE '^Warning:|^Unauthorized|^If you'; }
mkfiles='D="$1"; R="$2"; NF="$3"; for i in $(seq 1 $NF); do dd if=/dev/urandom of=$D/node${R}_f$i bs=4096 count=$(((i%8)+1)) oflag=sync 2>/dev/null; done; sync; for i in $(seq 1 $NF); do md5sum $D/node${R}_f$i 2>/dev/null | awk "{print \$1}" > $D/node${R}_f$i.md5; done; sync'

for n in test1 test2; do r $n "dmesg --clear" >/dev/null; done

for it in $(seq 1 "$ITERS"); do
    D="$MNT/.dg_$it"
    r test1 "mkdir -p $D; sync" >/dev/null
    r test1 "bash -c '$mkfiles' x $D 1 $NF" >/dev/null &
    r test2 "bash -c '$mkfiles' x $D 2 $NF" >/dev/null &
    wait
    r test2 "sync" >/dev/null
    exp=$((4*NF))
    cnt0=$(r test1 "sync; echo 3 > /proc/sys/vm/drop_caches; sleep 1; ls $D/node*_f[0-9]* 2>/dev/null | wc -l" | tr -dc '0-9')
    echo "iter $it: test1 all=$cnt0/$exp"
    if [ "${cnt0:-0}" -lt "$exp" ]; then
        echo "  >>> SHORT at iter $it. dir=$D"
        DINO=$(r test1 "stat -c %i $D" | tr -dc '0-9')
        echo "  dir inode = $DINO"
        miss=$(r test1 "for n in 1 2; do for i in \$(seq 1 $NF); do [ -e $D/node\${n}_f\$i ] || echo node\${n}_f\$i; [ -e $D/node\${n}_f\$i.md5 ] || echo node\${n}_f\$i.md5; done; done | tr '\n' ' '")
        echo "  MISSING: $miss"
        # Pull EX brackets for this inode from both nodes
        TMP=$(mktemp)
        for nn in 1 2; do
            r test$nn "dmesg | grep -aE 'P106-EX(GRANT|REL) ino=$DINO '" | \
              sed -nE "s/.*P106-(EX[A-Z]+) ino=$DINO realns=([0-9]+).*/\2 N$nn \1/p" >> $TMP
        done
        echo "  --- merged EX timeline for ino=$DINO (realns sorted) ---"
        sort -n $TMP | awk '{
            ev=$3; node=$2; t=$1;
            if(ev=="EXGRANT"){ held[node]=t;
                other=(node=="N1"?"N2":"N1");
                if(held[other]!=""){ printf "  *** OVERLAP: %s grants EX at %s while %s still holds (granted %s) ***\n", node,t,other,held[other] }
            }
            if(ev=="EXREL"){ held[node]="" }
            printf "    %s %s %s\n", t, node, ev
        }'
        ovl=$(sort -n $TMP | awk '{ev=$3;node=$2; if(ev=="EXGRANT"){held[node]=1; other=(node=="N1"?"N2":"N1"); if(held[other])c++} if(ev=="EXREL")held[node]=0} END{print c+0}')
        echo "  ==> OVERLAP COUNT (double-grant events) = $ovl"
        rm -f $TMP
        exit 0
    fi
    r test1 "rm -rf $D" >/dev/null
done
echo "=== no short in $ITERS iters ==="
