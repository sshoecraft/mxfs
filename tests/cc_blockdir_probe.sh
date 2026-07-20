#!/bin/bash
# cc_blockdir_probe.sh — focused reproducer + CASE A/B discriminator for the
# crash_consistency READ-side visibility lag on a BLOCK/LEAF-format shared dir
# (cc writes 2*NF entries into ONE dir -> block format).  Mirrors
# tests/suite/crash_consistency.sh: each node writes NF data files (oflag=sync)
# + NF .md5 sidecars into ONE shared dir, sync; then the reader drops caches and
# readdir-counts.  On a short count:
#   pureLUN : drop_caches + recount (coherent LUN re-read, no writer BAST)
#   direx   : touch a file (reader acquires dir-EX -> BASTs writer -> drain) + recount
# pureLUN restores  => CASE A (reader cache stale).
# only direx restores => CASE B (writer block-dir not durable at final location).
# Usage: cc_blockdir_probe.sh [iters] [nfiles]
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/..
SSH="$REPO/tools/mxfs_sshpass.sh"; PF=/tmp/.mxfs_pass
MNT=/mnt/shared; ITERS="${1:-30}"; NF="${2:-50}"
# sess19: NOREUSE=1 keeps each iter's dir (no rm-rf) so inode/daddr are NOT
# reused across iters — isolates whether the leaf-hash clobber requires the
# ABA inode/daddr-reuse stressor (rm-rf+recreate) or is fundamental to
# concurrent same-dir create.
NOREUSE="${NOREUSE:-0}"
r() { local n="$1"; shift; timeout 40 bash "$SSH" "$n" "$PF" "$*" 2>&1 | grep -vE '^Warning:|^Unauthorized|^If you'; }
mkfiles='D="$1"; R="$2"; NF="$3"; for i in $(seq 1 $NF); do dd if=/dev/urandom of=$D/node${R}_f$i bs=4096 count=$(((i%8)+1)) oflag=sync 2>/dev/null; done; sync; for i in $(seq 1 $NF); do md5sum $D/node${R}_f$i 2>/dev/null | awk "{print \$1}" > $D/node${R}_f$i.md5; done; sync'

for it in $(seq 1 "$ITERS"); do
    D="$MNT/.ccb_$it"
    r test1 "mkdir -p $D; sync" >/dev/null
    # sess16: isolate THIS iter's kernel trace so the failing iter's dir-block
    # writes aren't buried under prior iters' rm-rf drains.
    r test1 "dmesg --clear" >/dev/null; r test2 "dmesg --clear" >/dev/null
    DINO=$(r test1 "stat -c%i $D" | tr -dc '0-9')
    echo "iter $it: dir=$D ino=$DINO"
    r test1 "bash -c '$mkfiles' x $D 1 $NF" >/dev/null &
    r test2 "bash -c '$mkfiles' x $D 2 $NF" >/dev/null &
    wait
    r test2 "sync" >/dev/null
    exp=$((4*NF))     # 2 nodes * (NF data + NF md5) = all entries
    mexp=$((2*NF))    # 2 nodes * NF md5
    cnt0=$(r test1 "sync; echo 3 > /proc/sys/vm/drop_caches; sleep 1; ls $D/node*_f[0-9]* 2>/dev/null | wc -l" | tr -dc '0-9')
    md0=$(r test1 "ls $D/node*_f*.md5 2>/dev/null | wc -l" | tr -dc '0-9')
    echo "iter $it: test1 all=$cnt0/$exp md5=$md0/$mexp"
    if [ "${cnt0:-0}" -lt "$exp" ] || [ "${md0:-0}" -lt "$mexp" ]; then
        echo "  >>> SHORT. discriminating..."
        # sess19 CLASSIFIER: distinguish the two failure modes definitively.
        #   readdir-only (ls lists it, [ -e ] / statx ENOENT)  => LEAF-HASH
        #     inconsistency (dirent durable in data block, hash missing/wrong
        #     in the leaf index).  readdir-missing => genuine dirent/data loss.
        cls=$(r test1 "cd $D 2>/dev/null||exit; rd=\$(ls 2>/dev/null|grep -c .); lf=0; for f in \$(ls 2>/dev/null); do [ -e \"\$f\" ] || lf=\$((lf+1)); done; echo readdir=\$rd lookup_fail=\$lf")
        echo "      CLASSIFY test1: $cls (expected readdir=$exp)"
        echo "      => readdir==$exp & lookup_fail>0 = LEAF-HASH inconsistency; readdir<$exp = genuine DATA-LOSS"
        cL=$(r test1 "echo 3 > /proc/sys/vm/drop_caches; sleep 1; ls $D/node*_f[0-9]* 2>/dev/null|wc -l; ls $D/node*_f*.md5 2>/dev/null|wc -l" | tr '\n' ' ')
        echo "      pureLUN(drop+recount) all+md5: $cL (exp $exp / $mexp)"
        r test1 "echo p > $D/.probe; sync" >/dev/null
        cD=$(r test1 "echo 3 > /proc/sys/vm/drop_caches; sleep 1; ls $D/node*_f[0-9]* 2>/dev/null|wc -l; ls $D/node*_f*.md5 2>/dev/null|wc -l" | tr '\n' ' ')
        echo "      direx(touch+drop+recount) all+md5: $cD (exp $exp / $mexp)"
        # which entries does test1 miss?
        miss=$(r test1 "for n in 1 2; do for i in \$(seq 1 $NF); do [ -e $D/node\${n}_f\$i ] || echo node\${n}_f\$i; [ -e $D/node\${n}_f\$i.md5 ] || echo node\${n}_f\$i.md5; done; done | tr '\n' ' '")
        echo "      test1 MISSING: $miss"
        # does test2 (the shared LUN, other initiator) see the full set?
        c2all=$(r test2 "ls $D/node*_f[0-9]* 2>/dev/null|wc -l" | tr -dc '0-9')
        echo "      test2 sees all entries: $c2all/$exp"
        for m in $miss; do
            [ -n "$m" ] || continue
            e2=$(r test2 "[ -e $D/$m ] && echo Y || echo N")
            echo "        test2 has $m: $e2"
        done
        # eventual? wait 8s, re-read on test1
        sleep 8
        cE=$(r test1 "echo 3 > /proc/sys/vm/drop_caches; sleep 1; ls $D/node*_f[0-9]* 2>/dev/null|wc -l" | tr -dc '0-9')
        echo "      +8s eventual test1 all: $cE/$exp"
        echo "=== stop at first short for analysis ==="
        exit 0
    fi
    [ "$NOREUSE" = 1 ] || r test1 "rm -rf $D" >/dev/null
done
echo "=== no short in $ITERS iters ==="
