#!/bin/bash
# drc_probe.sh — standalone reproducer for the dir_reuse_coherency LEAF-HASH
# durable loss (2/tcp).  Mirrors tests/suite/dir_reuse_coherency.sh but without
# the MQTT coord harness: test1 owns the dir lifecycle (mkdir/rm-rf of the SAME
# name each round → maximal inode/daddr REUSE), both nodes concurrently create
# NF data+md5 files, then test1 cold-reads and verifies EVERY entry is
# lookup-able.  On the FIRST round where a lookup fails, immediately dump both
# nodes' always-on leaf/release detectors (P21F-RELFLUSH-LEAF, P-RELFLUSH,
# P62-RELOAD-FORK-SHRINK) BEFORE the dmesg ring rolls, plus the failing-leaf
# timeline.  Foreground only.
#   usage: tests/drc_probe.sh [rounds] [nfiles]
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/..
SSH="$REPO/tools/mxfs_sshpass.sh"; PF=/tmp/.mxfs_pass
MNT=/mnt/shared; ROUNDS="${1:-24}"; NF="${2:-50}"
D="$MNT/.drcp"
EXP=$((4*NF))   # 2 nodes * (NF data + NF md5)
r() { local n="$1"; shift; timeout 60 bash "$SSH" "$n" "$PF" "$*" 2>&1 | grep -vE '^Warning:|^Unauthorized|^If you'; }
mkfiles='D="$1"; R="$2"; NF="$3"; for i in $(seq 1 $NF); do dd if=/dev/urandom of=$D/node${R}_f$i bs=4096 count=$(((i%8)+1)) 2>/dev/null; done; sync; for i in $(seq 1 $NF); do md5sum $D/node${R}_f$i 2>/dev/null | awk "{print \$1}" > $D/node${R}_f$i.md5; done; sync'

# clear dmesg both nodes at start
for n in test1 test2; do r "$n" "dmesg -C" >/dev/null; done

for it in $(seq 1 "$ROUNDS"); do
    r test1 "mkdir -p $D; sync" >/dev/null
    DINO=$(r test1 "stat -c%i $D" | tr -dc '0-9')
    r test1 "bash -c '$mkfiles' x $D 1 $NF" >/dev/null &
    r test2 "bash -c '$mkfiles' x $D 2 $NF" >/dev/null &
    wait
    r test2 "sync" >/dev/null
    # cold reload on test1, verify count + per-entry lookup
    res=$(r test1 "sync; echo 3 > /proc/sys/vm/drop_caches; sleep 1; rd=\$(ls $D 2>/dev/null|grep -c .); lf=0; for nm in \$(ls $D 2>/dev/null); do [ -e \"$D/\$nm\" ] || lf=\$((lf+1)); done; echo rd=\$rd lf=\$lf")
    rd=$(echo "$res" | grep -oE 'rd=[0-9]+' | tr -dc 0-9)
    lf=$(echo "$res" | grep -oE 'lf=[0-9]+' | tr -dc 0-9)
    echo "round $it: ino=$DINO readdir=$rd/$EXP lookup_fail=$lf"
    if [ "${rd:-0}" -lt "$EXP" ] || [ "${lf:-0}" -gt 0 ]; then
        echo ">>>>> FAIL round $it ino=$DINO readdir=$rd lookup_fail=$lf <<<<<"
        # which entries fail lookup (first 20)
        miss=$(r test1 "n=0; for nm in \$(ls $D 2>/dev/null); do if [ ! -e \"$D/\$nm\" ]; then echo -n \"\$nm \"; n=\$((n+1)); [ \$n -ge 20 ] && break; fi; done")
        echo "  first lookup-fail entries: $miss"
        for n in test1 test2; do
            echo "  ===== $n leaf/release/reload timeline ====="
            r "$n" "dmesg | grep -aE 'P25-RESURRECT-SKIP|P-IRESURRECT|P54-DIRBLK-PROBE|leaf_read_verify|P119-NONEX|P17B-EPOCH' | tail -30"
        done
        echo "=== probe stop (cluster left mounted for inspection) ==="
        exit 0
    fi
    r test1 "rm -rf $D; sync" >/dev/null
done
echo "=== no failure in $ROUNDS rounds ==="
