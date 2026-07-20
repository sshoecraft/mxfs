#!/bin/bash
# drc_single_node.sh — SINGLE-NODE version of the dir_reuse_coherency churn.
#
# DECISIVE RULE-4 experiment (sess32): is the dir_reuse_coherency readdir-short /
# P31E-DATAINIT-ABA clobber a SINGLE-NODE self-clobber (a stale-buffer reload
# reverts this node's OWN dir fork → data_init re-inits lblk 0), or does it
# REQUIRE cross-node concurrency (dual-EX on the reused dir inode)?
#
# Runs the SAME mkdir / write-NF-files+NF-md5 / sync / drop_caches / readdir /
# rm-rf churn as tests/suite/dir_reuse_coherency.sh, but on ONE node only.  The
# cluster stays mounted multinode (the peer is idle, never touching $D), so there
# is NO concurrency on the test dir.
#   - readdir SHORT here  => SINGLE-NODE self-clobber (publish/mutual-exclusion is
#     NOT the root; the fork-revert reload is).
#   - readdir always full => the loss needs cross-node concurrency (dual-EX).
#
# Usage: tests/drc_single_node.sh [NODE] [NFILES] [ROUNDS]
set -u
NODE=${1:-test1}
NF=${2:-50}
ROUNDS=${3:-24}
M=/mnt/shared
D="$M/.drc_single"
PASS=/tmp/.mxfs_pass
SSH=/src/mxfs/tools/mxfs_sshpass.sh
EXP=$(( 2 * NF ))   # data + md5 sidecar (single node)

run() { "$SSH" "$NODE" "$PASS" "$1" 2>&1 | grep -vE '^Warning|^Unauthorized|^If you'; }

echo "drc_single_node: NODE=$NODE NF=$NF ROUNDS=$ROUNDS EXP=$EXP"
fails=0
for r in $(seq 1 "$ROUNDS"); do
    out=$(run "
        mkdir -p $D 2>/dev/null; sync
        for i in \$(seq 1 $NF); do dd if=/dev/urandom of=$D/node1_f\$i bs=4096 count=\$(( (\$i % 8) + 1 )) 2>/dev/null; done
        sync
        for i in \$(seq 1 $NF); do md5sum $D/node1_f\$i 2>/dev/null | awk '{print \$1}' > $D/node1_f\$i.md5; done
        sync
        echo 3 > /proc/sys/vm/drop_caches 2>/dev/null; sleep 1
        cnt=\$(ls $D 2>/dev/null | grep -c .)
        echo CNT=\$cnt
        rm -rf $D 2>/dev/null; sync
    ")
    cnt=$(echo "$out" | sed -n 's/^CNT=//p')
    if [ "$cnt" != "$EXP" ]; then
        echo "ROUND $r: readdir=$cnt/$EXP  *** SHORT (single-node loss) ***"
        fails=$((fails+1))
    else
        echo "ROUND $r: readdir=$cnt/$EXP ok"
    fi
done
echo "drc_single_node: $fails/$ROUNDS rounds SHORT"
[ "$fails" -eq 0 ] && echo "VERDICT: single-node CLEAN -> loss needs cross-node concurrency (dual-EX)" \
                   || echo "VERDICT: single-node SHORT -> SINGLE-NODE self-clobber (fork-revert reload), not mutual-exclusion"
