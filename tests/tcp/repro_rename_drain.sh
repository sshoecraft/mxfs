#!/bin/bash
# repro_rename_drain.sh — isolate the tcp_dlm_scaling "shared dir not drained"
# leak.  Each node concurrently does create+rename+rm of its OWN entries in a
# SHARED dir (forcing cross-node dir-EX handoffs), then we check the dir drains
# to empty.  A leftover dirent (often nlink=0 = dangling dirent over a freed
# inode) = the cross-node dir-block lost-update on EX-acquire.
#
# Run ON clyde:  bash tests/tcp/repro_rename_drain.sh [rounds] [iters]
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
S="$REPO/tools/mxfs_sshpass.sh"; P="${MXFS_PASS:-/tmp/.mxfs_pass}"
N1=test1; N2=test2; MNT=/mnt/shared; D="$MNT/.rrd"
ROUNDS="${1:-150}"; ITERS="${2:-6}"
CLEAN='grep -vE "^Warning:|^Unauthorized|^If you"'
run() { timeout 200 bash "$S" "$1" "$P" "$2" 2>&1 | grep -vE '^Warning:|^Unauthorized|^If you'; }

run "$N1" "rm -rf $D; mkdir -p $D; sync"
for it in $(seq 1 "$ITERS"); do
    run "$N1" "D=$D; for r in \$(seq 1 $ROUNDS); do f=\$D/n1_i${it}_r\$r; echo \$r > \$f && mv \$f \$f.done && rm -f \$f.done; done; echo n1_i${it}_done" &
    P1=$!
    run "$N2" "D=$D; for r in \$(seq 1 $ROUNDS); do f=\$D/n2_i${it}_r\$r; echo \$r > \$f && mv \$f \$f.done && rm -f \$f.done; done; echo n2_i${it}_done" &
    P2=$!
    wait $P1; wait $P2
    # drain check from BOTH nodes
    l1=$(run "$N1" "ls $D 2>/dev/null | wc -l" | grep -oE '[0-9]+' | tail -1)
    l2=$(run "$N2" "ls $D 2>/dev/null | wc -l" | grep -oE '[0-9]+' | tail -1)
    echo "iter $it: drain test1=$l1 test2=$l2"
    if [ "${l1:-x}" != 0 ] || [ "${l2:-x}" != 0 ]; then
        echo "*** LEAK at iter $it ***"
        run "$N1" "ls -la $D 2>/dev/null | head; echo '-- dmesg dir hits --'; dmesg | grep -iE 'P19-B3DEC|INACT-SKIP|dir.*lost|rename|EFSCORRUPT|Shutting down' | tail -8"
        exit 1
    fi
done
echo "ALL $ITERS iters drained clean"
