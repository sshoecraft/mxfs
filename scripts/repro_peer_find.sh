#!/bin/bash
# repro_peer_find.sh — loop reproducer for the sess20(ccloop) iflush
# bad-magic / error-117 family: solo rsync on test1, peer tree-walk on
# test2, unmount test1 (AIL push), dmesg sweep on both nodes.  Stops on
# the first cycle that trips a probe so the P20 forensics can be read.
#
# Usage: scripts/repro_peer_find.sh [CYCLES]
set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/../tests/criteria/lib.sh"
stamp() { echo "[$(date +%H:%M:%S)] $*"; }

CYCLES=${1:-4}
N1=test1; N2=test2
SRC=/root/open-gpu-kernel-modules

for c in $(seq 1 "$CYCLES"); do
    stamp "=== cycle $c/$CYCLES: teardown + fresh cluster ==="
    teardown_all "$N1 $N2"
    fresh_cluster_mount "$N1" "$N2" || { echo "MOUNT FAIL"; exit 1; }
    for h in "$N1" "$N2"; do ssh_node "$h" "dmesg -C"; done

    stamp "cycle $c: solo rsync on $N1"
    ssh_node "$N1" "
        mkdir -p $MXFS_MOUNT/diag/a1
        t0=\$(date +%s%N)
        timeout 120 rsync -a --no-i-r $SRC/ $MXFS_MOUNT/diag/a1/ >/dev/null 2>&1
        rc=\$?
        sync
        t1=\$(date +%s%N)
        echo SOLO_MS=\$(( (t1 - t0) / 1000000 )) rc=\$rc"

    stamp "cycle $c: peer find on $N2"
    nf=$(ssh_node "$N2" "find $MXFS_MOUNT/diag -type f 2>/dev/null | wc -l" | tr -cd '0-9')
    [ -z "$nf" ] && nf=$(ssh_node "$N2" "find $MXFS_MOUNT/diag -type f 2>/dev/null | wc -l" | tr -cd '0-9')
    echo "PEER_FIND_FILES=$nf"

    stamp "cycle $c: unmount $N1 (AIL push)"
    ssh_node "$N1" "umount $MXFS_MOUNT; echo UMOUNT_RC=\$?"

    bad=0
    for h in "$N1" "$N2"; do
        hits=$(ssh_node "$h" 'dmesg | grep -cE "Bad inode|error 117|Internal error|Structure needs|P20-BIO-READ-LOGGED"' | tr -cd '0-9')
        [ -z "$hits" ] && hits=$(ssh_node "$h" 'dmesg | grep -cE "Bad inode|error 117|Internal error|Structure needs|P20-BIO-READ-LOGGED"' | tr -cd '0-9')
        echo "cycle $c $h probe_hits=${hits:-NA}"
        [ "${hits:-1}" -gt 0 ] && bad=1
    done
    [ "$nf" != 8714 ] && { echo "cycle $c: PEER FIND INCOMPLETE ($nf/8714)"; bad=1; }

    if [ "$bad" = 1 ]; then
        echo "=== cycle $c TRIPPED — dumping forensics ==="
        for h in "$N1" "$N2"; do
            echo "--- $h ---"
            ssh_node "$h" 'dmesg | grep -E "P20-|Bad inode|error 117|Structure needs|Internal error" | head -30'
        done
        exit 2
    fi
    stamp "cycle $c clean"
done
stamp "all $CYCLES cycles clean"
exit 0
