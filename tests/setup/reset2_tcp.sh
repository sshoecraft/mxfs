#!/bin/bash
# reset2_tcp.sh — clean 2-node TCP cluster reset + basic create smoke test.
#
# Runs ON the dev host (clyde).  Brings both nodes to a clean slate, mkfs's the
# shared LUN, loads mxfs with force_transport=1 (TCP) on both, mounts, then
# does a minimal cross-node create/visibility smoke test.  This is the gate the
# full 2-node suite depends on: if a basic multi-node create crashes the kernel
# (do_open NULL-deref family), the suite can't run.
#
# Usage:  tests/setup/reset2_tcp.sh [node1 node2]
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"
PASS="${MXFS_PASS:-/tmp/.mxfs_pass}"
N1="${1:-test1}"; N2="${2:-test2}"
MNT=/mnt/shared
CLEAN='grep -vE "^Warning:|^Unauthorized|^If you"'

run() { local node="$1"; shift; bash "$SSH" "$node" "$PASS" "$*" 2>&1 | grep -vE '^Warning:|^Unauthorized|^If you'; }

echo "=== [1] clean slate (umount + rmmod) on both nodes ==="
for n in "$N1" "$N2"; do
    echo "--- $n ---"
    run "$n" "umount $MNT 2>/dev/null; sleep 1; rmmod mxfs 2>/dev/null; lsmod | grep -q '^mxfs' && echo STILL_LOADED || echo UNLOADED"
done

echo "=== [2] mkfs shared LUN on $N1 ==="
run "$N1" "MXFS_REPO=/src/mxfs bash /src/mxfs/tests/setup/prep_fs.sh"

echo "=== [3] prep $N1 (tcp) — forms cluster ==="
run "$N1" "MXFS_REPO=/src/mxfs bash /src/mxfs/tests/setup/prep_node.sh tcp"
sleep 3

echo "=== [4] prep $N2 (tcp) — joins cluster ==="
run "$N2" "MXFS_REPO=/src/mxfs bash /src/mxfs/tests/setup/prep_node.sh tcp"
sleep 3

echo "=== [5] confirm srcversion + mounts ==="
for n in "$N1" "$N2"; do
    echo -n "$n: "; run "$n" "cat /sys/module/mxfs/srcversion; mount | grep -c 'type mxfs'"
done

echo "=== [6] BASIC CROSS-NODE CREATE smoke test ==="
echo "--- $N1 creates /mnt/shared/smoke_n1 ---"
run "$N1" "echo hello-from-n1 > $MNT/smoke_n1 && echo CREATE_N1_OK || echo CREATE_N1_FAIL"
sleep 1
echo "--- $N2 reads it ---"
run "$N2" "cat $MNT/smoke_n1 2>&1 | head -1"
echo "--- $N2 creates /mnt/shared/smoke_n2 ---"
run "$N2" "echo hello-from-n2 > $MNT/smoke_n2 && echo CREATE_N2_OK || echo CREATE_N2_FAIL"
sleep 1
echo "--- $N1 reads it ---"
run "$N1" "cat $MNT/smoke_n2 2>&1 | head -1"

echo "=== [7] crash markers in dmesg (both nodes) ==="
for n in "$N1" "$N2"; do
    echo "--- $n ---"
    run "$n" "dmesg | grep -iE 'BUG:|null pointer|call trace|P-CREATE-ERR|P-CR62|P-DIALLOC|shutdown' | tail -8"
done
echo "=== reset2_tcp done ==="
