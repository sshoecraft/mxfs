#!/bin/bash
# sess62: prove the generalized cluster-buffer merge restores a REGULAR-FILE
# inode slot (the ino=132 alloc-revert class).  Runs test_cv_disc N times
# WITHOUT clearing dmesg, then dumps every P-CLMERGE "restored" line whose
# dmode is a regular file (010....) across all nodes.  A restore with
# dmode=0100xxx + bmode=0 (or differing) is the alloc-revert being prevented.
NODES="test1 test2 test3 test4"
PASS=/tmp/.mxfs_pass
SSH="bash /src/mxfs/tools/mxfs_sshpass.sh"
ITERS=${1:-6}
for n in $NODES; do timeout 8 $SSH $n $PASS 'dmesg -C >/dev/null 2>&1'; done
for it in $(seq 1 "$ITERS"); do
    echo "===== capture iter $it ====="
    MXFS_TESTS_DIR=/src/mxfs/tests timeout 120 ./tests/run_tests.sh \
        --nodes 4 --phase cluster --test test_cv_disc --pass-file "$PASS" \
        --device /dev/sda --mount-point /mnt/shared 2>&1 | grep -aE "=> H2|PASS:|FAIL:" | tail -3
done
echo "===== P-CLMERGE restored (all nodes, regular-file dmode) ====="
for n in $NODES; do
    echo "----- $n -----"
    timeout 10 $SSH $n $PASS 'dmesg | grep -a "P-CLMERGE restored"' 2>/dev/null | tail -40
done
