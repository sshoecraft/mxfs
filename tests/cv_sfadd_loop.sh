#!/bin/bash
# sess59: loop cv_disc, clearing dmesg before each iter, and on an H2 (on-disk
# lost-update) dump the P-SFADD modify-time timeline from ALL nodes for the
# failing dir inode.  Resolves the sess57(H2-lost)/sess58(child-miss) conflict:
#   ex_pop>1 in P-SFADD  => concurrent-EX (broken exclusion)
#   ex_pop=1 + stale base => clobber-after-stale-reload
NODES="test1 test2 test3 test4"
PASS=/tmp/.mxfs_pass
SSH="bash /src/mxfs/tools/mxfs_sshpass.sh"
OUT=/src/mxfs/tests/.cv_sfadd_loop.out
: > "$OUT"
ITERS=${1:-12}
for it in $(seq 1 "$ITERS"); do
    echo "===== ITER $it =====" | tee -a "$OUT"
    for n in $NODES; do timeout 8 $SSH $n $PASS 'dmesg -C >/dev/null 2>&1'; done
    RUNOUT=$(MXFS_TESTS_DIR=/src/mxfs/tests timeout 120 ./tests/run_tests.sh \
        --nodes 4 --phase cluster --test test_cv_disc --pass-file "$PASS" \
        --device /dev/sda --mount-point /mnt/shared 2>&1)
    echo "$RUNOUT" | grep -aE "DISC|cannot see|H1|H2" | tee -a "$OUT"
    if echo "$RUNOUT" | grep -qaE "=> H2"; then
        # extract the missing file name (nodeX.txt) from the DISC line
        MISS=$(echo "$RUNOUT" | grep -aoE "miss node[0-9]+\.txt" | head -1 | awk '{print $2}')
        echo ">>> H2 reproduced iter $it, missing=$MISS — dumping P-SFADD" | tee -a "$OUT"
        for n in $NODES; do
            echo "----- $n dmesg P-SFADD/RELOAD -----" | tee -a "$OUT"
            timeout 10 $SSH $n $PASS \
              'dmesg | grep -aE "P-CRNAME|P-SFADD|P-SFDIR-RELOAD|P-SFDIR-FASTEX|P-DIRFLUSH|P-CLMERGE|INODE-REUSE|SESS50-STARVE"' \
              2>/dev/null | tee -a "$OUT"
        done
        echo "=== STOP on H2 ===" | tee -a "$OUT"
        exit 0
    fi
done
echo "=== loop done, no H2 in $ITERS iters ===" | tee -a "$OUT"
