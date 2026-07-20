#!/bin/bash
# sess69: loop test_rename_visibility until it FAILS, then dump the P88
# numrecs=1 clobber writes + shutdown context from every node.  rename_visibility
# is flaky (~1/3 fail).  No reset between PASS iters (no shutdown => cluster still
# good); on FAIL we stop and the caller resets.  RULE 3: lives in the tree.
set -u
cd /src/mxfs
NODES="test1 test2 test3 test4"
MAXIT=${1:-8}
PASS=/tmp/.mxfs_pass
for it in $(seq 1 "$MAXIT"); do
    echo "===== iter $it ====="
    for n in $NODES; do timeout 8 bash tools/mxfs_sshpass.sh "$n" "$PASS" 'dmesg -C' >/dev/null 2>&1 & done
    wait
    out=$(MXFS_NODE_OFFSET=16 MXFS_TESTS_DIR=/src/mxfs/tests timeout 140 \
        bash tests/run_tests.sh --nodes 4 --phase cluster \
        --test test_rename_visibility --pass-file "$PASS" \
        --device /dev/sda --mount-point /mnt/shared 2>&1)
    res=$(echo "$out" | grep -aoE "PASS: [0-9]+|FAIL: [0-9]+" | tr '\n' ' ')
    echo "  result: $res"
    if echo "$out" | grep -qaE "FAIL: [1-9]"; then
        echo "===== FAIL on iter $it — dumping ====="
        for n in $NODES; do
            echo "----- $n: numrecs=1 clobber writes -----"
            timeout 12 bash tools/mxfs_sshpass.sh "$n" "$PASS" \
                'dmesg | grep -a "P88-INSTR" | grep -a "numrecs=1 " | head -20' 2>/dev/null
            echo "----- $n: shutdown/corruption -----"
            timeout 12 bash tools/mxfs_sshpass.sh "$n" "$PASS" \
                'dmesg | grep -aiE "shutting down|corruption|Internal error|reada_verify|EFSBADCRC|EFSCORRUPTED|0x5f8d" | head -10' 2>/dev/null
        done
        exit 7
    fi
done
echo "no failure in $MAXIT iters"
exit 0
