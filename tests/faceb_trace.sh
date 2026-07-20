#!/bin/bash
# sess75: Face B focused trace. Loops the concurrent shared-dir create until a
# lost-update, then for the FAILING dir reports per-node: dir inode number seen,
# surviving counts, and the create-phase dir-DLM event counts (FASTEX / EX
# ACQ-SLOW / PR ACQ-SLOW / REL) for that exact inode — synchronized with the
# failure. Resolves: do the losing peers ever acquire dir EX during create?
# Cluster must be mounted. Usage: faceb_trace.sh <iters> [K]
set -u
cd /src/mxfs
NODES=(test1 test2 test3 test4)
PASS=/tmp/.mxfs_pass
MNT=/mnt/shared
ITERS=${1:-30}
K=${2:-40}
SSH() { timeout "${3:-90}" bash tools/mxfs_sshpass.sh "$1" "$PASS" "$2" 2>/dev/null | grep -aviE 'Warning: Permanently|Unauthorized access|authorized user'; }

for it in $(seq 1 "$ITERS"); do
    D="$MNT/.fbt/it$it"
    SSH test1 "rm -rf $MNT/.fbt 2>/dev/null; mkdir -p $D; sync" 40 >/dev/null
    DINO=$(SSH test1 "stat -c '%i' $D" 20 | tr -d '[:space:]')
    for n in "${NODES[@]}"; do SSH "$n" "dmesg -C" 15 >/dev/null & done; wait
    declare -a PIDS=()
    idx=0
    for n in "${NODES[@]}"; do
        idx=$((idx+1))
        ( SSH "$n" "for i in \$(seq 1 $K); do echo c_${idx}_\$i > $D/n${idx}_f\$i; done; sync" 120 >/dev/null ) &
        PIDS+=($!)
    done
    wait "${PIDS[@]}" 2>/dev/null
    # verify from test1
    tot=$(SSH test1 "ls $D 2>/dev/null | wc -l" 60 | tr -d '[:space:]')
    exp=$((K*${#NODES[@]}))
    echo "===== iter $it: dir_ino=$DINO present=$tot/$exp ====="
    if [ "${tot:-0}" -ne "$exp" ]; then
        echo "===== FACE B on iter $it (dir_ino=$DINO) ====="
        idx=0
        for n in "${NODES[@]}"; do
            idx=$((idx+1))
            echo "--------- $n ---------"
            SSH "$n" "
                echo \"  sees_dir_ino=\$(stat -c '%i' $D 2>/dev/null) n${idx}_self=\$(ls $D/n${idx}_f* 2>/dev/null|wc -l)\"
                echo \"  view: n1=\$(ls $D/n1_f* 2>/dev/null|wc -l) n2=\$(ls $D/n2_f* 2>/dev/null|wc -l) n3=\$(ls $D/n3_f* 2>/dev/null|wc -l) n4=\$(ls $D/n4_f* 2>/dev/null|wc -l)\"
                echo \"  dir-DLM events (ino=$DINO): FASTEX=\$(dmesg|grep -ac \"P-DIR-SEQ FASTEX ino=$DINO\") EX-ACQSLOW=\$(dmesg|grep -aE \"P-DIR-SEQ ACQ-SLOW ino=$DINO mode=5\"|grep -ac .) PR-ACQSLOW=\$(dmesg|grep -aE \"P-DIR-SEQ ACQ-SLOW ino=$DINO mode=3\"|grep -ac .) REL=\$(dmesg|grep -ac \"P-DIR-SEQ REL ino=$DINO\")\"
                echo \"  DIR-STALE-SKIP=\$(dmesg|grep -ac \"DIR-STALE-SKIP ino=$DINO\") P-SF-DURABLE-FAIL=\$(dmesg|grep -ac P-SF-DURABLE-FAIL) shutdown=\$(dmesg|grep -ac -i 'shutting down')\"
            " 60
        done
        exit 7
    fi
done
echo "no Face B in $ITERS iters"
exit 0
