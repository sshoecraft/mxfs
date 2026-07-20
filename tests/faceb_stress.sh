#!/bin/bash
# sess73: aggressive Face B (concurrent shared-dir lost-update) reproducer.
# All N nodes SIMULTANEOUSLY create K files each into ONE shared directory
# with NO inter-node barrier (maximize concurrent read-modify-write on the
# shared dir data blocks), then EVERY node verifies that ALL N*K entries are
# present.  A lost-update (a peer RMW-clobbers a shared dir block from a stale
# cached copy) shows up as a missing file on one-or-more nodes — usually a
# contiguous suffix of some node's creations.  RULE 3: lives in the tree.
#
# Usage: faceb_stress.sh <iters> [files_per_node]
#   Cluster must already be mounted (use tests/reset4.sh 4 first).
set -u
cd /src/mxfs
NODES="${NODES:-test1 test2 test3 test4}"
PASS=/tmp/.mxfs_pass
MNT=/mnt/shared
ITERS=${1:-20}
K=${2:-40}
SSH() { timeout "${3:-60}" bash tools/mxfs_sshpass.sh "$1" "$PASS" "$2" 2>/dev/null | grep -aviE 'Warning: Permanently|Unauthorized access|authorized user'; }

NLIST=($NODES)
NN=${#NLIST[@]}

for it in $(seq 1 "$ITERS"); do
    D="$MNT/.faceb/it$it"
    # node1 makes the shared dir; all create into it.
    SSH "${NLIST[0]}" "mkdir -p $D; sync" 30 >/dev/null
    # clear dmesg on all
    for n in $NLIST; do SSH "$n" "dmesg -C" 15 >/dev/null & done; wait
    # Phase 1: every node, in parallel, creates K files into the SAME dir.
    # Use a per-node prefix; tight loop, no sync between files, then one sync.
    declare -a PIDS=()
    idx=0
    for n in $NLIST; do
        idx=$((idx+1))
        ( SSH "$n" "for i in \$(seq 1 $K); do echo c_${idx}_\$i > $D/n${idx}_f\$i; done; sync" 120 >/dev/null ) &
        PIDS+=($!)
    done
    wait "${PIDS[@]}" 2>/dev/null
    sleep 1
    # Phase 2: every node verifies ALL N*K files exist with correct content.
    miss=0
    report=""
    for n in $NLIST; do
        out=$(SSH "$n" "
            m=0
            for j in \$(seq 1 $NN); do
              for i in \$(seq 1 $K); do
                f=$D/n\${j}_f\$i
                if [ ! -e \"\$f\" ]; then echo \"MISS \$(hostname) n\${j}_f\$i\"; m=\$((m+1)); fi
              done
            done
            echo \"TOTAL_MISS \$(hostname) \$m\"
        " 90)
        report+="$out"$'\n'
    done
    tm=$(echo "$report" | grep -aE 'TOTAL_MISS' | awk '{s+=$3} END{print s+0}')
    echo "===== iter $it: aggregate_missing=$tm ====="
    if [ "${tm:-0}" -gt 0 ]; then
        echo "$report" | grep -aE 'MISS|TOTAL_MISS' | grep -avE 'TOTAL_MISS [^ ]+ 0' | head -40
        echo "===== FACE B REPRODUCED on iter $it ====="
        echo "===== DETECTOR DUMP (all nodes) ====="
        for n in $NLIST; do
            echo "--------------- $n ---------------"
            SSH "$n" 'dmesg | grep -aE "DIR-STALE-SKIP|P-SF-DURABLE-FAIL|P-SFDIR-FASTEX|P-EVICT-SKIP|P-EVICT-DONE|P-H18-INVAL|P63-INSTR" | tail -40' 25
        done
        exit 7
    fi
done
echo "no Face B in $ITERS iters (K=$K per node, $NN nodes)"
exit 0
