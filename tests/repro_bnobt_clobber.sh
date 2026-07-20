#!/bin/bash
# repro_bnobt_clobber.sh — fast, aggressive reproducer for the AG bnobt
# stale-pristine clobber → "ltbno + ltlen > bno" double-free corruption.
#
# Maximizes concurrent cross-node AG free activity: all N nodes, in tight
# loops, create a batch of files in a SHARED directory then delete them, many
# rounds, with NO barriers (so the create/delete phases of different nodes
# interleave maximally — that interleave is what trips the clobber).
#
# After each round, checks every node's dmesg for the corruption and for the
# sess47 detectors (ag_held=0 at a bnobt write, P88-CLOBBER-PRODUCER stack).
# Run AFTER tests/reset4.sh 4 with the F062090B+ build deployed.
#
# Usage: tests/repro_bnobt_clobber.sh [N_NODES] [FILES] [ROUNDS]
set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/criteria/lib.sh"

N=${1:-4}
FILES=${2:-60}
ROUNDS=${3:-40}
NODES=("${DEFAULT_NODES[@]:0:$N}")
M=/mnt/shared
PASS=/tmp/.mxfs_pass
SSH=/src/mxfs/tools/mxfs_sshpass.sh
D="$M/.bnclob"

run() { timeout 60 "$SSH" "$1" "$PASS" "$2" 2>&1 | grep -vE '^Warning|^Unauthorized|^If you'; }

echo "repro_bnobt_clobber: N=$N FILES=$FILES ROUNDS=$ROUNDS nodes=${NODES[*]}"
run "${NODES[0]}" "mkdir -p $D"

corrupt=0
for r in $(seq 1 "$ROUNDS"); do
    pids=()
    for idx in "${!NODES[@]}"; do
        nid=$((idx+1)); n="${NODES[$idx]}"
        # tight create-then-delete loop in the shared dir; no barrier
        run "$n" "for i in \$(seq 1 $FILES); do echo c_${nid}_\$i > $D/n${nid}_f\$i; done; for i in \$(seq 1 $FILES); do rm -f $D/n${nid}_f\$i; done" >/dev/null &
        pids+=($!)
    done
    wait "${pids[@]}" 2>/dev/null
    # quick corruption check (every round)
    for n in "${NODES[@]}"; do
        hit=$(run "$n" 'dmesg 2>/dev/null | grep -c "ltbno + ltlen"' | tr -d ' ')
        if [ "${hit:-0}" != "0" ]; then
            echo "ROUND $r: CORRUPTION on $n (ltbno count=$hit)"
            corrupt=1
        fi
    done
    if [ "$corrupt" = "1" ]; then break; fi
    [ $((r % 5)) -eq 0 ] && echo "  ...round $r clean"
done

echo "=== detector summary (all nodes) ==="
for n in "${NODES[@]}"; do
    echo -n "$n: "
    run "$n" 'echo -n "ag_held0="; dmesg 2>/dev/null|grep -c "ag_held=0"; echo -n " producer="; dmesg 2>/dev/null|grep -c "P88-CLOBBER-PRODUCER"; echo -n " pristine_writes="; dmesg 2>/dev/null|grep "P88-INSTR"|grep -c "numrecs=1 "; echo -n " ltbno="; dmesg 2>/dev/null|grep -c "ltbno + ltlen"' | tr '\n' ' '
    echo
done
[ "$corrupt" = "1" ] && echo "REPRODUCED" || echo "no corruption in $ROUNDS rounds"
