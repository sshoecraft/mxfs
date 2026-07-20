#!/bin/bash
# repro_mode0.sh — sess40 reproducer for the cross-node directory-inode
# mode=0 / EACCES coherency bug seen in cache_coherency.
#
# Symptom: after a CONCURRENT create-race on a shared parent dir, a peer
# node reads the parent's inode as `?---------` (di_mode=0, the freed/
# pre-allocation image) -> the subtree is EACCES on that peer; its inode
# cache is frozen at mode=0 and never reloads from the creator's commit.
#
# Trigger (mirrors the test framework): all N nodes simultaneously
# `mkdir -p $BASE/childX` where $BASE does not yet exist, so they race to
# allocate $BASE and the losers iget it mid-allocation.  Then every node
# stat's $BASE and we count peers that see mode!=dir.
#
# Fast: one fresh mount, then ITERS race rounds.  Iterate the fix here,
# not the 15-min cache_coherency criterion.
#
# Usage: tests/repro_mode0.sh [ITERS] [node...]   (default 30, test1..4)
set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/criteria/lib.sh"

ITERS=${1:-30}
shift 2>/dev/null
if [ "$#" -ge 2 ]; then NODES=("$@"); else NODES=(test1 test2 test3 test4); fi
N=${#NODES[@]}
A="${NODES[0]}"

echo "repro_mode0: nodes=${NODES[*]} iters=$ITERS module=$(modinfo "$MXFS_MODULE" 2>/dev/null | awk '/srcversion/{print $2}')"

teardown_all "${NODES[*]}"
fresh_cluster_mount "$A" "${NODES[@]:1}" || { echo "MOUNT FAILED"; exit 1; }

# Clear dmesg on every node so post-run detector grep is scoped to this run.
for n in "${NODES[@]}"; do ssh_node_quiet "$n" "dmesg -C 2>/dev/null"; done

# stat just the mode char-string, stripping any login banner noise.
peer_mode() { ssh_node "$1" "stat -c MODE=%A '$2' 2>&1" | sed -n 's/.*MODE=\([^ ]*\).*/\1/p' | head -1; }

total_fail=0
for it in $(seq 1 "$ITERS"); do
    BASE="$MXFS_MOUNT/m0_${$}_$it"
    # Wipe any prior, settle.
    ssh_node_quiet "$A" "rm -rf $BASE 2>/dev/null; sync"
    # All nodes race to create $BASE (via mkdir -p of a per-node child).
    pids=()
    for n in "${NODES[@]}"; do
        ( ssh_node_quiet "$n" "mkdir -p $BASE/child_$n" ) &
        pids+=($!)
    done
    for p in "${pids[@]}"; do wait "$p" 2>/dev/null; done
    # Every node reads $BASE's mode immediately.
    bad=""
    for n in "${NODES[@]}"; do
        m=$(peer_mode "$n" "$BASE")
        case "$m" in
            drwx*) : ;;
            *)
                # Classify: stat error string + whether it persists after
                # a settle (sync + 2s) — persistent == the real blocker.
                cls=$(ssh_node "$n" "stat -c m=%A '$BASE' 2>&1; sync; sleep 2; echo -n PERSIST=; stat -c %A '$BASE' 2>&1 | head -1" \
                      | grep -oE 'denied|No such|m=[^ ]+|PERSIST=[^ ]+' | tr '\n' ',')
                bad="$bad $n:[${cls}]"
                ;;
        esac
    done
    if [ -n "$bad" ]; then
        total_fail=$((total_fail+1))
        echo "  iter $it: STALE on$bad"
    fi
done

echo "RESULT: iters=$ITERS fail_iters=$total_fail"
echo "=== coherence detectors (this run, ALL nodes) ==="
for n in "${NODES[@]}"; do
    echo "--- $n ---"
    ssh_node "$n" "dmesg 2>/dev/null | grep -E 'P-IGET-ENOENT|DIR-STALE-SKIP|RELOAD-SIZE-DROP|P-H18-INVAL|from_disk FAILED|imap_to_bp failed' | tail -8"
done
[ "$total_fail" = "0" ] && echo "REPRO: PASS (coherent)" || echo "REPRO: FAIL (stale di_mode on peer)"
