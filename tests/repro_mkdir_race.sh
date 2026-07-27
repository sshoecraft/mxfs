#!/bin/bash
# repro_mkdir_race — N-way concurrent `mkdir -p SHARED_NEW_PARENT/nodeR`.
#
# Found 8/cawd fence_during_write 2026-07-26 (ccloop c7ee71c6 sess11): the
# test's silent `mkdir -p $D/node$R` failed on 4/8 nodes and every subsequent
# write into the missing subdir returned ENOENT for the whole window.  The
# per-node child names are unique, so the only contended step is the shared
# fresh PARENT: `mkdir -p` tolerates EEXIST there, anything else (ENOENT from
# a mid-coherence lookup, EIO, stale-handle) aborts it.
#
# This driver runs R rounds; each round uses a FRESH parent name and fires the
# mkdir on all N nodes concurrently, capturing rc + stderr per node, then
# lists the parent from node1 to count landed children.
#
# Usage: tests/repro_mkdir_race.sh [N] [ROUNDS] [MNT]
set -u
N="${1:-8}"; ROUNDS="${2:-30}"; MNT="${3:-/mnt/shared}"
REPO=/src/mxfs
SSH="$REPO/tools/mxfs_sshpass.sh"
PASS=$("$REPO/tools/mxfs_secrets.sh" passfile)
STAMP=$(date +%s)
fails=0
for r in $(seq 1 "$ROUNDS"); do
    P="$MNT/.mkrace_${STAMP}_r${r}"
    td=$(mktemp -d)
    # epoch-aligned start: every node spins to the same wall-clock nanosecond
    # (nodes are NTP-synced) so the mkdirs collide within ~1ms like the suite
    # dispatcher's row start, instead of ssh-launch skew (~300ms, no repro).
    GO=$(( ($(date +%s) + 3) * 1000000000 ))
    for i in $(seq 1 "$N"); do
        ( out=$(timeout 30 "$SSH" "test$i" "$PASS" \
              "while [ \$(date +%s%N) -lt $GO ]; do :; done; mkdir -p $P/node$i $P/hot 2>&1; echo rc=\$?" 2>/dev/null | tail -2 | tr '\n' ' ')
          echo "test$i: $out" > "$td/$i" ) &
    done
    wait
    landed=$(timeout 30 "$SSH" test1 "$PASS" "ls $P 2>/dev/null | grep -c node" 2>/dev/null | tr -cd '0-9')
    bad=""
    for i in $(seq 1 "$N"); do
        grep -q 'rc=0 *$' "$td/$i" || bad="$bad $(cat "$td/$i")"
    done
    if [ -n "$bad" ] || [ "${landed:-0}" != "$N" ]; then
        fails=$((fails+1))
        echo "ROUND $r: landed=$landed/$N FAIL:$bad"
    else
        echo "ROUND $r: landed=$landed/$N ok"
    fi
    rm -rf "$td"
done
echo "MKRACE_RESULT rounds=$ROUNDS failed_rounds=$fails"
[ "$fails" -eq 0 ]
