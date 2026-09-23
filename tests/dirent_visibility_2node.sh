#!/bin/bash
# dirent_visibility_2node.sh — a peer's completed directory writes must be
# visible to the other node.  Two-node TCP rig.  D-...-0941.
#
# WHAT THE BOARD ROW SHOWED AND WHY THIS EXISTS.  cache_coherency fails ~1 run
# in 3 with the reading node's view of a shared directory behind its peer's, in
# BOTH directions: creates not yet visible (exp=128 got=102) and deletes not yet
# visible ('uv gone node2_file56' is the POST-DELETE assertion, so its failure
# means the file is STILL THERE).  That row prints counts, not names, and cleans
# up after itself, so it cannot say WHICH dirents were wrong -- and whether the
# wrong set is one directory data block's worth (a stale block) or scattered
# (an index or invalidate-granularity fault) is the discriminating fact.
#
# TWO EARLIER SHAPES OF THIS HARNESS PASSED CLEAN AND BOTH FAILURES ARE THE
# POINT -- do not "simplify" back to either of them.
#   1. Writers SERIALISED (A does everything, its ssh returns, then B): 10 rounds
#      x 64 files, zero failures, while the board row was failing 1 in 3.  With
#      no two nodes writing one directory at once there is no contended EX
#      handoff and the fault cannot appear.
#   2. Writers CONCURRENT but each phase a separate ssh round trip: 20 rounds,
#      2560 operations, zero failures.  The round trip costs ~1 s between a write
#      and the read that must observe it, and coord_barrier -- which the failing
#      row uses -- releases both nodes within MILLISECONDS.  A second of slack is
#      apparently enough for the cluster to become coherent, so the harness's own
#      latency was hiding the defect.
# So the reproducer needs BOTH concurrent writers AND a read that lands
# immediately after the peer's write.  Both nodes are UTC-synced, so each round
# pins its phases to absolute wall-clock instants and each node runs the WHOLE
# round inside ONE remote command: no round trip sits between any write and the
# read that must see it, and both readers fire at the same instant.
#
# The delete direction is the load-bearing one: the deleting node runs rm and
# then sync(2) before its command returns, so by any single-system-image
# contract the unlink is complete and durable when the peer looks.  The create
# direction deliberately does NOT fsync, matching the row, because that is the
# shape the row exercises -- but a create-side failure alone is arguable and a
# delete-side failure is not.
#
# the budget rule (derived, for the clock-aligned shape): each round is one 6 s wall-clock
# schedule per node (T0 create, T0+2 read, T0+4 delete+sync, T0+6 read) plus a
# 3 s lead-in to align both nodes, and both nodes run it concurrently in ONE
# remote command => 9 s/round.  ROUNDS=20 => ~180 s, plus a ~5 s precondition
# check.  The per-ssh bound below is 40 s, which is the 9 s schedule plus margin
# for the listing of a directory holding 2N names -- not a round number.
#
# Usage: tests/dirent_visibility_2node.sh <label> [ROUNDS=10] [N=64]
# Env:   MXFS_NODE_LIST (default test1,test2), MXFS_DEV, MNT=/mnt/shared
set -u
LABEL=${1:?label}
ROUNDS=${2:-10}
N=${3:-64}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
A=${MXFS_NODE_LIST%%,*}
B=${MXFS_NODE_LIST##*,}
SSH=tools/mxfs_sshpass.sh
MNT=${MNT:-/mnt/shared}
D=$MNT/dvis_$LABEL
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_dvis_$LABEL
mkdir -p "$OUT"
fails=0
rounds_run=0
create_bad=0
delete_bad=0
filt() { grep -av '^Unauthorized\|^Warning:\|^If you\|^$'; }
rs() { timeout "$1" $SSH "$2" "$3" 2>/dev/null | filt; }
SV=$(modinfo mxfs.ko 2>/dev/null | sed -n 's/^srcversion: *//p')

echo "=== dirent_visibility_2node label=$LABEL A=$A B=$B rounds=$ROUNDS n=$N sv=$SV $(date -u +%FT%TZ) ==="
for n in $A $B; do
    echo "  INFO $n $(rs 20 "$n" "echo sv=\$(cat /sys/module/mxfs/srcversion) mounted=\$(grep -c ' $MNT mxfs ' /proc/mounts) heal=\$(cat /sys/module/mxfs/parameters/dir_datascan_heal)" | tr -d '\n')"
done
mounted=$(for n in $A $B; do rs 20 "$n" "grep -c ' $MNT mxfs ' /proc/mounts"; done | tr -d '\n')
if [ "$mounted" != "11" ]; then echo "RESULT: FAIL label=$LABEL precondition mounted=$mounted (want 11)"; exit 2; fi
rs 30 "$A" "rm -rf $D; mkdir -p $D; sync" >/dev/null

# CLOCK-ALIGNED PHASES.  An ssh round trip between the write and the read costs
# ~1 s, and two earlier versions of this harness passed clean (10 rounds
# serialised, then 20 rounds with concurrent writers) while the board row was
# failing 1 in 3 -- because coord_barrier releases both nodes within
# milliseconds and reads essentially AT the moment the peer's write lands, while
# an orchestrator round trip gives the cluster a second to become coherent.  If
# the incoherent window is short, the harness's own latency hides the defect.
#
# Both nodes are UTC-synced, so each round pins its phases to absolute wall-clock
# instants and each node runs the WHOLE round in ONE remote command: no round
# trip sits between a write and the read that must observe it.  The reads on both
# nodes therefore happen simultaneously and immediately after the writes, which
# is the rendezvous the row has.
remote_round() {  # <who> <peer> <round> <t0>
    cat <<EOF
wait_until() { while [ "\$(date +%s)" -lt "\$1" ]; do sleep 0.05; done; }
W=$1; P=$2; r=$3; T0=$4
wait_until \$T0
for i in \$(seq 1 $N); do echo v > $D/\${W}_r\${r}_f\$i; done
echo "PH created=\$(ls $D/\${W}_r\${r}_f* 2>/dev/null | wc -l)"
wait_until \$(( T0 + 2 ))
echo "PH seen_after_create=\$(ls $D/ 2>/dev/null | grep -c "_r\${r}_f")"
ls $D/ 2>/dev/null | grep "_r\${r}_f" | sort | sed 's/^/CREATE_SEEN /'
wait_until \$(( T0 + 4 ))
for i in \$(seq 1 $N); do rm -f $D/\${W}_r\${r}_f\$i; done
sync
wait_until \$(( T0 + 6 ))
echo "PH seen_after_delete=\$(ls $D/ 2>/dev/null | grep -c "_r\${r}_f")"
ls $D/ 2>/dev/null | grep "_r\${r}_f" | sort | sed 's/^/DELETE_SEEN /'
EOF
}

s=$(date +%s)
for r in $(seq 1 "$ROUNDS"); do
    rounds_run=$r
    rs 20 "$A" "echo DVIS-$LABEL-r$r > /dev/kmsg" >/dev/null
    rs 20 "$B" "echo DVIS-$LABEL-r$r > /dev/kmsg" >/dev/null
    T0=$(( $(date +%s) + 3 ))
    for who in "$A" "$B"; do
        peer=$A; [ "$who" = "$A" ] && peer=$B
        rs 40 "$who" "$(remote_round "$who" "$peer" "$r" "$T0")" > "$OUT/round_${who}_r$r.txt" &
    done
    wait
    for who in "$A" "$B"; do
        f="$OUT/round_${who}_r$r.txt"
        cseen=$(grep -a 'seen_after_create=' "$f" 2>/dev/null | head -1 | sed 's/.*seen_after_create=//')
        dseen=$(grep -a 'seen_after_delete=' "$f" 2>/dev/null | head -1 | sed 's/.*seen_after_delete=//')
        want=$(( N * 2 ))
        if [ "${cseen:-x}" != "$want" ]; then
            create_bad=$((create_bad+1)); fails=$((fails+1))
            miss=$(comm -23 <(for w in $A $B; do for i in $(seq 1 $N); do echo "${w}_r${r}_f$i"; done; done | sort) <(grep -a '^CREATE_SEEN ' "$f" | sed 's/^CREATE_SEEN //' | sort))
            echo "  FAIL round=$r CREATE-not-visible reader=$who saw=${cseen:-?} want=$want missing_count=$(echo "$miss" | grep -c .)"
            echo "$miss" | tr '\n' ' ' | cut -c1-360 | sed 's/^/      missing: /'
            echo "$miss" > "$OUT/missing_create_${who}_r$r.txt"
        fi
        if [ "${dseen:-x}" != "0" ]; then
            delete_bad=$((delete_bad+1)); fails=$((fails+1))
            echo "  FAIL round=$r DELETE-still-visible reader=$who still_sees=${dseen:-?} (both nodes ran rm THEN sync inside the same clock window)"
            grep -a '^DELETE_SEEN ' "$f" | sed 's/^DELETE_SEEN //' | tr '\n' ' ' | cut -c1-360 | sed 's/^/      lingering: /'
            grep -a '^DELETE_SEEN ' "$f" | sed 's/^DELETE_SEEN //' > "$OUT/lingering_delete_${who}_r$r.txt"
        fi
    done
done
wall=$(( $(date +%s) - s ))
echo "  DVIS-MEASURE $LABEL rounds=$rounds_run n_per_node=$N create_failures=$create_bad delete_failures=$delete_bad total_failures=$fails wall=${wall}s"
rs 30 "$A" "rm -rf $D" >/dev/null
if [ $fails = 0 ]; then
    echo "RESULT: PASS label=$LABEL rounds=$rounds_run wall=${wall}s evidence=$OUT"
else
    echo "RESULT: FAIL label=$LABEL create_failures=$create_bad delete_failures=$delete_bad rounds=$rounds_run wall=${wall}s evidence=$OUT"
fi
exit $fails
