#!/bin/bash
# d0941_inode_reuse_estale.sh — drive the PROVEN root of D-0941 directly instead
# of waiting for the board row to flake into it.
#
# THE ROOT (proven sess566, evidence 20260910T012708Z_d0941_s566a/lap2_test1_kmsg.txt):
# a node that still holds an in-core inode for a number a PEER has since freed
# and reused will, on looking up the peer's new name for that number:
#
#   P103-RELOAD-REUSE-ADOPT   incore_gen != disk_gen
#   P34H-INCARN-POISON        clean shell vs cross-incarnation disk image
#   P34H-POISON-EVICT try=1..4   i_count=2 every time, no dentry alias
#   P34H-POISON-UNRETIRED     retirement failed
#   P-LKERR err=-116          -ESTALE
#
# ...and the caller sees ESTALE for a file that exists and whose dirent resolves
# correctly.  In the board row that surfaced as `ls | wc -l` under-counting the
# peer's directory by exactly the number of unretireable shells (128 -> 104, 24
# names, 24 shells).
#
# THE PRECONDITION, WHICH THE ROW ONLY REACHES BY LUCK (it fired in 1 lap of 18):
#   1. the reader has the inode IN CORE, clean, from a previous incarnation
#   2. the peer frees that number and reuses it
#   3. the reader looks the number up again under its new name
#   4. AND the reader's own INODE-CLUSTER BUFFER carries its own
#      logged-but-uncheckpointed modifications
#
# Condition 4 was missing from the first version of this harness, which ran a
# pure reader against a pure writer and passed 10 rounds clean.  It is not
# optional: the observed poison came from `src=freshsrc`, and that arm is only
# reachable when P91-RELOAD-PROTECT has already refused to stale the cluster
# buffer -- which happens exactly when THIS node has uncheckpointed mods in it.
# A reader with a clean buffer takes the ordinary path: the buffer is staled,
# re-read, and the peer's incarnation adopted without a poison.  In the board
# row both nodes create into ONE shared directory, so each node's inodes are
# co-resident in the other's cluster buffers and every node is dirty.
#
# So both nodes here are writers AND readers, symmetrically, and each round
# makes all four conditions hold on purpose: create, cross-read to force the
# prior incarnation into core, recycle the numbers, then look them up again.
#
# WHAT IT ASSERTS, and why each one is separate:
#   count   the reader sees all N of the peer's new names.  This is the row's
#           own assertion shape and catches silent under-listing.
#   stat    every one of those names stats successfully.  A name can be listed
#           and still fail to stat -- that is exactly this defect -- so counting
#           alone would report a pass while every open returns ESTALE.
#   estale  how many of the stat failures were specifically "Stale file handle".
#           Recorded separately so a different errno is not quietly folded into
#           this defect's evidence.
#
# the budget rule (derived): native XFS writes 128 small files in well under a second; the
# four phases of a round are 2 creates, 1 read sweep, 1 delete+recreate and 1
# stat sweep of N files each, so a round is ~4 x (2 x native) plus four ssh round
# trips at ~0.4 s => the per-ssh bound is 25 s and a round is budgeted 60 s.  A
# round that exceeds it is a FAILURE and is recorded as one, never re-run wider.
#
# Usage: tests/d0941_inode_reuse_estale.sh <label> [ROUNDS=10] [N=128]
# Env:   MXFS_NODE_LIST (default test1,test2), MNT (default /mnt/shared)
set -u
LABEL=${1:?label}
ROUNDS=${2:-10}
N=${3:-128}
cd "$(dirname "$0")/.." || exit 2

export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
A=${MXFS_NODE_LIST%%,*}          # both nodes are writers AND readers, symmetrically:
B=${MXFS_NODE_LIST##*,}          # a pure reader has a clean cluster buffer and cannot reach the fault
SSH=tools/mxfs_sshpass.sh
MNT=${MNT:-/mnt/shared}
D=$MNT/d0941_$LABEL
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_d0941reuse_$LABEL
mkdir -p "$OUT"

filt() { grep -av '^Unauthorized\|^Warning:\|^If you\|^$'; }
rs() { timeout "$1" $SSH "$2" "$3" 2>/dev/null | filt; }

SV=$(modinfo mxfs.ko 2>/dev/null | sed -n 's/^srcversion: *//p')
echo "=== d0941_inode_reuse_estale label=$LABEL nodes=$A,$B rounds=$ROUNDS n=$N sv=$SV $(date -u +%FT%TZ) ==="

# Precondition.  A lap run against a stale module measures the previous build,
# and its evidence is a lie about which code produced it.
bad=0
for n in $A $B; do
    info=$(rs 25 "$n" "echo sv=\$(cat /sys/module/mxfs/srcversion 2>/dev/null) mounted=\$(grep -c ' $MNT mxfs ' /proc/mounts)")
    echo "  INFO $n $info"
    echo "$info" | grep -q "sv=$SV"  || { echo "  PRECOND $n srcversion != tree ($SV)"; bad=1; }
    echo "$info" | grep -q "mounted=1" || { echo "  PRECOND $n not mounted"; bad=1; }
done
[ "$bad" = 0 ] || { echo "RESULT: INFRA label=$LABEL precondition not met"; exit 2; }

rs 30 "$A" "rm -rf $D; mkdir -p $D; sync" >/dev/null

fails=0
rounds_run=0
# Both nodes run every phase CONCURRENTLY (backgrounded ssh, then wait), with
# the orchestrator as the barrier between phases.  Symmetry is the point: each
# node must be dirty in the cluster buffers that hold the peer's inodes, which
# a serialised writer/reader split cannot produce.
phase() {   # <bound> <label> <cmd-for-A> <cmd-for-B>  -> writes $OUT/<label>_<node>
    local b=$1 lbl=$2 ca=$3 cb=$4
    ( rs "$b" "$A" "$ca" > "$OUT/${lbl}_$A" 2>&1 ) &
    local pa=$!
    ( rs "$b" "$B" "$cb" > "$OUT/${lbl}_$B" 2>&1 ) &
    local pb=$!
    wait $pa; wait $pb
}

for r in $(seq 1 "$ROUNDS"); do
    rounds_run=$r
    mark="D0941R-$LABEL-r$r"
    for n in $A $B; do rs 20 "$n" "echo $mark > /dev/kmsg" >/dev/null; done
    t0=$(date +%s)

    # 1. both nodes create the FIRST incarnation of N inode numbers each, into
    #    ONE shared directory, so the two sets interleave in the same clusters.
    mk='for i in $(seq 1 '"$N"'); do echo x > '"$D"'/@WHO@_r'"$r"'_a_$i; done; sync'
    phase 25 "r${r}p1" "${mk//@WHO@/$A}" "${mk//@WHO@/$B}"

    # 2. each node reads EVERY file, its own and the peer's, forcing the peer's
    #    current incarnation into core.  Without this the shell that later gets
    #    poisoned may simply not exist.
    rd='for f in '"$D"'/*_r'"$r"'_a_*; do cat "$f" >/dev/null 2>&1; done; ls '"$D"'/ | grep -c "_r'"$r"'_a_"'
    phase 25 "r${r}p2" "$rd" "$rd"

    # 3. each node frees ITS OWN set and immediately creates a new one, which
    #    recycles those inode numbers under different names and generations
    #    while the peer still holds the old incarnation in core.
    rc='for i in $(seq 1 '"$N"'); do rm -f '"$D"'/@WHO@_r'"$r"'_a_$i; done; sync; for i in $(seq 1 '"$N"'); do echo y > '"$D"'/@WHO@_r'"$r"'_b_$i; done; sync'
    phase 25 "r${r}p3" "${rc//@WHO@/$A}" "${rc//@WHO@/$B}"

    # 4. each node looks up ALL the recycled numbers under their new names.
    #    Count and stat are asked separately: a name that lists but cannot be
    #    stat'd is precisely this defect, and counting alone would call it a pass.
    vf='n=$(ls '"$D"'/ 2>/dev/null | grep -c "_r'"$r"'_b_"); errs=0; estale=0; for f in '"$D"'/*_r'"$r"'_b_*; do e=$(stat "$f" 2>&1 >/dev/null); if [ -n "$e" ]; then errs=$((errs+1)); case "$e" in *[Ss]tale*) estale=$((estale+1));; esac; fi; done; echo "listed=$n errs=$errs estale=$estale"'
    phase 25 "r${r}p4" "$vf" "$vf"

    wall=$(( $(date +%s) - t0 ))
    want=$(( N * 2 ))
    bad_round=0
    line="round=$r"
    for n in $A $B; do
        res=$(cat "$OUT/r${r}p4_$n" 2>/dev/null)
        cached=$(cat "$OUT/r${r}p2_$n" 2>/dev/null | tr -dc '0-9')
        listed=$(echo "$res" | sed -n 's/.*listed=\([0-9]*\).*/\1/p')
        errs=$(echo   "$res" | sed -n 's/.*errs=\([0-9]*\).*/\1/p')
        estale=$(echo "$res" | sed -n 's/.*estale=\([0-9]*\).*/\1/p')
        [ -n "$listed" ] || listed=-1
        [ -n "$errs" ]   || errs=-1
        [ -n "$estale" ] || estale=-1
        [ "$listed" = "$want" ] || bad_round=1
        [ "$errs" = 0 ]         || bad_round=1
        line="$line | $n cached=${cached:-?} listed=$listed/$want errs=$errs estale=$estale"
    done
    [ "$wall" -le 60 ] || bad_round=1        # budget: a timeout IS a failure
    [ "$bad_round" = 0 ] || fails=$((fails+1))
    echo "$line wall=${wall}s $([ $bad_round = 0 ] && echo OK || echo BAD)" | tee -a "$OUT/rounds.txt"

    if [ "$bad_round" != 0 ]; then
        for n in $A $B; do
            rs 45 "$n" "dmesg | awk '/$mark/{f=1} f'" > "$OUT/round${r}_${n}_kmsg.txt" 2>/dev/null
            k="$OUT/round${r}_${n}_kmsg.txt"
            echo "    $n poison=$(grep -ac 'P34H-INCARN-POISON' "$k") evict=$(grep -ac 'P34H-POISON-EVICT' "$k") unretired=$(grep -ac 'P34H-POISON-UNRETIRED' "$k") lkerr116=$(grep -a 'P-LKERR' "$k" | grep -ac 'err=-116') drainwait=$(grep -ac 'P566-POISON-DRAINWAIT' "$k") grabst=$(grep -ac 'P566-GRABST' "$k") protect=$(grep -ac 'P91-RELOAD-PROTECT' "$k")" \
                | tee -a "$OUT/rounds.txt"
        done
    fi
done

echo "RESULT: label=$LABEL rounds=$rounds_run fails=$fails n=$N sv=$SV evidence=$OUT"
[ "$fails" = 0 ]
