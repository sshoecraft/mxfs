#!/bin/bash
# tests/incarn_reuse_lookup_stress.sh <label> <legacy 0|1> [secs]
#
# Natural (no injection) exerciser for
# D-TCP-INCARN-REVOKE-WORKER-IRELE-HITS-IPUT-BUG-NODE-PANIC.
#
# The field path: a lookup on one node resolves a dirent to an inode number the
# peer has just freed (the iget miss path reads FREE and runs its coordinated
# reload), the cluster buffer is protected by this node's own logged changes to
# a co-resident inode, the fresh read shows the peer's NEW incarnation of that
# number, and the clean uninserted shell is poisoned.  So:
#   test1  churns create+unlink of the same names in one directory, reusing
#          inode numbers in the same chunk;
#   test2  concurrently stats every name (lookups racing the unlinks) and
#          touches whichever exist (logged changes to co-resident inodes).
#
# legacy=1 sets poison_uninserted_legacy (the pre-0.89.75 behaviour) on both
# nodes: a natural P-POISON-UNINSERTED followed by P-REVOKE-DIRECT-FREE or a
# panic proves the field path.  legacy=0 is the fix: the same poisonings must
# show no direct free with a revocation outstanding, no P-REVOKE-*, no panic.
#
# Verdicts: PROVEN (legacy arm: natural direct-free or panic), CLEAN (fixed
# arm: natural uninserted poisonings > 0 and nothing else), VACUOUS (no natural
# uninserted poisoning occurred — the race was never met), FAIL otherwise.
#
# derived time budgets: prep 400 s (tests/dirent_durability_loop.sh's bound for
# the same 2/tcp prep); the workload runs SECS (default 120) on each node and
# is bounded at SECS+60 s; evidence pulls 40 s per node.
set -u
cd /src/mxfs || exit 2
LABEL=${1:?label}
LEGACY=${2:?legacy 0|1}
SECS=${3:-120}
NC=tests/evidence/netconsole.log
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_irls_$LABEL
mkdir -p "$OUT"
SSH=tools/mxfs_sshpass.sh
nc_mark=$(wc -l < "$NC" 2>/dev/null || echo 0)
echo "=== irls $LABEL START $(date -u +%FT%TZ) VERSION=$(cat VERSION) sv=$(modinfo -F srcversion mxfs.ko) legacy=$LEGACY secs=$SECS out=$OUT netconsole_from_line=$nc_mark ==="

timeout 400 ./run.sh 2 tcp prep_cluster > "$OUT/prep.log" 2>&1 \
    || { echo "RESULT: ABORT label=$LABEL stage=prep evidence=$OUT"; exit 2; }

D=/mnt/shared/irls.$LABEL
timeout 30 "$SSH" test1 "rm -rf $D; mkdir -p $D && sync" > /dev/null 2>&1 \
    || { echo "RESULT: ABORT label=$LABEL stage=mkdir evidence=$OUT"; exit 2; }

for n in test1 test2; do
    timeout 20 "$SSH" "$n" "echo $LEGACY > /sys/module/mxfs/parameters/poison_uninserted_legacy; echo IRLS-MARK-$LABEL > /dev/kmsg" > /dev/null 2>&1
done

cat > "$OUT/churn.sh" <<EOF
end=\$((\$(date +%s) + $SECS)); r=0
while [ \$(date +%s) -lt \$end ]; do
    for i in \$(seq 0 31); do echo \$r > $D/f\$i; done
    for i in \$(seq 0 31); do rm -f $D/f\$i; done
    r=\$((r + 1))
done
echo "churn rounds=\$r"
EOF
cat > "$OUT/lookup.sh" <<EOF
end=\$((\$(date +%s) + $SECS)); r=0
while [ \$(date +%s) -lt \$end ]; do
    for i in \$(seq 0 31); do
        stat $D/f\$i > /dev/null 2>&1 && touch -c $D/f\$i 2>/dev/null
    done
    # Evict the unused shells so later lookups take the iget MISS path
    # rather than hitting (or recycling) a cached inode.
    echo 2 > /proc/sys/vm/drop_caches
    r=\$((r + 1))
done
echo "lookup rounds=\$r"
EOF

timeout $((SECS + 60)) "$SSH" test1 "bash -s" < "$OUT/churn.sh" > "$OUT/test1_work.out" 2>&1 &
p1=$!
timeout $((SECS + 60)) "$SSH" test2 "bash -s" < "$OUT/lookup.sh" > "$OUT/test2_work.out" 2>&1 &
p2=$!
wait $p1; rc1=$?
wait $p2; rc2=$?

sleep 3
tot_unins=0; tot_df=0; tot_other=0; mounted=0
for n in test1 test2; do
    timeout 40 "$SSH" "$n" "echo 0 > /sys/module/mxfs/parameters/poison_uninserted_legacy; grep -c ' /mnt/shared mxfs ' /proc/mounts; dmesg | sed -n '/IRLS-MARK-$LABEL/,\$p'" > "$OUT/${n}_dmesg.txt" 2>/dev/null
    m=$(head -1 "$OUT/${n}_dmesg.txt"); [ "$m" = 1 ] && mounted=$((mounted + 1))
    u=$(grep -ac 'P-POISON-UNINSERTED' "$OUT/${n}_dmesg.txt")
    df=$(grep -ac 'P-REVOKE-DIRECT-FREE' "$OUT/${n}_dmesg.txt")
    ot=$(grep -ac 'P-REVOKE-REF-LOST\|P-REVOKE-EVICT-EARLY' "$OUT/${n}_dmesg.txt")
    pn=$(grep -ac 'P566-POISON-N' "$OUT/${n}_dmesg.txt")
    miss=$(grep -ac 'P127-IGET-COORD\|P-TCP-VERIFY-COORD' "$OUT/${n}_dmesg.txt")
    echo "$n miss_path_reloads=$miss"
    echo "$n rc=$([ $n = test1 ] && echo $rc1 || echo $rc2) mounted=$m poison_n=$pn uninserted=$u direct_free=$df other_revoke_probes=$ot $(tail -1 "$OUT/${n}_work.out")"
    grep -a -m2 'P-POISON-UNINSERTED' "$OUT/${n}_dmesg.txt" | cut -c1-260
    tot_unins=$((tot_unins + u)); tot_df=$((tot_df + df)); tot_other=$((tot_other + ot))
done
tail -n +"$((nc_mark + 1))" "$NC" > "$OUT/netconsole_window.txt"
panics=$(grep -ac 'invalid opcode\|Kernel panic\|BUG:\|Oops' "$OUT/netconsole_window.txt")
grep -a -m6 'BUG:\|invalid opcode\|RIP:\|Workqueue:\|Kernel panic' "$OUT/netconsole_window.txt" | cut -c1-200
echo "totals legacy=$LEGACY uninserted=$tot_unins direct_free=$tot_df other_revoke_probes=$tot_other panics=$panics mounted=$mounted/2"

if [ "$LEGACY" = 1 ] && { [ "$tot_df" -gt 0 ] || [ "$panics" -gt 0 ]; }; then
    echo "RESULT: PROVEN label=$LABEL evidence=$OUT"; exit 0
fi
if [ "$tot_unins" = 0 ] && [ "$panics" = 0 ]; then
    echo "RESULT: VACUOUS label=$LABEL — no natural uninserted poisoning evidence=$OUT"; exit 1
fi
if [ "$LEGACY" = 0 ] && [ "$tot_df" = 0 ] && [ "$tot_other" = 0 ] && [ "$panics" = 0 ] && [ "$mounted" = 2 ]; then
    echo "RESULT: CLEAN label=$LABEL uninserted=$tot_unins evidence=$OUT"; exit 0
fi
echo "RESULT: FAIL label=$LABEL evidence=$OUT"; exit 1
