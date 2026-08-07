#!/bin/bash
# foreign_replay_ab.sh — exercise LIVE foreign-slice replay with a real node
# kill, and measure the D-FOREIGN-REPLAY-UNGATED-IMAGES containment A/B.
# (ccloop c7ee71c6 sess32, GPT-ruled stop-ship containment, 0.11.273.)
#
# WHY THIS EXISTS
#   No criterion on the board actually drives mxfs_xlog_recover_foreign_slice:
#   crash_consistency is guest-side only (its header says a true node-KILL
#   needs host orchestration), and fence_during_write never leaves a dirty
#   slice behind.  Measured on 0.11.273: zero "foreign replay of dead slot"
#   lines across both criteria on all 32 nodes.  This harness IS that host
#   orchestration: durable workload on a victim -> virsh destroy -> wait for
#   death detection (~62s disklock) -> elected survivor live-replays the dead
#   slice -> verify + harvest.
#
# WHAT IT MEASURES (honestly, both directions)
#   - that the replay ran (survivor dmesg "foreign replay of dead slot N"),
#   - P223-FR-UNTAGGED-SKIP count (containment active: buf/dquot/icreate
#     image records skipped),
#   - post-recovery visibility of the victim's ACKED entries from a survivor:
#     found/missing dirents and file sizes.  With the containment ON, dirents
#     whose dir-block records only exist in the dead slice are EXPECTED
#     missing (the documented residual: held-at-death dir-block changes are
#     no longer live-applied); with apply=1 (legacy) they are applied through
#     the unsound cross-slice LSN gate.  BOTH numbers get reported; neither
#     arm is asserted "clean" — the point is to see the trade measured.
#
# USAGE
#   tests/foreign_replay_ab.sh <nodes> <victim_idx> [apply]
#     nodes      cluster size (e.g. 32)
#     victim_idx node to kill (2..nodes; never 1 — rank1 is the coordinator
#                and usually the elected replayer)
#     apply      value for mxfs.foreign_replay_untagged_apply on survivors:
#                0 = containment (default), 1 = legacy apply (A/B control)
#
# The victim VM is restarted at the end but NOT re-prepped/mounted; run
# MXFS_FORCE_PREP=1 ./run.sh <nodes> caw prep_cluster before the next board.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO"

N="${1:?usage: foreign_replay_ab.sh <nodes> <victim_idx> [apply]}"
V="${2:?victim index required (2..N)}"
APPLY="${3:-0}"
MNT=/mnt/shared

if [ "$V" -le 1 ] || [ "$V" -gt "$N" ]; then
    echo "victim must be 2..$N (never 1)"; exit 2
fi

TS=$(date -u +%H%M%S)
WORK=".frab_$TS"
NFILES=40
NDIRS=40
OUT=$(mktemp -d)
echo "=== foreign_replay_ab: nodes=$N victim=test$V apply=$APPLY work=$WORK out=$OUT ==="

survivors() { local i; for ((i = 1; i <= N; i++)); do [ "$i" -ne "$V" ] && echo "test$i"; done; }

# -- 1. knob on every survivor (any of them can be the elected replayer) -----
for h in $(survivors); do
    ( timeout 12 tools/mxfs_sshpass.sh "$h" \
        "echo $APPLY > /sys/module/mxfs/parameters/foreign_replay_untagged_apply" \
        </dev/null >/dev/null 2>&1 ) &
done
wait
# verify, abort on disagreement (creator_baseline_ab.sh lesson)
BAD=0
for h in $(survivors); do
    got=$(timeout 12 tools/mxfs_sshpass.sh "$h" \
        "cat /sys/module/mxfs/parameters/foreign_replay_untagged_apply" 2>/dev/null </dev/null)
    [ "$got" = "$APPLY" ] || { echo "KNOB MISMATCH $h=$got"; BAD=1; }
done
[ "$BAD" = 0 ] || exit 3
echo "--- knob foreign_replay_untagged_apply=$APPLY on $((N-1)) survivors ---"

# -- 2. mark windows ---------------------------------------------------------
for i in $(seq 1 "$N"); do
    ( timeout 12 tools/mxfs_sshpass.sh "test$i" \
        "echo 'MXFS_FRAB_WINDOW mark' > /dev/kmsg" </dev/null >/dev/null 2>&1 ) &
done
wait

# -- 3. durable workload on the victim --------------------------------------
# mkdirs + 4K files under one fresh dir, then syncfs: everything is committed
# to the victim's journal slice (and NOT necessarily at home) when we kill it.
timeout 60 tools/mxfs_sshpass.sh "test$V" "
    mkdir -p $MNT/$WORK &&
    for k in \$(seq 1 $NDIRS); do mkdir $MNT/$WORK/d\$k; done &&
    for k in \$(seq 1 $NFILES); do
        dd if=/dev/urandom of=$MNT/$WORK/f\$k bs=4096 count=1 status=none
    done &&
    sync -f $MNT &&
    echo WORKLOAD_OK" 2>/dev/null | tail -1 > "$OUT/workload"
grep -q WORKLOAD_OK "$OUT/workload" || { echo "workload FAILED on test$V"; exit 4; }
echo "--- victim committed $NDIRS dirs + $NFILES files, syncfs acked ---"

# -- 4. kill -----------------------------------------------------------------
K0=$(date +%s)
virsh -c qemu:///system destroy "test$V" >/dev/null 2>&1 || {
    echo "virsh destroy test$V failed"; exit 5; }
echo "--- test$V destroyed at t+0 ---"

# -- 5. wait for live foreign replay on any survivor -------------------------
# death detect ~62s (disklock 2s/sample threshold) + election + replay.
REPLAYER=""
VERDICT=""
for t in $(seq 1 60); do
    sleep 3
    for h in $(survivors); do
        line=$(timeout 10 tools/mxfs_sshpass.sh "$h" \
            "dmesg | awk '/MXFS_FRAB_WINDOW/{m=NR} {l[NR]=\$0} END{for(i=m+1;i<=NR;i++) print l[i]}' | grep -E 'foreign replay of (dead )?slot .* (complete|failed)' | tail -1" \
            2>/dev/null </dev/null)
        if [ -n "$line" ]; then REPLAYER="$h"; VERDICT="$line"; break 2; fi
    done
done
T_REPLAY=$(( $(date +%s) - K0 ))
if [ -z "$REPLAYER" ]; then
    echo "!!! NO foreign replay observed on any survivor within $T_REPLAY s"
    echo "    (death not detected, or replay path not reached — investigate)"
else
    echo "--- replay on $REPLAYER at t+${T_REPLAY}s: $VERDICT ---"
fi

# -- 6. harvest replay-side counters from the replayer -----------------------
if [ -n "$REPLAYER" ]; then
    timeout 15 tools/mxfs_sshpass.sh "$REPLAYER" "
        dmesg | awk '/MXFS_FRAB_WINDOW/{m=NR} {l[NR]=\$0} END{for(i=m+1;i<=NR;i++) print l[i]}' |
        grep -E 'foreign replay|P223-FR-UNTAGGED-SKIP|P227-FR-ATOMIC-SKIP|P227-TOKEN|P77-FRINODE|P163-RECOVERED|P273-SHADOW' > /tmp/frab_replayer.log
        echo P223_COUNT=\$(grep -c P223-FR-UNTAGGED-SKIP /tmp/frab_replayer.log)
        echo P227_ATOMIC_SKIP=\$(grep -c P227-FR-ATOMIC-SKIP /tmp/frab_replayer.log)
        echo P227_TOKEN_DETAIL=\$(grep -c 'P227-TOKEN ' /tmp/frab_replayer.log)
        echo P227_TOKEN_AG=\$(grep -c 'P227-TOKEN .*class=1 ' /tmp/frab_replayer.log)
        echo P227_TOKEN_SB=\$(grep -c 'P227-TOKEN .*class=2 ' /tmp/frab_replayer.log)
        echo P227_TOKEN_NONE=\$(grep -c 'P227-TOKEN .*class=0 ' /tmp/frab_replayer.log)
        echo P227_TOKENSUM=\$(grep -c P227-TOKENSUM /tmp/frab_replayer.log)
        echo P227_UNTAGGED=\$(grep -o 'untagged=[0-9]*' /tmp/frab_replayer.log | awk -F= '{s+=\$2} END{print s+0}')
        echo REPLAY_LINES=\$(grep -c 'foreign replay' /tmp/frab_replayer.log)
        echo '--- P273 shadow evaluator (sess167) ---'
        grep 'P273-SHADOW' /tmp/frab_replayer.log || echo P273_NONE" \
        2>/dev/null </dev/null | tee "$OUT/replayer_counts"
    timeout 15 tools/mxfs_sshpass.sh "$REPLAYER" \
        "cat /tmp/frab_replayer.log" 2>/dev/null </dev/null > "$OUT/replayer.log"
fi

# -- 7. post-recovery visibility from a survivor ------------------------------
# Give the deferred purge a beat after recovery-complete, then read.
sleep 10
RD=test1; [ "$V" = 1 ] && RD=test2
timeout 40 tools/mxfs_sshpass.sh "$RD" "
    d=$MNT/$WORK
    dirs=\$(ls -1 \$d 2>/dev/null | grep -c '^d')
    files=\$(ls -1 \$d 2>/dev/null | grep -c '^f')
    sz_ok=0
    for k in \$(seq 1 $NFILES); do
        s=\$(stat -c %s \$d/f\$k 2>/dev/null)
        [ \"\$s\" = 4096 ] && sz_ok=\$((sz_ok+1))
    done
    echo \"VISIBLE dirs=\$dirs/$NDIRS files=\$files/$NFILES size_ok=\$sz_ok/$NFILES\"" \
    2>/dev/null </dev/null | tail -1 | tee "$OUT/visibility"

# -- 8. restart the victim (boot only; no mount, no prep) ---------------------
virsh -c qemu:///system start "test$V" >/dev/null 2>&1
echo "--- test$V started (NOT re-prepped; run prep_cluster before the next board) ---"
echo "=== artifacts in $OUT (replayer.log, replayer_counts, visibility) ==="
