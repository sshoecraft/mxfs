#!/bin/bash
# d513_refusal_containment.sh — D-513 phase-A containment check (Q7 rig plan,
# sess325/sess328/sess333 rulings): force a foreign-replay REFUSAL via the
# one-shot freplay_force_refusal knob, kill one victim, and assert the
# containment machinery works end-to-end WITHOUT the cluster-wide suicide that
# defines D-FOREIGN-REPLAY-REFUSAL-CLUSTERWIDE-SUICIDE-513:
#
#   1. exactly one survivor (the elected replayer) refuses the replay and
#      durably publishes the TERMINAL_REFUSED outcome,
#   2. survivors import the quarantine (P240-QUAR-IMPORT) and latch the slot,
#   3. the victim slot is terminal, NOT "replayed": no recovery-complete purge
#      of its heartbeat sector,
#   4. ZERO forced shutdowns / withdrawals on survivors (quiescent test -> the
#      sess328 Q3 threshold is exactly zero),
#   5. all survivors still have /mnt/shared mounted at the end.
#
# Usage: tests/d513_refusal_containment.sh <N> <victim> [shape]
#   N      node count (test1..testN); knob armed on all survivors
#   victim hostname to virsh destroy (must be within test1..testN, not test1)
#   shape  freplay_force_refusal shape (default 1 = POLICY refusal, AG-mask ag0;
#          2 = POLICY fswide, 3 = TORN forged post-success, 4 = genuine
#          mid-replay TORN)
#
# The test leaves the FS with a durable quarantine on the victim's slice
# domain — re-prep the cluster (./run.sh N caw prep_cluster) before any other
# board test.  Exit 0 = all assertions PASS.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"

N="${1:?usage: d513_refusal_containment.sh <N> <victim> [shape]}"
VICTIM="${2:?usage: d513_refusal_containment.sh <N> <victim> [shape]}"
SHAPE="${3:-1}"
MNT=/mnt/shared
# HB confirm window ~62s + fence + replay(1-3s) + publish + import lap slack.
RECOVERY_WAIT="${RECOVERY_WAIT:-150}"

[ "$VICTIM" = "test1" ] && { echo "FAIL: test1 is the probe node, pick another victim"; exit 1; }

T0=$(date -u +%FT%TZ)
echo "=== d513_refusal_containment: N=$N victim=$VICTIM shape=$SHAPE @ $T0 ==="

survivors=()
for i in $(seq 1 "$N"); do
    h="test$i"
    [ "$h" = "$VICTIM" ] || survivors+=("$h")
done

# 1. Arm the one-shot knob on every survivor (only the elected replayer will
#    consume it; the rest are disarmed in step 6).  slot=-1 = first replay
#    attempted, which in this quiescent single-victim test is the victim's.
echo "--- arming freplay_force_refusal=$SHAPE on ${#survivors[@]} survivors"
for h in "${survivors[@]}"; do
    "$SSH" "$h" "echo $SHAPE > /sys/module/mxfs/parameters/freplay_force_refusal;
                 echo -1 > /sys/module/mxfs/parameters/freplay_force_slot;
                 echo ${TORN_ITEMS:-8} > /sys/module/mxfs/parameters/freplay_force_torn_items;
                 dmesg --clear" >/dev/null 2>&1 &
done
wait
armed=0
for h in "${survivors[@]}"; do
    v=$("$SSH" "$h" "cat /sys/module/mxfs/parameters/freplay_force_refusal" 2>/dev/null | tail -1 | tr -d '[:space:]')
    [ "$v" = "$SHAPE" ] && armed=$((armed+1))
done
if [ "$armed" -ne "${#survivors[@]}" ]; then
    echo "FAIL: knob armed on $armed/${#survivors[@]} survivors — aborting, no kill issued"
    exit 1
fi
echo "knob CONFIRMED armed on all $armed survivors"

# 1b. Optional victim write load (VICTIM_LOAD=seconds, default 0=quiescent).
#     Shape 4 (genuine mid-replay TORN) REQUIRES a dirty victim slice at death:
#     a quiescent victim replays state=no_txns and the injection point is never
#     reached (proven sess336).  The loop is pure metadata churn (create/
#     rename/unlink) with no final sync, so log items are in the victim's
#     slice when it dies mid-loop.
if [ "${VICTIM_LOAD:-0}" -gt 0 ]; then
    MODE="${VICTIM_LOAD_MODE:-churn}"
    echo "--- starting ${VICTIM_LOAD}s $MODE load on $VICTIM"
    if [ "$MODE" = "inode" ]; then
        # Pure inode-item transactions (shape 4 needs an APPLIED prefix):
        # create/rename/unlink log BUF+ICREATE items and every such
        # transaction is ATOMIC-SKIP'd at foreign replay (proven this
        # session), so the shape-4 countdown never decrements.  Timestamp
        # updates on PREEXISTING files log only XFS_LI_INODE items, which
        # pass the taint scan and genuinely apply through the
        # di_changecount gate.  Prepopulate + sync first so the tainted
        # create transactions are stable, then touch+sync in a loop so the
        # victim dies with committed unapplied inode items in its slice.
        "$SSH" "$VICTIM" "D=$MNT/.d513load; mkdir -p \$D;
            for i in \$(seq 1 64); do echo seed > \$D/t\$i; done; sync" >/dev/null 2>&1
        "$SSH" "$VICTIM" "nohup bash -c '
            D=$MNT/.d513load
            end=\$((SECONDS + ${VICTIM_LOAD} + 30))
            while [ \$SECONDS -lt \$end ]; do
                touch \$D/t{1..64}
                sync
            done
        ' >/tmp/d513load.log 2>&1 &" >/dev/null 2>&1
    else
        "$SSH" "$VICTIM" "nohup bash -c '
        D=$MNT/.d513load
        mkdir -p \$D
        end=\$((SECONDS + ${VICTIM_LOAD} + 30))
        i=0
        while [ \$SECONDS -lt \$end ]; do
            i=\$((i+1))
            echo payload-\$i > \$D/f\$i
            mv \$D/f\$i \$D/g\$i
            [ \$((i % 8)) -eq 0 ] && rm -f \$D/g\$((i-4))
        done
    ' >/tmp/d513load.log 2>&1 &" >/dev/null 2>&1
    fi
    sleep "$VICTIM_LOAD"
    # Confirm the load is real before killing (visible from the probe node).
    lcnt=$("$SSH" test1 "ls $MNT/.d513load 2>/dev/null | wc -l" 2>/dev/null | tail -1 | tr -d '[:space:]')
    echo "victim load confirmed: ${lcnt:-0} files visible from test1"
    [ "${lcnt:-0}" -gt 0 ] || { echo "FAIL: victim load never landed"; exit 1; }
fi

# 2. Kill the victim.
date -u "+KILL $VICTIM @ %FT%TZ"
sudo virsh -c qemu:///system destroy "$VICTIM" || { echo "FAIL: virsh destroy $VICTIM"; exit 1; }

# 3. Wait out fence + recovery + publish + import propagation.
echo "waiting ${RECOVERY_WAIT}s for fence+refusal+publish+import..."
sleep "$RECOVERY_WAIT"

# 4. Harvest survivor dmesg (cleared at arm time, so everything is this test's).
D=$(mktemp -d)
for h in "${survivors[@]}"; do
    "$SSH" "$h" "dmesg" > "$D/$h.dmesg" 2>/dev/null &
done
wait

pass=1
refusers=$(grep -l "slice replay refused" "$D"/*.dmesg 2>/dev/null | wc -l)
publishes=$(grep -h "terminal outcome PUBLISHED" "$D"/*.dmesg 2>/dev/null | wc -l)
importers=$(grep -l "P240-QUAR-IMPORT" "$D"/*.dmesg 2>/dev/null | wc -l)
recovered_pub=$(grep -h "published as recovered\|slice recovery complete" "$D"/*.dmesg 2>/dev/null | wc -l)
shutdowns=$(grep -l "Filesystem has been shut down\|forced shutdown\|MXFS.*withdraw" "$D"/*.dmesg 2>/dev/null | wc -l)

echo "--- assertions"
echo "refusing replayers (want 1): $refusers"
[ "$refusers" -eq 1 ] || { echo "FAIL: expected exactly 1 refusing replayer"; pass=0; }
echo "terminal publishes (want >=1): $publishes"
[ "$publishes" -ge 1 ] || { echo "FAIL: refusal was never published"; pass=0; }
echo "importing survivors (want >=$(( ${#survivors[@]} - 1 ))): $importers"
[ "$importers" -ge $(( ${#survivors[@]} - 1 )) ] || { echo "FAIL: quarantine import did not propagate"; pass=0; }
echo "slot published-as-recovered lines (want 0): $recovered_pub"
[ "$recovered_pub" -eq 0 ] || { echo "FAIL: refused slice was published as recovered"; pass=0; }
echo "survivors with shutdown/withdraw (want 0): $shutdowns"
if [ "$shutdowns" -ne 0 ]; then
    echo "FAIL: survivor shutdowns — the D-513 suicide"
    grep -l "Filesystem has been shut down\|forced shutdown\|MXFS.*withdraw" "$D"/*.dmesg
    pass=0
fi

# 5. Every survivor still mounted.
mounted=0
for h in "${survivors[@]}"; do
    m=$("$SSH" "$h" "mount | grep -c 'on $MNT type mxfs'" 2>/dev/null | tail -1 | tr -d '[:space:]')
    [ "${m:-0}" -ge 1 ] && mounted=$((mounted+1))
done
echo "survivors still mounted (want ${#survivors[@]}): $mounted"
[ "$mounted" -eq "${#survivors[@]}" ] || { echo "FAIL: survivor lost its mount"; pass=0; }

# 6. Disarm the knob on every survivor (one-shot consumed only on the replayer).
for h in "${survivors[@]}"; do
    "$SSH" "$h" "echo 0 > /sys/module/mxfs/parameters/freplay_force_refusal;
                 echo -1 > /sys/module/mxfs/parameters/freplay_force_slot" >/dev/null 2>&1 &
done
wait

echo "--- refusal/publish/import detail (replayer + first importer)"
grep -h "slice replay refused\|terminal outcome PUBLISHED" "$D"/*.dmesg | head -5
grep -h "P240-QUAR-IMPORT" "$D"/*.dmesg | head -3
grep -h "terminal verdict durable" "$D"/*.dmesg | head -3

echo "dmesg harvest kept in $D"
if [ "$pass" -eq 1 ]; then
    echo "=== d513_refusal_containment PASS (shape=$SHAPE) @ $(date -u +%FT%TZ) ==="
    exit 0
fi
echo "=== d513_refusal_containment FAIL (shape=$SHAPE) @ $(date -u +%FT%TZ) ==="
exit 1
