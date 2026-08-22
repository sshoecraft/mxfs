#!/bin/bash
# closure_multivictim.sh — sess363 ruling Hazards-§7: "a slot carrying MULTIPLE
# victims", for the out-of-closure purge (D-REFUSAL-GRANT-FREEZE-OUT-OF-
# CLOSURE-356).
#
# THE RULE BEING TESTED (ruling item A): "ONE victim per invocation
# (dead_mask == BIT(victim)); a victim's gate never authorizes stripping
# another node's bits (multi-victim slots: independent gate+classify per
# victim)."
#
# By construction the strip touches exactly `1ULL << victim_slot` and commits
# with a full-image compare-and-write, so another victim's bit cannot be
# cleared as a side effect.  That is an argument, not evidence.  This produces
# evidence: TWO nodes are made to hold shared (PR) grants on the SAME
# resources, both are killed at once, and exactly ONE of them is forced into a
# terminal refusal.  If the refused victim's purge had over-reached and wiped
# the other victim's bits, the other victim's OWN recovery would have nothing
# left to work with; instead it must replay and complete normally.  So the
# discriminating observable is:
#
#   * exactly one P299-CLOSURE-SCAN ENTRY, naming the REFUSED victim's slot;
#   * the OTHER victim's slice is recovered normally (its heartbeat sector is
#     zeroed — the cluster-wide "replay done" broadcast), which cannot happen
#     if its authority manifest was destroyed;
#   * the refused victim's slot is NEVER published as recovered;
#   * nobody shuts down, and a survivor blocked on the refused victim's
#     out-of-closure root grant is released.
#
# Usage: tests/closure_multivictim.sh <N> <refused_victim> <other_victim>
# Env: PROBE_HOST (default test1), RECOVERY_WAIT (default 210 — two recoveries
#      serialize behind one heartbeat confirm window), VICTIM_LOAD (default 6).
#
# Leaves a durable quarantine — re-prep before anything else.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"

N="${1:?usage: closure_multivictim.sh <N> <refused_victim> <other_victim>}"
V1="${2:?usage: closure_multivictim.sh <N> <refused_victim> <other_victim>}"
V2="${3:?usage: closure_multivictim.sh <N> <refused_victim> <other_victim>}"
PROBE_HOST="${PROBE_HOST:-test1}"
MNT=/mnt/shared
AGMASK=0x2
RECOVERY_WAIT="${RECOVERY_WAIT:-210}"
VICTIM_LOAD="${VICTIM_LOAD:-6}"

[ "$V1" = "$V2" ] && { echo "FAIL: the two victims must differ"; exit 1; }
for v in "$V1" "$V2"; do
    [ "$v" = "$PROBE_HOST" ] && { echo "FAIL: $v is the probe host — set PROBE_HOST"; exit 1; }
done

T0=$(date -u +%FT%TZ)
echo "=== closure_multivictim: N=$N refused=$V1 other=$V2 probe=$PROBE_HOST @ $T0 ==="

survivors=()
for i in $(seq 1 "$N"); do
    h="test$i"
    [ "$h" = "$V1" ] || [ "$h" = "$V2" ] || survivors+=("$h")
done

# 1. Resolve the refused victim's heartbeat slot, so the one-shot refusal is
#    aimed rather than "whichever replay happens first" — with two deaths the
#    -1 form is a coin toss and the test would not be reproducible.
V1SLOT=$("$SSH" "$V1" "dmesg | grep -oE 'node_slot=[0-9]+' | tail -1" 2>/dev/null |
         tr -d '[:space:]' | cut -d= -f2)
V2SLOT=$("$SSH" "$V2" "dmesg | grep -oE 'node_slot=[0-9]+' | tail -1" 2>/dev/null |
         tr -d '[:space:]' | cut -d= -f2)
[ -n "${V1SLOT:-}" ] && [ -n "${V2SLOT:-}" ] || { echo "FAIL: could not resolve victim slots (V1=${V1SLOT:-?} V2=${V2SLOT:-?})"; exit 1; }
[ "$V1SLOT" != "$V2SLOT" ] || { echo "FAIL: both victims report slot $V1SLOT"; exit 1; }
echo "slots: $V1=$V1SLOT (to be refused)  $V2=$V2SLOT (must recover normally)"

# 2. Arm the refusal on the survivors, AIMED at V1's slot.
echo "--- arming freplay_force_refusal=1 slot=$V1SLOT ag_mask=$AGMASK on ${#survivors[@]} survivors"
for h in "${survivors[@]}"; do
    "$SSH" "$h" "echo $AGMASK > /sys/module/mxfs/parameters/freplay_force_ag_mask;
                 echo $V1SLOT > /sys/module/mxfs/parameters/freplay_force_slot;
                 echo 1 > /sys/module/mxfs/parameters/freplay_force_refusal;
                 dmesg --clear" >/dev/null 2>&1 &
done
wait
armed=0
for h in "${survivors[@]}"; do
    v=$("$SSH" "$h" "cat /sys/module/mxfs/parameters/freplay_force_refusal;
                     cat /sys/module/mxfs/parameters/freplay_force_slot" 2>/dev/null \
        | tr '\n' ' ' | tr -d '[:space:]')
    [ "$v" = "1$V1SLOT" ] && armed=$((armed+1))
done
[ "$armed" -eq "${#survivors[@]}" ] || {
    echo "FAIL: armed on $armed/${#survivors[@]} survivors — aborting, no kill issued"; exit 1; }
echo "refusal CONFIRMED armed on all $armed survivors"

# 3. Make BOTH victims co-resident on the same resources.  A shared read of the
#    root directory puts both of their bits in the same slot's holders_pr —
#    which is exactly the multi-victim slot the ruling is about.  V1 also runs
#    un-synced churn so it dies with a dirty slice and a hot root EX.
echo "--- both victims take shared grants on the same resources"
for v in "$V1" "$V2"; do
    "$SSH" "$v" "ls -a $MNT >/dev/null 2>&1; cat $MNT/.. >/dev/null 2>&1; true" >/dev/null 2>&1 &
done
wait
"$SSH" "$V1" "nohup bash -c '
    end=\$((SECONDS + ${VICTIM_LOAD} + 120))
    i=0
    while [ \$SECONDS -lt \$end ]; do
        i=\$((i+1))
        echo hot > $MNT/.cmv-v1.\$i
        rm -f $MNT/.cmv-v1.\$((i-3))
    done
' >/tmp/cmvload.log 2>&1 &" >/dev/null 2>&1
"$SSH" "$V2" "nohup bash -c '
    end=\$((SECONDS + ${VICTIM_LOAD} + 120))
    while [ \$SECONDS -lt \$end ]; do ls -a $MNT >/dev/null 2>&1; done
' >/tmp/cmvread.log 2>&1 &" >/dev/null 2>&1
sleep "$VICTIM_LOAD"
lcnt=$("$SSH" "$PROBE_HOST" "ls -a $MNT/ 2>/dev/null | grep -c cmv-v1" 2>/dev/null | tail -1 | tr -d '[:space:]')
[ "${lcnt:-0}" -gt 0 ] || { echo "FAIL: victim load never landed"; exit 1; }
echo "co-residency established (${lcnt} churn files visible)"

# 4. Kill BOTH at once.
date -u "+KILL $V1 + $V2 @ %FT%TZ"
sudo virsh -c qemu:///system destroy "$V1" || { echo "FAIL: virsh destroy $V1"; exit 1; }
sudo virsh -c qemu:///system destroy "$V2" || { echo "FAIL: virsh destroy $V2"; exit 1; }

BLOCK_BUDGET=$(( RECOVERY_WAIT + 60 ))
"$SSH" "$PROBE_HOST" "nohup bash -c '
    s=\$(date +%s)
    timeout $BLOCK_BUDGET touch $MNT/.cmv-blocked; rc=\$?
    echo \"BLOCKED_PROBE rc=\$rc elapsed=\$((\$(date +%s) - s))\" > /tmp/cmvprobe.out
' >/dev/null 2>&1 &" >/dev/null 2>&1
echo "blocked prober launched on $PROBE_HOST (budget ${BLOCK_BUDGET}s)"

echo "waiting ${RECOVERY_WAIT}s for two fences + both recoveries..."
sleep "$RECOVERY_WAIT"

bp=$("$SSH" "$PROBE_HOST" "cat /tmp/cmvprobe.out 2>/dev/null" 2>/dev/null | tr -d '\r' | grep BLOCKED_PROBE | tail -1)
bp_rc=$(echo "$bp" | grep -o 'rc=[0-9]*' | cut -d= -f2)
bp_s=$(echo "$bp" | grep -o 'elapsed=[0-9]*' | cut -d= -f2)
echo "--- blocked prober: ${bp:-<still running>}"

D=$(mktemp -d)
for h in "${survivors[@]}"; do
    "$SSH" "$h" "dmesg" > "$D/$h.dmesg" 2>/dev/null &
done
wait
for h in "${survivors[@]}"; do
    "$SSH" "$h" "echo 0 > /sys/module/mxfs/parameters/freplay_force_refusal;
                 echo 1 > /sys/module/mxfs/parameters/freplay_force_ag_mask;
                 echo -1 > /sys/module/mxfs/parameters/freplay_force_slot" >/dev/null 2>&1 &
done
wait

pass=1
scans=$(grep -h "P299-CLOSURE-SCAN ENTRY" "$D"/*.dmesg 2>/dev/null)
scan_n=$(echo "$scans" | grep -c "victim_slot=" || true)
scan_v1=$(echo "$scans" | grep -c "victim_slot=$V1SLOT " || true)
scan_v2=$(echo "$scans" | grep -c "victim_slot=$V2SLOT " || true)
refused_v1=$(grep -h "slice replay refused" "$D"/*.dmesg 2>/dev/null | grep -c "slot=$V1SLOT:" || true)
refused_v2=$(grep -h "slice replay refused" "$D"/*.dmesg 2>/dev/null | grep -c "slot=$V2SLOT:" || true)
# The "replay done" broadcast for a slot: its heartbeat sector was zeroed.
done_v2=$(grep -h "P163-RECOVERED\|slice recovery complete\|published as recovered" "$D"/*.dmesg 2>/dev/null | grep -c "slot=$V2SLOT\b" || true)
shutdowns=$(grep -l "Filesystem has been shut down\|forced shutdown\|MXFS.*withdraw" "$D"/*.dmesg 2>/dev/null | wc -l)
strips=$(grep -h "P299-CLOSURE-STRIP\|P299-SCRUB-STRIP" "$D"/*.dmesg 2>/dev/null | wc -l)
strip_wrong=$(grep -h "P299-CLOSURE-STRIP\|P299-SCRUB-STRIP" "$D"/*.dmesg 2>/dev/null | grep -c "victim_slot=$V2SLOT\b" || true)

echo "--- assertions"
echo "closure scans (want exactly 1, naming slot $V1SLOT): total=$scan_n v1=$scan_v1 v2=$scan_v2"
[ "$scan_v1" -ge 1 ] || { echo "FAIL: no closure scan for the refused victim"; pass=0; }
[ "$scan_v2" -eq 0 ] || { echo "FAIL: a closure scan ran for the OTHER victim — one victim per invocation is violated"; pass=0; }
echo "refusals (want v1=1 v2=0): v1=$refused_v1 v2=$refused_v2"
[ "$refused_v1" -ge 1 ] || { echo "FAIL: the aimed refusal did not fire on slot $V1SLOT"; pass=0; }
[ "$refused_v2" -eq 0 ] || { echo "FAIL: the OTHER victim was also refused — the test cannot discriminate"; pass=0; }
echo "strips attributed to the other victim (want 0): $strip_wrong of $strips total"
[ "$strip_wrong" -eq 0 ] || { echo "FAIL: a strip was attributed to the other victim's bit"; pass=0; }
echo "other victim's slice recovered normally (want >=1): $done_v2"
if [ "$done_v2" -lt 1 ]; then
    echo "FAIL: the co-resident victim's slice did NOT complete recovery — the"
    echo "      refused victim's purge may have destroyed its authority manifest"
    pass=0
fi
echo "survivors with shutdown/withdraw (want 0): $shutdowns"
[ "$shutdowns" -eq 0 ] || { echo "FAIL: survivor shutdown"; pass=0; }
if [ "${bp_rc:-1}" -ne 0 ]; then
    echo "FAIL: blocked prober not released (rc=${bp_rc:-<hung>} after ${bp_s:-?}s)"
    pass=0
else
    echo "blocked prober released after ${bp_s}s"
fi
mounted=0
for h in "${survivors[@]}"; do
    m=$("$SSH" "$h" "mount | grep -c 'on $MNT type mxfs'" 2>/dev/null | tail -1 | tr -d '[:space:]')
    [ "${m:-0}" -ge 1 ] && mounted=$((mounted+1))
done
echo "survivors still mounted (want ${#survivors[@]}): $mounted"
[ "$mounted" -eq "${#survivors[@]}" ] || { echo "FAIL: survivor lost its mount"; pass=0; }

echo "--- evidence"
echo "$scans" | head -3
grep -h "slice replay refused" "$D"/*.dmesg | head -2
grep -h "P299-CLOSURE-PURGE" "$D"/*.dmesg | head -2
grep -h "P163-RECOVERED\|slice recovery complete" "$D"/*.dmesg | head -3

echo "dmesg harvest kept in $D"
if [ "$pass" -eq 1 ]; then
    echo "=== closure_multivictim PASS @ $(date -u +%FT%TZ) ==="
    exit 0
fi
echo "=== closure_multivictim FAIL @ $(date -u +%FT%TZ) ==="
exit 1
