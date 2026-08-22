#!/bin/bash
# clean_depart_mixed_death.sh — #92 race 5 closure run (sess349 GPT ruling,
# item 5): EMPTY (clean release) vs GUARD (death fence) CAS interplay.
#
# One mixed end-to-end run: dirty-kill ONE node under metadata I/O while
# SEVERAL other nodes cleanly unmount concurrently.  CAW serializes the
# EMPTY-vs-GUARD CAS (one winner per slot), so no deterministic collision
# test exists; the ruling's closure is this mixed run + the loser-path code
# audit.
#
# PASS (all must hold):
#   1. >=1 "no longer responding" declaration, and EVERY such line across
#      all surviving nodes names ONLY the victim's slot,
#   2. every P163-RECOVERY-PENDING line names ONLY the victim's slot,
#   3. P163-RECOVERY-COMPLETE for the victim's slot on >=1 survivor
#      (fenced + slice replayed, not just declared),
#   4. each clean departer's slot appears in >=1 P163-CLEAN-DEPART* line
#      and in ZERO death/recovery lines (clean release retired without
#      recovery),
#   5. no shutdown/withdraw on any surviving node; observer still writable.
#
# Leaves the rig degraded: victim DESTROYED, departers unmounted.  Rejoin
# by hand (virsh start victim + prep_node; mount -t mxfs on departers).
#
# Usage: tests/clean_depart_mixed_death.sh [victim] [obs] [clean...]
#   victim  dirty-killed node          (default test30)
#   obs     observer/survivor          (default test1)
#   clean   clean-unmount nodes        (default test26 test27 test28 test29)
#
# RULE 0 budget: preflight+slots 20s + I/O spin-up 8s + death declare 62s +
# confirm 62s + fence+dispatch 10s + slice replay ~20s (WATCH 240s cap) +
# concurrent umounts (overlap the window; 150s cap each) + sweep 40s
# = ~370s worst case; run under `timeout 420`.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"
VIRSH="virsh -c qemu:///system"
DEV=/dev/mapper/mpatha
MNT=/mnt/shared
NODES_N="${MXFS_NODES:-32}"
WATCH_S="${WATCH_S:-240}"

VICTIM="${1:-test30}"
OBS="${2:-test1}"
shift 2 2>/dev/null || shift $# 2>/dev/null
CLEAN=("${@:-}")
[ -z "${CLEAN[0]:-}" ] && CLEAN=(test26 test27 test28 test29)

for c in "$VICTIM" "${CLEAN[@]}"; do
    [ "$c" = "$OBS" ] && { echo "FAIL: observer $OBS cannot be victim/departer"; exit 2; }
done

# T0 backdated 5s: VM journal clocks skew 1-2s from this host (sess355).
T0=$(date -u -d '5 seconds ago' +%FT%TZ)
echo "=== clean_depart_mixed_death: victim=$VICTIM clean=(${CLEAN[*]}) obs=$OBS T0=$T0 ==="

# ── 0. Preflight: all roles mounted; learn each role's hb slot ──────────────
declare -A SLOT_OF
for h in "$VICTIM" "${CLEAN[@]}" "$OBS"; do
    m=$("$SSH" "$h" "mountpoint -q $MNT && echo Y" 2>/dev/null | tr -d ' \r\n')
    [ "$m" = "Y" ] || { echo "FAIL: $h not mounted"; exit 1; }
    claim=$("$SSH" "$h" \
        "dmesg | grep -a 'claimed heartbeat slot' | tail -1; \
         journalctl -k --no-pager 2>/dev/null | grep -a 'claimed heartbeat slot' | tail -1" \
        2>/dev/null | grep -a 'claimed heartbeat slot' | tail -1)
    s=$(printf '%s\n' "$claim" | sed -n 's/.*claimed heartbeat slot \([0-9]*\) .*/\1/p')
    [ -n "$s" ] || { echo "FAIL: cannot learn $h's hb slot"; exit 2; }
    SLOT_OF[$h]=$s
    echo "    $h -> slot $s"
done
VSLOT=${SLOT_OF[$VICTIM]}

# ── 1. Dirty metadata load on the victim (detached; killed with the VM) ─────
"$SSH" "$VICTIM" "mkdir -p $MNT/.mixdeath.$$ || exit 1; setsid nohup bash -c 'i=0; while :; do echo line-\$i >> $MNT/.mixdeath.$$/append; touch $MNT/.mixdeath.$$/f\$((i%200)); i=\$((i+1)); done' </dev/null >/dev/null 2>&1 & echo SPAWNED" 2>/dev/null | grep -q SPAWNED \
    || { echo "FAIL: could not start load on $VICTIM"; exit 1; }
sleep 5
sz=$("$SSH" "$VICTIM" "stat -c %s $MNT/.mixdeath.$$/append 2>/dev/null" 2>/dev/null | tr -d ' \r\n')
[ "${sz:-0}" -gt 0 ] || { echo "FAIL: victim load not writing (append size=${sz:-none})"; exit 1; }
echo "--- victim load live (append=${sz}B); killing $VICTIM + launching ${#CLEAN[@]} clean umounts"

# ── 2. Kill the victim and unmount the departers CONCURRENTLY ───────────────
$VIRSH destroy "$VICTIM" >/dev/null 2>&1 || { echo "FAIL: virsh destroy $VICTIM"; exit 2; }
TKILL=$(date +%s)
for h in "${CLEAN[@]}"; do
    "$SSH" "$h" "timeout 150 umount $MNT" >/dev/null 2>&1 &
done

# ── 3. Wait for the victim's recovery to COMPLETE on some survivor ──────────
DONE=""
while [ $(( $(date +%s) - TKILL )) -lt "$WATCH_S" ]; do
    sleep 15
    got=$("$SSH" "$OBS" "journalctl -k --since '$T0' --no-pager 2>/dev/null | grep -a 'P163-RECOVERY-COMPLETE slot=$VSLOT '" 2>/dev/null | tail -1)
    [ -n "$got" ] && { DONE="$got"; break; }
    echo "    t+$(( $(date +%s) - TKILL ))s — recovery not complete yet"
done
wait   # collect the umount jobs
if [ -z "$DONE" ]; then
    echo "FAIL: no P163-RECOVERY-COMPLETE slot=$VSLOT on $OBS within ${WATCH_S}s"
    exit 1
fi
TREC=$(( $(date +%s) - TKILL ))
echo "--- victim recovery complete at t+${TREC}s: $DONE"

# departers must actually be unmounted
still=""
for h in "${CLEAN[@]}"; do
    m=$("$SSH" "$h" "mountpoint -q $MNT && echo Y" 2>/dev/null | tr -d ' \r\n')
    [ "$m" = "Y" ] && still="$still $h"
done
[ -n "$still" ] && { echo "FAIL: departers still mounted:$still"; exit 1; }

# ── 4. Cluster-wide evidence sweep (all nodes still booted) ─────────────────
td=$(mktemp -d)
for i in $(seq 1 "$NODES_N"); do
    h="test$i"
    [ "$h" = "$VICTIM" ] && continue
    "$SSH" "$h" "journalctl -k --since '$T0' --no-pager 2>/dev/null | grep -aE 'no longer responding|P163-RECOVERY-PENDING|P163-RECOVERY-COMPLETE|P163-CLEAN-DEPART|Filesystem has been shut down|MXFS.*withdraw'" > "$td/$h" 2>/dev/null &
done
wait

fail=0

# 4a. every death declaration names the victim's slot, nowhere else
dd_all=$(cat "$td"/* 2>/dev/null | grep -a "no longer responding")
dd_n=$(printf '%s' "$dd_all" | grep -c "no longer responding")
bad_dd=$(printf '%s\n' "$dd_all" | grep -a "no longer responding" | grep -av "slot $VSLOT is no longer\|slot=$VSLOT \|(slot $VSLOT ")
if [ "$dd_n" -lt 1 ]; then
    echo "FAIL-1: zero death declarations — victim death never detected"; fail=1
elif [ -n "$bad_dd" ]; then
    echo "FAIL-1: death declaration(s) naming a NON-victim slot:"; printf '%s\n' "$bad_dd" | head -5; fail=1
else
    echo "PASS-1: $dd_n death declaration(s), all naming victim slot $VSLOT"
fi

# 4b. every RECOVERY-PENDING names the victim's slot
rp_bad=$(cat "$td"/* 2>/dev/null | grep -a "P163-RECOVERY-PENDING" | grep -av "slot=$VSLOT ")
if [ -n "$rp_bad" ]; then
    echo "FAIL-2: RECOVERY-PENDING for a NON-victim slot:"; printf '%s\n' "$rp_bad" | head -5; fail=1
else
    echo "PASS-2: all P163-RECOVERY-PENDING lines name victim slot $VSLOT"
fi

# 4c. recovery completed (already proven by the poll)
echo "PASS-3: P163-RECOVERY-COMPLETE slot=$VSLOT (t+${TREC}s)"

# 4d. each clean slot: >=1 CLEAN-DEPART*, 0 death/recovery lines
for h in "${CLEAN[@]}"; do
    s=${SLOT_OF[$h]}
    cd_n=$(cat "$td"/* 2>/dev/null | grep -a "P163-CLEAN-DEPART" | grep -ac "slot=$s ")
    death_n=$(cat "$td"/* 2>/dev/null | grep -a "no longer responding" | grep -ac "slot $s is\|slot=$s ")
    rec_n=$(cat "$td"/* 2>/dev/null | grep -a "P163-RECOVERY-" | grep -ac "slot=$s ")
    if [ "$cd_n" -ge 1 ] && [ "$death_n" -eq 0 ] && [ "$rec_n" -eq 0 ]; then
        echo "PASS-4: $h (slot $s) clean-departed x$cd_n, zero death/recovery"
    else
        echo "FAIL-4: $h (slot $s) clean-depart=$cd_n death=$death_n recovery=$rec_n"; fail=1
    fi
done

# 4e. no shutdown/withdraw on any surviving node; observer writable
sd=$(cat "$td"/* 2>/dev/null | grep -acE "Filesystem has been shut down|MXFS.*withdraw")
if [ "$sd" -gt 0 ]; then
    echo "FAIL-5: shutdown/withdraw on a survivor:"; cat "$td"/* | grep -aE "shut down|withdraw" | head -5; fail=1
else
    hw=$("$SSH" "$OBS" "echo post > $MNT/.mixdeath_post && sync $MNT/.mixdeath_post 2>/dev/null && echo W_OK" 2>/dev/null | tr -d ' \r\n')
    if [ "$hw" = "W_OK" ]; then
        echo "PASS-5: zero shutdown/withdraw; observer writable"
    else
        echo "FAIL-5: observer not writable after the storm"; fail=1
    fi
fi

rm -rf "$td"
echo "NOTE: rig left degraded — virsh start $VICTIM + prep_node; remount ${CLEAN[*]}"
if [ "$fail" -eq 0 ]; then
    echo "=== clean_depart_mixed_death PASS (recovery t+${TREC}s) ==="
    exit 0
fi
echo "=== clean_depart_mixed_death FAIL ==="
exit 1
