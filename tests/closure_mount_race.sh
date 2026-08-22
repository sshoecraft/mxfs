#!/bin/bash
# closure_mount_race.sh — sess363 ruling Hazards-§7 item 2: "Terminal import
# must precede mount-time adopt of victim's retained grants; fail closed
# before v5 callbacks registered."
#
# THE HAZARD.  A mount does two things this fix cares about: it scans the
# heartbeat table for already-terminal verdicts and imports them (so it
# enforces the quarantine from its first operation), and it runs the
# mount-time adopt/purge of retained grants.  If a node joins WHILE a terminal
# refusal is being published, the two can interleave.  The dangerous order is
# adopt-then-import: the joining node would take up the victim's retained
# grants as ordinary stale state, unaware that they are frozen evidence, and
# either strand them again or act on a quarantined domain it does not yet know
# about.
#
# THE TEST.  A spare node is power-cycled BEFORE the run and brought to the
# edge of joining: booted, /src mounted, the shared LUN assembled, but with NO
# mxfs module loaded.  That makes the join itself a single fast step (insmod +
# mount, seconds) which the harness fires at a chosen offset into the recovery
# window -- so the mount really does land around the publish/import instead of
# being smeared across a 60s VM boot.  Then:
#
#   * the joiner must end up enforcing the quarantine — it must show the
#     registration-time terminal scan or a quarantine import for the victim's
#     slot (this is the "import precedes exposure" property);
#   * the joiner must NOT shut down, withdraw, or lose its mount;
#   * the refused victim's slot must never be published as recovered, from
#     ANY node including the joiner;
#   * a survivor blocked on the victim's out-of-closure root grant must still
#     be released (the joiner must not have disturbed the repair).
#
# Usage: tests/closure_mount_race.sh <N> <victim> <joiner>
# Env: PROBE_HOST (default test1), RECOVERY_WAIT (default 210),
#      VICTIM_LOAD (default 6), JOIN_DELAY (default 55 -- seconds after the
#      kill at which the joiner's insmod+mount is fired; the death confirm
#      window is ~62s, so this lands the mount squarely inside
#      fence+replay+publish), BOOT_WAIT (default 240).
#
# Leaves a durable quarantine — re-prep before anything else.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"

N="${1:?usage: closure_mount_race.sh <N> <victim> <joiner>}"
VICTIM="${2:?usage: closure_mount_race.sh <N> <victim> <joiner>}"
JOINER="${3:?usage: closure_mount_race.sh <N> <victim> <joiner>}"
PROBE_HOST="${PROBE_HOST:-test1}"
MNT=/mnt/shared
AGMASK=0x2
RECOVERY_WAIT="${RECOVERY_WAIT:-210}"
VICTIM_LOAD="${VICTIM_LOAD:-6}"
JOIN_DELAY="${JOIN_DELAY:-55}"
BOOT_WAIT="${BOOT_WAIT:-240}"
DEV=/dev/mapper/mpatha
KO_MD5=$(md5sum "$REPO/mxfs.ko" 2>/dev/null | awk '{print $1}')

[ "$VICTIM" = "$JOINER" ] && { echo "FAIL: victim and joiner must differ"; exit 1; }
for h in "$VICTIM" "$JOINER"; do
    [ "$h" = "$PROBE_HOST" ] && { echo "FAIL: $h is the probe host — set PROBE_HOST"; exit 1; }
done

T0=$(date -u +%FT%TZ)
echo "=== closure_mount_race: N=$N victim=$VICTIM joiner=$JOINER probe=$PROBE_HOST @ $T0 ==="

survivors=()
for i in $(seq 1 "$N"); do
    h="test$i"
    [ "$h" = "$VICTIM" ] || [ "$h" = "$JOINER" ] || survivors+=("$h")
done

VSLOT=$("$SSH" "$VICTIM" "dmesg | grep -oE 'node_slot=[0-9]+' | tail -1" 2>/dev/null |
        tr -d '[:space:]' | cut -d= -f2)
[ -n "${VSLOT:-}" ] || { echo "FAIL: could not resolve the victim's heartbeat slot"; exit 1; }
echo "victim $VICTIM holds heartbeat slot $VSLOT"

# 1. Remove the joiner from the cluster CLEANLY and stage it at the edge of
#    rejoining: umount + rmmod, leaving /src and the LUN in place.
#
#    NOT `virsh destroy`.  sess375 measured what that costs: a destroyed joiner
#    is a SECOND dead node, so the cluster runs a second fence + foreign-slice
#    replay, that replay competes for the one-shot refusal knob, and it
#    publishes a quarantine of its own.  In one run the knob was consumed by
#    the joiner's slice (ag_mask=0x2) while the real victim's slice refused
#    genuinely with ag_mask=0x80001 — which contains ag0, so the root grant
#    stayed frozen CORRECTLY and the run had nothing to measure.  A clean
#    departure releases the slot (P163-CLEAN-DEPART) and leaves no slice to
#    replay, so the run has exactly one death: the victim's.
#
#    The join is still genuinely cold at the layer this test is about: fresh
#    module, fresh mount, no cached membership, no retained slot.
echo "--- removing $JOINER from the cluster cleanly (umount + rmmod)"
"$SSH" "$JOINER" "fuser -km $MNT >/dev/null 2>&1; sleep 1;
     umount $MNT >/dev/null 2>&1 || umount -f $MNT >/dev/null 2>&1 || umount -l $MNT >/dev/null 2>&1
     for i in 1 2 3 4 5 6 7 8; do rmmod mxfs >/dev/null 2>&1 && break; sleep 2; done" >/dev/null 2>&1
staged=$("$SSH" "$JOINER" "mountpoint -q /src && [ -b $DEV ] && [ -f /src/mxfs/mxfs.ko ] &&
     ! lsmod | grep -q '^mxfs ' && echo JOINER_STAGED" 2>/dev/null | grep -c JOINER_STAGED)
[ "${staged:-0}" -ge 1 ] || {
    echo "FAIL: $JOINER did not reach the staged state (/src + $DEV + ko present, mxfs unloaded)"
    echo "      HARNESS fault, not an MXFS defect — do not ledger it."
    exit 1; }
echo "$JOINER STAGED: departed cleanly, /src mounted, $DEV present, mxfs NOT loaded"
# Let the clean departure settle in every survivor's membership view before the
# kill, so the only death the recovery machinery sees is the victim's.
sleep 15

# 2. Arm the aimed refusal on the survivors.
echo "--- arming freplay_force_refusal=1 slot=$VSLOT ag_mask=$AGMASK on ${#survivors[@]} survivors"
for h in "${survivors[@]}"; do
    # PIN the victim's slot.  force_slot=-1 was tried and is wrong here: the
    # one-shot knob then fires on whichever slice is replayed first, and
    # sess375 measured it being consumed by an unrelated recovery while the
    # real victim's replay refused genuinely with its own domain (0x80001,
    # which contains ag0 — so the root grant was correctly frozen and the run
    # measured nothing).
    "$SSH" "$h" "echo $AGMASK > /sys/module/mxfs/parameters/freplay_force_ag_mask;
                 echo $VSLOT > /sys/module/mxfs/parameters/freplay_force_slot;
                 echo 1 > /sys/module/mxfs/parameters/freplay_force_refusal;
                 dmesg --clear" >/dev/null 2>&1 &
done
wait
armed=0
for h in "${survivors[@]}"; do
    v=$("$SSH" "$h" "cat /sys/module/mxfs/parameters/freplay_force_refusal" 2>/dev/null | tail -1 | tr -d '[:space:]')
    [ "$v" = "1" ] && armed=$((armed+1))
done
[ "$armed" -eq "${#survivors[@]}" ] || {
    echo "FAIL: armed on $armed/${#survivors[@]} survivors — aborting, no kill issued"; exit 1; }
echo "refusal CONFIRMED armed on all $armed survivors"

echo "--- victim takes a HOT root-dir EX (${VICTIM_LOAD}s of un-synced churn)"
"$SSH" "$VICTIM" "nohup bash -c '
    end=\$((SECONDS + ${VICTIM_LOAD} + 120))
    i=0
    while [ \$SECONDS -lt \$end ]; do
        i=\$((i+1))
        echo hot > $MNT/.cmr-victim.\$i
        rm -f $MNT/.cmr-victim.\$((i-3))
    done
' >/tmp/cmrload.log 2>&1 &" >/dev/null 2>&1
sleep "$VICTIM_LOAD"
lcnt=$("$SSH" "$PROBE_HOST" "ls -a $MNT/ 2>/dev/null | grep -c cmr-victim" 2>/dev/null | tail -1 | tr -d '[:space:]')
[ "${lcnt:-0}" -gt 0 ] || { echo "FAIL: victim root-dir churn never landed"; exit 1; }
echo "victim holds a hot root-dir EX (${lcnt} churn files visible)"

date -u "+KILL $VICTIM @ %FT%TZ"
sudo virsh -c qemu:///system destroy "$VICTIM" || { echo "FAIL: virsh destroy $VICTIM"; exit 1; }

BLOCK_BUDGET=$(( RECOVERY_WAIT + 60 ))
"$SSH" "$PROBE_HOST" "nohup bash -c '
    s=\$(date +%s)
    timeout $BLOCK_BUDGET touch $MNT/.cmr-blocked; rc=\$?
    echo \"BLOCKED_PROBE rc=\$rc elapsed=\$((\$(date +%s) - s))\" > /tmp/cmrprobe.out
' >/dev/null 2>&1 &" >/dev/null 2>&1
echo "blocked prober launched on $PROBE_HOST (budget ${BLOCK_BUDGET}s)"

# 3. THE RACE.  Fire the staged joiner's insmod+mount inside the
#    fence/replay/publish window.  Backgrounded on the node with nohup so a
#    mount that blocks on the recovery barrier cannot stall the harness; its
#    verdict is read back from /tmp/cmrjoin.out afterwards.
sleep "$JOIN_DELAY"
date -u "+JOIN $JOINER (insmod+mount at T+${JOIN_DELAY}s, inside the recovery window) @ %FT%TZ"
"$SSH" "$JOINER" "nohup bash -c '
    s=\$(date +%s)
    MXFS_DEV=\"$DEV\" MXFS_KO_MD5=\"$KO_MD5\" \
        timeout $(( RECOVERY_WAIT - JOIN_DELAY )) bash /src/mxfs/tests/setup/prep_node.sh caw \
        > /tmp/cmrjoin.raw 2>&1
    echo \"JOIN_RC=\$? elapsed=\$((\$(date +%s) - s))\" > /tmp/cmrjoin.out
' >/dev/null 2>&1 &" >/dev/null 2>&1
echo "join fired"

echo "waiting $(( RECOVERY_WAIT - JOIN_DELAY ))s for refusal+publish+import and the joiner's mount..."
sleep $(( RECOVERY_WAIT - JOIN_DELAY ))

jn=$("$SSH" "$JOINER" "cat /tmp/cmrjoin.out 2>/dev/null; tail -2 /tmp/cmrjoin.raw 2>/dev/null" 2>/dev/null | tr -d '\r' | grep -vE 'known hosts|Unauthorized|authorized user')
echo "--- joiner prep_node: ${jn:-<no result>}"

bp=$("$SSH" "$PROBE_HOST" "cat /tmp/cmrprobe.out 2>/dev/null" 2>/dev/null | tr -d '\r' | grep BLOCKED_PROBE | tail -1)
bp_rc=$(echo "$bp" | grep -o 'rc=[0-9]*' | cut -d= -f2)
bp_s=$(echo "$bp" | grep -o 'elapsed=[0-9]*' | cut -d= -f2)
echo "--- blocked prober: ${bp:-<still running>}"

D=$(mktemp -d)
for h in "${survivors[@]}"; do
    "$SSH" "$h" "dmesg" > "$D/$h.dmesg" 2>/dev/null &
done
wait
# the joiner is up by construction; still bound the read
"$SSH" "$JOINER" "dmesg" > "$D/JOINER-$JOINER.dmesg" 2>/dev/null || true
for h in "${survivors[@]}"; do
    "$SSH" "$h" "echo 0 > /sys/module/mxfs/parameters/freplay_force_refusal;
                 echo 1 > /sys/module/mxfs/parameters/freplay_force_ag_mask;
                 echo -1 > /sys/module/mxfs/parameters/freplay_force_slot" >/dev/null 2>&1 &
done
wait

# ── did the FORGED domain actually take? ────────────────────────────────────
# Measured sess375: a replay can refuse GENUINELY (defect #1, unauthorized
# images) before the one-shot knob is even reached, and then the published
# domain is the replay's own refused AG set — which included ag0.  With ag0 IN
# closure the victim's root grant is SUPPOSED to stay frozen, so the purge
# correctly does nothing and the blocked prober correctly never returns.
# Reporting that as FAIL blames the filesystem for the harness not getting the
# scenario it asked for.  Check both halves: the injection fired, and the
# domain that got published is the one that was armed.
INJ=$(grep -h "P227-FR-INJECT-ARMED" "$D"/*.dmesg 2>/dev/null | head -1)
PUBMASK=$(grep -h "slice replay refused" "$D"/*.dmesg 2>/dev/null |
          grep -oE 'ag_mask=0x[0-9a-f]+' | head -1 | cut -d= -f2)
echo "--- forged-domain check: injection=$( [ -n "$INJ" ] && echo fired || echo NOT-FIRED ) published ag_mask=${PUBMASK:-<none>} (armed $AGMASK)"
if [ -z "$INJ" ] || [ -z "${PUBMASK:-}" ] || [ $(( PUBMASK )) -ne $(( AGMASK )) ]; then
    echo "PRECONDITION-NOT-MET: the run did not get the domain it armed."
    echo "  armed ag_mask=$AGMASK, published ag_mask=${PUBMASK:-<none>},"
    echo "  one-shot injection $( [ -n "$INJ" ] && echo consumed || echo NEVER CONSUMED )."
    echo "  A genuine refusal (defect #1) preempting the forged one publishes"
    echo "  its OWN refused AG set; if that set contains the probe's AG then"
    echo "  the frozen grant is CORRECT and there is nothing here to measure."
    echo "  This is a harness precondition, NOT an MXFS defect — do not ledger it."
    exit 2
fi

pass=1
JD="$D/JOINER-$JOINER.dmesg"
joiner_mounted=$("$SSH" "$JOINER" "mount | grep -c 'on $MNT type mxfs'" 2>/dev/null | tail -1 | tr -d '[:space:]')
joiner_quar=$(grep -cE "P241-RECOV-TERMINAL-SCAN|P240-QUAR-IMPORT" "$JD" 2>/dev/null || true)
joiner_down=$(grep -cE "Filesystem has been shut down|forced shutdown|MXFS.*withdraw" "$JD" 2>/dev/null || true)
recovered_pub=$(grep -h "P163-RECOVERED\|slice recovery complete\|published as recovered" "$D"/*.dmesg 2>/dev/null | grep -c "slot=$VSLOT\b" || true)
shutdowns=$(grep -l "Filesystem has been shut down\|forced shutdown\|MXFS.*withdraw" "$D"/*.dmesg 2>/dev/null | wc -l)
purged=$(grep -h "P299-CLOSURE-PURGE" "$D"/*.dmesg 2>/dev/null | grep -o "purged=[0-9]*" | cut -d= -f2 | paste -sd+ - | bc 2>/dev/null)
purged=${purged:-0}
scrub_n=$(grep -h "P299-SCRUB-STRIP" "$D"/*.dmesg 2>/dev/null | wc -l)

echo "--- assertions"
echo "joiner mounted (want 1): ${joiner_mounted:-0}"
[ "${joiner_mounted:-0}" -ge 1 ] || { echo "FAIL: the joiner never mounted — it must join, not be excluded"; pass=0; }
echo "joiner imported the quarantine (want >=1): $joiner_quar"
[ "$joiner_quar" -ge 1 ] || {
    echo "FAIL: the joiner mounted WITHOUT importing the terminal verdict — it"
    echo "      is exposed to a quarantined domain it does not know about"
    pass=0; }
echo "joiner shutdown/withdraw lines (want 0): $joiner_down"
[ "$joiner_down" -eq 0 ] || { echo "FAIL: the joiner shut down"; pass=0; }
echo "refused victim's slot published as recovered (want 0): $recovered_pub"
[ "$recovered_pub" -eq 0 ] || { echo "FAIL: the refused slice was published as recovered"; pass=0; }
echo "survivors with shutdown/withdraw (want 0): $shutdowns"
[ "$shutdowns" -eq 0 ] || { echo "FAIL: survivor shutdown"; pass=0; }
echo "repair happened (purged=$purged scrub=$scrub_n, want at least one)"
[ $(( purged + scrub_n )) -ge 1 ] || { echo "FAIL: nothing was repaired"; pass=0; }
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

echo "--- evidence (joiner)"
grep -E "P241-RECOV-TERMINAL-SCAN|P240-QUAR-IMPORT" "$JD" 2>/dev/null | head -3
echo "--- evidence (cluster)"
grep -h "slice replay refused" "$D"/*.dmesg | head -2
grep -h "P299-CLOSURE-PURGE\|P299-SCRUB-STRIP" "$D"/*.dmesg | head -3

echo "dmesg harvest kept in $D"
if [ "$pass" -eq 1 ]; then
    echo "=== closure_mount_race PASS @ $(date -u +%FT%TZ) ==="
    exit 0
fi
echo "=== closure_mount_race FAIL @ $(date -u +%FT%TZ) ==="
exit 1
