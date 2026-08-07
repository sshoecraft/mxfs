#!/bin/bash
# tests/incarnation_death_probe.sh — does a node death name the victim by a
# REAL incarnation?
#
# WHY THIS EXISTS (D-MOUNT-INCARNATION-CONSTANT-ZERO, sess83 -> sess88)
#   sess83 measured the on-disk disklock mount-incarnation epoch as a
#   hard-coded 0 on all 31 live HB records: `ctx->epoch = 0` in the
#   constructor was the only write in the tree.  That made ~8 recovery/fence
#   incarnation tests vacuous — every `victim_epoch && ...` guard was skipped,
#   a rejoined node adopted its own prior incarnation's recovery lease, and the
#   durable recovery descriptor could not say WHICH incarnation it was
#   recovering.  0.11.420 gives each mount a random nonzero 64-bit incarnation
#   and threads it through the death path.
#
# THE MEASUREMENT
#   1. Read the victim's on-disk HB record (O_DIRECT, from a SURVIVOR — never
#      the victim, whose own page cache would serve its own writes back).
#      Record slot / node_id / epoch.  This is the incarnation that is about
#      to die.
#   2. Drop a marker into every survivor's kmsg so the observation window is
#      scoped to THIS kill and cannot pick up a prior run's probes (sess27:
#      first-marker window scoping was itself an evidence-integrity bug).
#   3. Hard-kill the victim with `virsh destroy` — node death, not a clean
#      withdraw, so no WITHDRAWN record is written and the survivors must
#      detect the death from missed heartbeats alone.
#   4. Poll survivors for P163-RECOVERY-PENDING.
#
# THE ASSERTION
#   The marker must name epoch == the victim's pre-kill on-disk epoch, and
#   that epoch must be NONZERO.  epoch=0 is the defect (the pre-0.11.420
#   behaviour).  An epoch that is nonzero but DIFFERENT from the pre-kill
#   value is worse than either — it means the death path fabricated an
#   identity, which is exactly the category error sess87 removed from
#   mark_recovery_pending (it used to read back "who is in this slot NOW").
#
# TIMING (RULE 0 — derived, not chosen)
#   declare dead : MXFS_DISKLOCK_DEAD_THRESHOLD(31) * HB_INTERVAL_MS(2000) = 62s
#   confirm      : the settle sweep re-samples the same 31 * 2000ms      = 62s
#   fence+dispatch                                                       ~ 10s
#   budget = 134s; default WATCH_S 180 leaves margin without hiding slowness.
#   A probe that has not appeared by then is a FAILURE, not a slow pass.
#
# usage: incarnation_death_probe.sh [victim=test32] [reader=test1] [watch_s=180]
set -u
VICTIM="${1:-test32}"
READER="${2:-test1}"
WATCH_S="${3:-180}"
DEV="${MXFS_DEV:-/dev/mapper/mpatha}"
NODES_N="${MXFS_NODES:-32}"

cd "$(dirname "$0")/.." || exit 2
SSH=tools/mxfs_sshpass.sh

if [ "$VICTIM" = "$READER" ]; then
    echo "probe: victim and reader must differ (the victim cannot observe its own death)" >&2
    exit 2
fi

MARK="INCPROBE-$$-$(date -u +%s)"
echo "probe: victim=$VICTIM reader=$READER dev=$DEV watch=${WATCH_S}s mark=$MARK"

# ── 1. victim's slot, from its OWN claim line (authoritative for slot) ───────
# Retention differs ~60x across nodes and between dmesg and journalctl -k, and
# a node that has run a board has long since rolled the claim out of its ring
# buffer.  Ask both; the on-disk cross-check below catches a stale answer.
claim=$($SSH "$VICTIM" \
    "dmesg | grep -a 'claimed heartbeat slot' | tail -1; \
     journalctl -k --no-pager 2>/dev/null | grep -a 'claimed heartbeat slot' | tail -1" \
    2>/dev/null | grep -a 'claimed heartbeat slot' | tail -1)
SLOT=$(printf '%s\n' "$claim" | sed -n 's/.*claimed heartbeat slot \([0-9]*\) .*/\1/p')
NODEID=$(printf '%s\n' "$claim" | sed -n 's/.*for node \([0-9]*\).*/\1/p')
if [ -z "${SLOT:-}" ] || [ -z "${NODEID:-}" ]; then
    echo "probe: could not learn $VICTIM's slot/node_id from kmsg" >&2
    echo "       last claim line: '$claim'" >&2
    exit 2
fi

# ── 1b. the victim's incarnation, read O_DIRECT from a SURVIVOR ─────────────
PRE=$($SSH "$READER" "python3 - <<'EOF'
import struct, os, mmap
f=os.open('$DEV', os.O_RDONLY)
sup=os.pread(f,4096,0); dloff,=struct.unpack_from('<Q',sup,64); os.close(f)
fd=os.open('$DEV', os.O_RDONLY|os.O_DIRECT)
buf=mmap.mmap(-1,32768); os.preadv(fd,[buf],dloff); os.close(fd)
r=bytes(buf)[$SLOT*512:($SLOT+1)*512]
magic,flags,node,gen=struct.unpack_from('<IIII',r,0)
ep,=struct.unpack_from('<Q',r,24)
print('%d %d %d %d' % (magic,flags,node,ep))
EOF" 2>/dev/null)
read -r PMAGIC PFLAGS PNODE PEPOCH <<<"$PRE"
if [ "${PMAGIC:-0}" != "1297632331" ]; then   # 0x4D584C4B 'MXLK'
    echo "probe: slot $SLOT does not carry a valid MXLK record (magic=${PMAGIC:-none})" >&2
    exit 2
fi
if [ "${PNODE:-0}" != "$NODEID" ]; then
    echo "probe: slot $SLOT holds node $PNODE but $VICTIM claims node $NODEID — stale map, aborting" >&2
    exit 2
fi
echo "probe: pre-kill  slot=$SLOT node=$NODEID flags=$PFLAGS EPOCH=$PEPOCH"
if [ "$PEPOCH" = "0" ]; then
    echo "probe: RESULT FAIL — the victim's on-disk incarnation is already 0 before the kill."
    echo "       D-MOUNT-INCARNATION-CONSTANT-ZERO is PRESENT in the running build."
    exit 1
fi

# ── 2. survivors + kmsg marker ──────────────────────────────────────────────
SURV=()
for i in $(seq 1 "$NODES_N"); do [ "test$i" = "$VICTIM" ] || SURV+=("test$i"); done
for n in "${SURV[@]}"; do
    ( $SSH "$n" "echo '$MARK' > /dev/kmsg" >/dev/null 2>&1 ) &
done
wait

# ── 3. kill ─────────────────────────────────────────────────────────────────
echo "probe: destroying $VICTIM at $(date -u +%H:%M:%S)Z"
virsh -c qemu:///system destroy "$VICTIM" >/dev/null 2>&1 || {
    echo "probe: virsh destroy $VICTIM failed" >&2; exit 2; }
T0=$(date +%s)

# ── 4. poll survivors for the pending marker, scoped after $MARK ────────────
TD=$(mktemp -d)
FOUND=""
while [ $(( $(date +%s) - T0 )) -lt "$WATCH_S" ]; do
    sleep 10
    for n in "${SURV[@]}"; do
        ( $SSH "$n" "dmesg | sed -n '/$MARK/,\$p' | grep -a 'P163-RECOVERY-PENDING'" \
            > "$TD/$n" 2>/dev/null ) &
    done
    wait
    FOUND=$(grep -l . "$TD"/* 2>/dev/null | head -1)
    [ -n "$FOUND" ] && break
    echo "probe:   t+$(( $(date +%s) - T0 ))s — no P163 yet"
done
ELAPSED=$(( $(date +%s) - T0 ))

if [ -z "$FOUND" ]; then
    echo "probe: RESULT FAIL — no survivor logged P163-RECOVERY-PENDING within ${WATCH_S}s."
    echo "       Death was not detected/dispatched inside the derived budget (RULE 0)."
    rm -rf "$TD"; exit 1
fi

echo "probe: P163 seen at t+${ELAPSED}s on $(basename "$FOUND"); all reporting survivors:"
rc=0; seen=0
for n in "${SURV[@]}"; do
    [ -s "$TD/$n" ] || continue
    while IFS= read -r line; do
        seen=$((seen+1))
        gslot=$(printf '%s\n' "$line" | sed -n 's/.*P163-RECOVERY-PENDING slot=\([0-9-]*\) .*/\1/p')
        gnode=$(printf '%s\n' "$line" | sed -n 's/.*P163-RECOVERY-PENDING slot=[0-9-]* node=\([0-9]*\) .*/\1/p')
        gep=$(printf '%s\n' "$line" | sed -n 's/.*P163-RECOVERY-PENDING slot=[0-9-]* node=[0-9]* epoch=\([0-9]*\).*/\1/p')
        verdict="OK"
        if [ "$gslot" = "$SLOT" ]; then
            if [ "${gep:-0}" = "0" ]; then
                verdict="FAIL(epoch=0 — incarnation not observed)"; rc=1
            elif [ "$gep" != "$PEPOCH" ]; then
                verdict="FAIL(epoch $gep != pre-kill $PEPOCH — FABRICATED identity)"; rc=1
            elif [ "$gnode" != "$NODEID" ]; then
                verdict="FAIL(node $gnode != victim $NODEID)"; rc=1
            fi
        else
            verdict="other-slot"
        fi
        printf '  %-8s slot=%-3s node=%-11s epoch=%-21s %s\n' "$n" "$gslot" "$gnode" "$gep" "$verdict"
    done < "$TD/$n"
done
rm -rf "$TD"

echo
echo "probe: victim pre-kill incarnation = $PEPOCH"
if [ "$seen" = "0" ]; then
    echo "probe: RESULT FAIL — P163 lines present but none parsed."; exit 1
fi
if [ "$rc" = "0" ]; then
    echo "probe: RESULT PASS — every survivor named the victim by its real, nonzero,"
    echo "       pre-kill incarnation.  D-MOUNT-INCARNATION-CONSTANT-ZERO not present"
    echo "       on this path in the running build."
else
    echo "probe: RESULT FAIL — see the FAIL lines above."
fi
echo "probe: $VICTIM is DESTROYED — restart it (virsh start $VICTIM) + re-prep before the next test."
exit $rc
