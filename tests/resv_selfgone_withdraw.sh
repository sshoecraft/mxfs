#!/bin/bash
# tests/resv_selfgone_withdraw.sh
#
# The second cause-exercising arm for
# D-PR-RESERVATION-HEALTH-UNMONITORED-AFTER-MOUNT-381.
#
# tests/resv_health_detect.sh covers the reservation going ABSENT while the
# cluster is healthy.  This covers the other half, and the one that was
# actually MEASURED in the field (sess572, build 0.75.118, test1,
# tests/evidence/sess572_resv_conflict/test1.txt): the reservation stayed in
# force but THIS NODE'S OWN REGISTRATION was removed.  From then on the target
# rejected every write -- 4280 'reservation conflict' lines -- and MXFS
# reported them upward as EIO with the mount still in /proc/mounts, never shut
# down, never withdrawn, never rejoined.  A filesystem that cannot write a
# single block stayed mounted and kept answering userspace with EIO
# indefinitely.
#
# So the assertion here is NOT "nothing bad happens".  It is that the node
# NOTICES and WITHDRAWS within a bounded time instead of serving EIO for ever.
# A withdrawal IS the designed outcome: the node has been fenced at the target.
#
# The removal is done out of band, from the peer's nexus, with no node death
# and no MXFS involvement -- exactly the shape a stray administrative
# sg_persist, a target restart losing PR state, or a third initiator produces.
#
# Usage: tests/resv_selfgone_withdraw.sh [victim] [peer] [label]
# Env:   MXFS_DEV  shared LUN as the GUESTS see it (default per rig, below)
#
set -u

VICTIM="${1:-test1}"
PEER="${2:-test2}"
LABEL="${3:-selfgone}"

REPO="$(cd -- "$(dirname "$0")/.." && pwd)"
SSH="$REPO/tools/mxfs_sshpass.sh"
MNT=/mnt/shared
OUT="$REPO/tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_resvselfgone_$LABEL"
mkdir -p "$OUT"

fail=0
say()  { echo "[$(date -u +%H:%M:%SZ)] $*"; }
chk()  { if [ "$1" = 0 ]; then echo "   PASS: $2"; else echo "   FAIL: $2"; fail=$((fail+1)); fi; }
rs()   { local h="$1" t="$2"; shift 2; timeout "$t" "$SSH" "$h" "$*" 2>/dev/null; }

# ---------------------------------------------------------------------------
# The device.  A harness that guesses this wrong does not fail loudly -- it
# reads an absent device, sg_persist errors, and an unwary parser reports "no
# reservation" as though it had OBSERVED one absent.  So: take it from the
# node's own live mount, which cannot be wrong, and only then fall back.
# ---------------------------------------------------------------------------
DEV="${MXFS_DEV:-}"
if [ -z "$DEV" ]; then
    DEV=$(rs "$PEER" 20 "awk '\$2==\"$MNT\" && \$3==\"mxfs\" {print \$1}' /proc/mounts" | tr -d '\r\n')
fi
[ -n "$DEV" ] || { echo "FATAL: no mxfs mount on $PEER and MXFS_DEV unset"; exit 2; }
say "device=$DEV victim=$VICTIM peer=$PEER evidence=$OUT"

# ---------------------------------------------------------------------------
# 0. Both nodes mounted, WE-AR in force, and we know each node's own key.
#    The key is read from the node's OWN kernel log, not guessed from the
#    target's key list: READ KEYS never says which nexus holds which key.
# ---------------------------------------------------------------------------
say "0. baseline"
for n in "$VICTIM" "$PEER"; do
    m=$(rs "$n" 20 "grep -c ' $MNT mxfs ' /proc/mounts" | tr -d '\r\n')
    echo "   $n mounted=$m"
    [ "$m" = 1 ] || { echo "FATAL: $n is not mounted -- form the cluster first"; exit 2; }
done

own_key() { rs "$1" 20 "dmesg | grep -oE \"P-PRKEY-REGISTERED .*key=0x[0-9a-f]+\" | tail -1 | sed 's/.*key=//'" | tr -d '\r\n'; }
vkey=$(own_key "$VICTIM")
pkey=$(own_key "$PEER")
echo "   victim_key=$vkey peer_key=$pkey"
case "$vkey" in 0x*) ;; *) echo "FATAL: could not read $VICTIM's own PR key from its kernel log"; exit 2 ;; esac
case "$pkey" in 0x*) ;; *) echo "FATAL: could not read $PEER's own PR key from its kernel log"; exit 2 ;; esac
[ "$vkey" != "$pkey" ] || { echo "FATAL: both nodes report the same key -- per-node PR is not in force"; exit 2; }

rs "$PEER" 30 "sg_persist --in --read-reservation $DEV; sg_persist --in --read-keys $DEV" \
    > "$OUT/pr_before.txt" 2>&1
grep -q 'all registrants' "$OUT/pr_before.txt"; chk $? "WE-AR held before the removal"
grep -qi "${vkey#0x}" "$OUT/pr_before.txt"; chk $? "the victim's key is registered before the removal"

# ---------------------------------------------------------------------------
# 1. A write workload on the victim, so the data path is live when its key
#    goes.  Without it the only trigger is the slow health audit and the
#    measurement says nothing about the EIO-for-ever shape this arm is about.
# ---------------------------------------------------------------------------
# The loop carries its own DEADLINE rather than being killed afterwards:
# nothing on this rig may be terminated by pattern-matching a process list.
say "1. start a write workload on $VICTIM (self-terminating)"
WL_S=240
rs "$VICTIM" 20 "mkdir -p $MNT/$LABEL; nohup sh -c 'END=\$(( \$(date +%s) + $WL_S )); i=0; while [ \$(date +%s) -lt \$END ]; do echo \$i > $MNT/$LABEL/w.\$((i%64)) 2>/dev/null; sync $MNT/$LABEL/w.\$((i%64)) 2>/dev/null; i=\$((i+1)); sleep 0.2; done' >/dev/null 2>&1 & echo started" >/dev/null
sleep 5

# ---------------------------------------------------------------------------
# 2. Remove the victim's registration OUT OF BAND, from the peer's nexus.
#    PREEMPT (not preempt-and-abort) with the peer's own key as the
#    reservation key and the victim's as the service-action key: the victim's
#    registration goes, WE-AR survives because the peer is still a registrant.
# ---------------------------------------------------------------------------
say "2. PREEMPT the victim's key from $PEER's nexus (no death, nothing else changes)"
T0=$(date -u +%s)
rs "$PEER" 30 "sg_persist --out --preempt --param-rk=$pkey --param-sark=$vkey --prout-type=7 $DEV" \
    > "$OUT/preempt.txt" 2>&1
sed 's/^/   | /' "$OUT/preempt.txt" | head -5

rs "$PEER" 30 "sg_persist --in --read-reservation $DEV; sg_persist --in --read-keys $DEV" \
    > "$OUT/pr_after.txt" 2>&1
grep -qi "${vkey#0x}" "$OUT/pr_after.txt" && \
    { chk 1 "the victim's key is GONE from the target (the removal did not take)"; } || \
    { chk 0 "the victim's key is gone from the target"; }
grep -q 'all registrants' "$OUT/pr_after.txt"; chk $? "WE-AR still held (only the registration went)"

# ---------------------------------------------------------------------------
# 3. THE ASSERTION.  Bound derived from the design, not from patience:
#    the data path conflicts within one heartbeat (~1-2 s), three conflicts
#    arm the inspection, the inspection asks the target up to 5 times at
#    200 ms -- under 15 s.  The slow path is the auditor's reservation-health
#    audit at up to 60 s, plus the same inspection.  So 90 s covers both with
#    margin; anything past it is the defect this record names.
# ---------------------------------------------------------------------------
BOUND=90
say "3. $VICTIM must notice and withdraw within ${BOUND}s"
withdrew=""; t_w=""
for i in $(seq 1 30); do
    sleep 3
    AGE=$(( $(date -u +%s) - T0 ))
    w=$(rs "$VICTIM" 20 "dmesg | grep -cE 'P277-FENCED-SELF-WITHDRAW|P-PR-SELFFENCE'" | tr -d '\r\n')
    case "$w" in ''|*[!0-9]*) w=0 ;; esac
    if [ "$w" -gt 0 ]; then withdrew=1; t_w=$AGE; say "   withdrew at t+${AGE}s"; break; fi
    [ "$AGE" -gt "$BOUND" ] && { say "   still serving at t+${AGE}s"; break; }
done

rs "$VICTIM" 30 "dmesg | grep -E 'P305-RESV|P277-|P-PR-ADVISORY|P-PR-OWNKEY-GONE|Shutting down filesystem|reservation conflict' | tail -40" \
    > "$OUT/victim_dmesg.txt" 2>&1
sed 's/^/   | /' "$OUT/victim_dmesg.txt" | tail -12

[ -n "$withdrew" ]; chk $? "the victim WITHDREW rather than serving EIO indefinitely (t+${t_w:-never}s, bound ${BOUND}s)"
grep -q 'P305-RESV-HEALTH\|P305-RESV-SELF-GONE-INSPECT\|P277-RESV-CONFLICT' "$OUT/victim_dmesg.txt"
chk $? "the loss of our own registration was reported, not silent"

mounted=$(rs "$VICTIM" 20 "grep -c ' $MNT mxfs ' /proc/mounts" | tr -d '\r\n')
shut=$(rs "$VICTIM" 20 "dmesg | grep -c 'Shutting down filesystem'" | tr -d '\r\n')
echo "   victim: still_mounted=$mounted shutdown_lines=$shut"

# ---------------------------------------------------------------------------
# 4. The peer must be unharmed: one node losing its registration is not a
#    reason for the other to stop.
# ---------------------------------------------------------------------------
say "4. the peer must be unaffected"
pm=$(rs "$PEER" 20 "grep -c ' $MNT mxfs ' /proc/mounts" | tr -d '\r\n')
ps=$(rs "$PEER" 20 "dmesg | grep -c 'Shutting down filesystem'" | tr -d '\r\n')
echo "   peer: mounted=$pm shutdown_lines=$ps"
[ "$pm" = 1 ]; chk $? "the peer is still mounted"

for n in "$VICTIM" "$PEER"; do
    s=$(rs "$n" 25 "dmesg | grep -acE 'BUG:|Oops|general protection|kernel NULL|Corruption of in-memory'" | tr -d '\r\n')
    case "$s" in ''|*[!0-9]*) s=unknown ;; esac
    echo "   $n splats=$s"
    [ "$s" = 0 ]; chk $? "$n: no kernel splat"
done

# The workload ends on its own deadline; nothing is killed by pattern here.
say "5. leave the victim clean for the next prep"
rs "$VICTIM" 60 "umount -f $MNT 2>/dev/null; grep -c ' $MNT mxfs ' /proc/mounts" >/dev/null

echo
echo "evidence: $OUT"
[ "$fail" = 0 ] && echo "RESULT: PASS (all assertions)" || echo "RESULT: FAIL ($fail assertion(s))"
exit "$fail"
