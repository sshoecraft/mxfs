#!/bin/bash
# tests/excl_lapse_probe.sh — if the fenced victim comes BACK mid-recovery, does
# the recovery stop?
#
# WHY THIS EXISTS (sess93)
#   tests/pr_reregister_probe.sh MEASURED that a PREEMPT-AND-ABORTed node can
#   re-register with a fresh key and write to the shared LUN seconds later.  So
#   the fence certificate is evidence of a completed EVICTION EVENT, not
#   evidence that the host stays fenced (GPT RULE-5 ruling, sess93 follow-up:
#   "PREEMPT AND ABORT alone is ... not evidence that the host remains fenced").
#
#   0.11.423 adds mxfs_scsipr_exclusion_holds() and calls it at four points —
#   after a fresh claim, after a re-acquire, after a takeover, and once more
#   immediately before the irreversible CAW authority purge.  GPT ranked this
#   "detect-only; useful, but not safety enforcement" and was explicit about the
#   required behaviour on detection: "do not continue replay.  Enter a
#   failed/blocked state."  This probe checks that it actually does.
#
# THE INJECTION
#   A real death cannot test this: virsh destroy is a power cut, so the victim
#   is GONE and can never re-register.  Instead, once the certificate is durable,
#   a SURVIVOR registers the victim's key value on its own I_T nexus.  From the
#   target's point of view that key is registered again — which is exactly the
#   state a returning victim produces, and exactly what the re-check looks for.
#
# WHAT IT ASSERTS
#   1. Some node logs P239-EXCL-RETURNED or P239-EXCL-LAPSED for the victim.
#   2. NO node logs P163-RECOVERY-COMPLETE for the slot: the recovery STOPPED.
#      A detector that fires and then publishes anyway is worse than no detector.
#
# NOTE: on success this deliberately leaves the slice unrecovered and its grants
#   frozen — that is the fail-closed outcome under test.  Re-prep afterwards:
#   MXFS_FORCE_PREP=1 ./run.sh 32 caw prep_cluster
#
# TIMING (RULE 0 — derived)
#   certificate appears : DEAD_THRESHOLD(31) * HB_INTERVAL_MS(2000) + fence = 65s
#   -> CERT_S 150 (slack for a slow scan phase)
#   replay window       : claim -> replay -> complete                      ~ 10s
#   -> OBSERVE_S 90 is well past it, so "never completed" is a real verdict
#      and not just an impatient one.
#
# usage: excl_lapse_probe.sh [victim=test32] [injector=test1] [cert_s=150] [observe_s=90]
set -u
VICTIM="${1:-test32}"
INJ="${2:-test1}"
CERT_S="${3:-150}"
OBSERVE_S="${4:-90}"
DEV="${MXFS_DEV:-/dev/mapper/mpatha}"
NODES_N="${MXFS_NODES:-32}"
IMG="${MXFS_BACKING_IMG:-/home/steve/disk.img}"

cd "$(dirname "$0")/.." || exit 2
SSH=tools/mxfs_sshpass.sh
[ "$VICTIM" = "$INJ" ] && { echo "probe: victim and injector must differ" >&2; exit 2; }
[ -r "$IMG" ] || { echo "probe: cannot read backing store $IMG" >&2; exit 2; }

claim=$($SSH "$VICTIM" "dmesg | grep -a 'claimed heartbeat slot' | tail -1" 2>/dev/null)
SLOT=$(printf '%s\n' "$claim" | sed -n 's/.*claimed heartbeat slot \([0-9]*\) .*/\1/p')
VID=$(printf '%s\n' "$claim" | sed -n 's/.*for node \([0-9]*\).*/\1/p')
[ -n "${SLOT:-}" ] && [ -n "${VID:-}" ] || {
    echo "probe: could not learn $VICTIM's slot/node id" >&2; exit 2; }
VKEY=$(printf '0x%x' "$VID")
echo "probe: victim=$VICTIM slot=$SLOT node=$VID key=$VKEY injector=$INJ"

MARK="EXCLLAPSE-$$-$(date -u +%s)"
SURV=()
for i in $(seq 1 "$NODES_N"); do [ "test$i" = "$VICTIM" ] || SURV+=("test$i"); done
for n in "${SURV[@]}"; do ( $SSH "$n" "echo '$MARK' > /dev/kmsg" >/dev/null 2>&1 ) & done
wait

echo "probe: destroying $VICTIM at $(date -u +%H:%M:%S)Z"
virsh -c qemu:///system destroy "$VICTIM" >/dev/null 2>&1 || {
    echo "probe: virsh destroy failed" >&2; exit 2; }

# Wait — on this host, with O_DIRECT — for the certificate to be durable.
SLOT="$SLOT" IMG="$IMG" CERT_S="$CERT_S" python3 - <<'PYEOF'
import os, struct, mmap, time, sys
SLOT=int(os.environ['SLOT']); IMG=os.environ['IMG']; CERT_S=float(os.environ['CERT_S'])
MAGIC=0x4D584C4B; GUARD=3; DESC_OFF=40; DESC_MAGIC=0x5643524D
ST_OFF=DESC_OFF+6; KIND_OFF=DESC_OFF+8      # stage, then fence_kind
FENCED=2
fd=os.open(IMG, os.O_RDONLY|os.O_DIRECT)
buf=mmap.mmap(-1,4096); mv=memoryview(buf)
def dread(off,n):
    os.preadv(fd,[mv[:n]],off); return bytes(mv[:n])
dloff,=struct.unpack_from('<Q',dread(0,4096),64)
off=dloff+SLOT*512
t0=time.time()
while time.time()-t0 < CERT_S:
    r=dread(off,512)
    magic,flags=struct.unpack_from('<II',r,0)
    dm,=struct.unpack_from('<I',r,DESC_OFF)
    if magic==MAGIC and flags==GUARD and dm==DESC_MAGIC:
        stage,=struct.unpack_from('<H',r,ST_OFF)
        if stage>=FENCED:
            print('CERTIFIED at t+%.1fs (stage=%u)'%(time.time()-t0,stage))
            sys.exit(0)
    time.sleep(0.05)
print('TIMEOUT: no certificate within %ds'%CERT_S); sys.exit(2)
PYEOF
[ $? -eq 0 ] || { echo "probe: ABORT — no certificate appeared" >&2; exit 2; }

echo "probe: injecting the victim's return — $INJ registers key $VKEY"
$SSH "$INJ" "sg_persist --out --register-ignore --param-sark=$VKEY $DEV 2>&1; echo rc=\$?" \
    2>/dev/null | tail -2

echo "probe: observing ${OBSERVE_S}s"
sleep "$OBSERVE_S"

TD=$(mktemp -d)
for n in "${SURV[@]}"; do
    ( $SSH "$n" "dmesg | sed -n '/$MARK/,\$p'" > "$TD/$n.log" 2>/dev/null ) &
done
wait

count_nodes() {
    local pat="$1" n c=0 lst=""
    for n in "${SURV[@]}"; do
        if grep -qa -- "$pat" "$TD/$n.log" 2>/dev/null; then c=$((c+1)); lst="$lst $n"; fi
    done
    printf '%d%s\n' "$c" "$lst"
}
LAPSED=$(count_nodes "P239-EXCL-LAPSED")
RET=$(count_nodes "P239-EXCL-RETURNED")
DONE=$(count_nodes "P163-RECOVERY-COMPLETE slot=$SLOT ")

echo
echo "=== exclusion-lapse probe: victim slot=$SLOT key=$VKEY ==="
printf '  detector fired (P239-EXCL-LAPSED)     nodes=%s\n' "$LAPSED"
printf '  cause logged  (P239-EXCL-RETURNED)    nodes=%s\n' "$RET"
printf '  recovery published (must be 0)        nodes=%s\n' "$DONE"
echo
echo "--- /sys/kernel/debug/mxfs/*/recovery_blocked (the OBSERVABLE state) ---"
BLK=0
for n in "${SURV[@]}"; do
    out=$($SSH "$n" "cat /sys/kernel/debug/mxfs/*/recovery_blocked 2>/dev/null" 2>/dev/null \
          | grep -v "Unauthorized access\|not an authorized")
    if [ -n "${out//[[:space:]]/}" ]; then
        BLK=$((BLK+1))
        [ "$BLK" = 1 ] && { echo "  [$n]"; printf '%s\n' "$out" | sed 's/^/    /'; }
    fi
done
echo "  nodes reporting a blocked slice: $BLK"

echo
echo "--- the detector lines ---"
grep -ha "P239-EXCL-\|P238-RECOV-LEASE slot=$SLOT \|P163-RECOVERY-COMPLETE slot=$SLOT " \
    "$TD"/*.log 2>/dev/null | sed 's/^/  /' | head -15

fail=0
[ "${LAPSED%% *}" -ge 1 ] || { echo "FAIL: the re-check never fired — a returned victim went unnoticed"; fail=1; }
[ "${DONE%% *}" = 0 ] || { echo "FAIL: recovery published anyway (${DONE%% *} node(s)) — the detector fired and was ignored"; fail=1; }
[ "$BLK" -ge 1 ] || { echo "FAIL: no node surfaced the block in debugfs — it is only in dmesg, i.e. indistinguishable from a hang"; fail=1; }
echo
[ "$fail" = 0 ] && echo "PROBE PASS — the returned victim was detected and the recovery STOPPED" \
                || echo "PROBE FAIL — logs kept in $TD"
echo "logs: $TD"
exit "$fail"
