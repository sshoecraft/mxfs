#!/bin/bash
# tests/pr_reregister_probe.sh — after a PREEMPT AND ABORT removes a node's PR
# key, can that node simply register again and resume writing to the shared LUN?
#
# WHY THIS EXISTS (D-FENCED-VICTIM-MAY-REREGISTER, filed sess93)
#   The 0.11.422 fence-evidence channel authorises a foreign-slice replay on a
#   certificate whose strongest claim is MXFS_FENCE_KIND_PREEMPT_ABORT_DONE:
#   "the victim's task set was aborted and its registration removed, with a
#   WE-RO reservation held".  That is a statement about a POINT IN TIME.  The
#   replay it authorises runs for seconds afterwards.
#
#   GPT (RULE-5 ruling sess93, release-blocking requirement B): "A successful
#   P&A proves the old registration was excluded at a point in time.  It does
#   not necessarily prevent a still-running victim from registering again...
#   If a partitioned old node can simply register its key again, the
#   certificate is only historical evidence and is not enough to protect
#   replay."
#
#   MXFS's answer today is COOPERATIVE: mxfs_scsipr_self_check notices the key
#   is gone and the node force-shuts-down (P131-SELF-FENCE, no auto
#   re-register).  That depends on the victim's own kernel still running and
#   still scheduling — which is exactly what is in doubt about a node we just
#   declared dead.  This probe measures what the TARGET enforces, independent
#   of what MXFS chooses to do.
#
# THE MEASUREMENT — four steps, at the SCSI layer, bypassing MXFS entirely:
#   1. baseline: victim writes the scratch LBA           -> must SUCCEED
#   2. a survivor issues PREEMPT AND ABORT of the victim's key
#   3. victim writes the scratch LBA                     -> must FAIL (conflict)
#      (if it does not, exclusion never worked at all and everything above it
#       is void — that is a far bigger finding than the one being tested)
#   4. victim issues REGISTER_AND_IGNORE with a fresh key, then writes again
#      -> if BOTH succeed, D-FENCED-VICTIM-MAY-REREGISTER is CONFIRMED: the
#         certificate does not exclude the victim for the duration of the
#         replay, and the only thing standing between a partitioned node and
#         the shared metadata is that node's own cooperation.
#      -> if either is refused by the target, the defect is DISPROVED on this
#         topology and the reason must be recorded.
#
#   The scratch LBA is 131087 — the sector immediately below the disklock table
#   (byte 67117056 = LBA 131088), the same one tools/caw_verify and the shipped
#   dlm_lock_correctness criterion have used on every board run.
#
# NOTE: this preempts a live node's key, so that node WILL self-fence and its
#   slice WILL be recovered by the cluster — a real fence, deliberately.
#   Re-prep afterwards:  MXFS_FORCE_PREP=1 ./run.sh 32 caw prep_cluster
#
# usage: pr_reregister_probe.sh [victim=test32] [preemptor=test1]
set -u
VICTIM="${1:-test32}"
PRE="${2:-test1}"
DEV="${MXFS_DEV:-/dev/mapper/mpatha}"
SCRATCH_LBA="${MXFS_SCRATCH_LBA:-131087}"

cd "$(dirname "$0")/.." || exit 2
SSH=tools/mxfs_sshpass.sh
[ "$VICTIM" = "$PRE" ] && { echo "probe: victim and preemptor must differ" >&2; exit 2; }

nodeid_of() {
    $SSH "$1" "dmesg | grep -a 'claimed heartbeat slot' | tail -1" 2>/dev/null \
        | sed -n 's/.*for node \([0-9]*\).*/\1/p'
}
VID=$(nodeid_of "$VICTIM"); PID=$(nodeid_of "$PRE")
[ -n "${VID:-}" ] && [ -n "${PID:-}" ] || {
    echo "probe: could not learn node ids (victim='$VID' preemptor='$PID')" >&2; exit 2; }
VKEY=$(printf '0x%x' "$VID"); PKEY=$(printf '0x%x' "$PID")
echo "probe: victim=$VICTIM key=$VKEY   preemptor=$PRE key=$PKEY   dev=$DEV lba=$SCRATCH_LBA"

echo
echo "--- reservation before ---"
$SSH "$PRE" "sg_persist --in --read-reservation $DEV" 2>/dev/null | tail -3

# ── 1. baseline write from the victim ──────────────────────────────────────
echo
echo "--- 1. baseline: victim writes the scratch LBA (expect SUCCESS) ---"
b1=$($SSH "$VICTIM" "/src/mxfs/tools/caw_verify --retry-ua write $DEV $SCRATCH_LBA 0xa5 2>&1; echo rc=\$?" 2>/dev/null)
echo "$b1" | tail -3
BASE_RC=$(printf '%s\n' "$b1" | sed -n 's/^rc=//p' | tail -1)

# ── 2. PREEMPT AND ABORT from the survivor ─────────────────────────────────
echo
echo "--- 2. $PRE issues PREEMPT AND ABORT of $VKEY ---"
$SSH "$PRE" "sg_persist --out --preempt-abort --param-rk=$PKEY --param-sark=$VKEY \
             --prout-type=5 $DEV 2>&1; echo rc=\$?" 2>/dev/null | tail -4

sleep 1
echo "--- victim key still registered? ---"
STILL=$($SSH "$PRE" "sg_persist --in --read-keys $DEV" 2>/dev/null | grep -c -i "$VKEY")
echo "  descriptors matching $VKEY: $STILL   (0 = removed)"

# ── 3. victim writes again (expect REFUSED) ────────────────────────────────
echo
echo "--- 3. victim writes the scratch LBA after being preempted (expect FAIL) ---"
b3=$($SSH "$VICTIM" "/src/mxfs/tools/caw_verify --retry-ua write $DEV $SCRATCH_LBA 0x5a 2>&1; echo rc=\$?" 2>/dev/null)
echo "$b3" | tail -3
FENCED_RC=$(printf '%s\n' "$b3" | sed -n 's/^rc=//p' | tail -1)

# ── 4. can the victim re-register, and then write? ─────────────────────────
NEWKEY=0xfeed0001
echo
echo "--- 4a. victim issues REGISTER_AND_IGNORE with a fresh key $NEWKEY ---"
r4=$($SSH "$VICTIM" "sg_persist --out --register-ignore --param-sark=$NEWKEY $DEV 2>&1; echo rc=\$?" 2>/dev/null)
echo "$r4" | tail -4
REG_RC=$(printf '%s\n' "$r4" | sed -n 's/^rc=//p' | tail -1)

echo
echo "--- 4b. victim writes the scratch LBA as a fresh registrant ---"
b4=$($SSH "$VICTIM" "/src/mxfs/tools/caw_verify --retry-ua write $DEV $SCRATCH_LBA 0x33 2>&1; echo rc=\$?" 2>/dev/null)
echo "$b4" | tail -3
REWRITE_RC=$(printf '%s\n' "$b4" | sed -n 's/^rc=//p' | tail -1)

echo
echo "=========================== VERDICT ==========================="
printf '  1. baseline write (pre-fence)      rc=%s  %s\n' "${BASE_RC:-?}" \
       "$([ "${BASE_RC:-1}" = 0 ] && echo 'SUCCESS (as expected)' || echo '*** UNEXPECTED FAILURE — the rest of this probe is void ***')"
printf '  2. victim key descriptors left     %s\n' "$STILL"
printf '  3. write after PREEMPT AND ABORT   rc=%s  %s\n' "${FENCED_RC:-?}" \
       "$([ "${FENCED_RC:-0}" != 0 ] && echo 'REFUSED (exclusion works)' || echo '*** ACCEPTED — exclusion NEVER worked; every fence certificate is void ***')"
printf '  4a. re-registration by the victim  rc=%s  %s\n' "${REG_RC:-?}" \
       "$([ "${REG_RC:-1}" = 0 ] && echo 'ACCEPTED by the target' || echo 'REFUSED by the target')"
printf '  4b. write as a fresh registrant    rc=%s  %s\n' "${REWRITE_RC:-?}" \
       "$([ "${REWRITE_RC:-1}" = 0 ] && echo 'ACCEPTED' || echo 'REFUSED')"
echo
if [ "${BASE_RC:-1}" != 0 ]; then
    echo "INCONCLUSIVE — the victim could not write even before the fence."
    exit 2
fi
if [ "${FENCED_RC:-0}" = 0 ]; then
    echo "CRITICAL — the PREEMPT AND ABORT did not exclude the victim at all."
    exit 1
fi
if [ "${REG_RC:-1}" = 0 ] && [ "${REWRITE_RC:-1}" = 0 ]; then
    echo "D-FENCED-VICTIM-MAY-REREGISTER: CONFIRMED."
    echo "  A preempted node re-registered and wrote to the shared LUN.  The fence"
    echo "  certificate proves exclusion only at the instant of the P&A; for the"
    echo "  duration of the replay it authorises, the ONLY thing keeping the victim"
    echo "  off the LUN is that victim's own self-fence — i.e. its cooperation."
    exit 1
fi
echo "D-FENCED-VICTIM-MAY-REREGISTER: NOT reproduced on this topology."
echo "  Record WHICH step the target refused and why before treating this as"
echo "  DISPROVED — a refusal that depends on target configuration is not a"
echo "  property of the protocol."
exit 0
