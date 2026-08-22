#!/bin/bash
# closure_fault_matrix.sh — the sess363 RULE-5 ruling's Hazards-§7 fault
# tests for the out-of-closure purge/scrub (D-REFUSAL-GRANT-FREEZE-OUT-OF-
# CLOSURE-356).
#
# tests/closure_purge_scrub.sh proves the fix WORKS.  This proves it FAILS
# CORRECTLY, which is the harder half: every refusal path in the closure gate
# and the strip CAS is one the ruling requires POSITIVE observation of, and
# none of them occur naturally on a healthy rig.  A gate that never fails has
# only ever demonstrated that nothing asked it.
#
# The safety invariants asserted on EVERY shape, whatever the injected fault:
#   * no survivor shuts down or withdraws, and all stay mounted;
#   * the victim's heartbeat sector is never zeroed (a refused slice must
#     never be published as recovered);
#   * a partial purge is NEVER reported as complete.
# Plus one shape-specific assertion for the path being injected.
#
# Usage: tests/closure_fault_matrix.sh <N> <victim> <shape>
#   gate_read    phase-0 closure-gate sector read -> -EIO.  The PUBLISHER must
#                refuse and strip nothing; the SURVIVOR scrub (whose own gate
#                read is unaffected — the knob is consumable) must still
#                converge and release the blocked prober.  That redundancy is
#                the whole reason the fix has two halves.
#   gate_crc     closure-gate descriptor reads unparseable -> -EPROTO.  Same
#                shape, different predicate arm.
#   gate_mask    a per-CAS REVALIDATION reads a different ag_mask than the
#                caller imported -> -ESTALE mid-scan.  The purge must STOP
#                (P299-CLOSURE-REFROZE) with the CASes already done standing,
#                and must not report complete.
#   gate_percas  a per-CAS gate evaluation fails -> -ESTALE at a CAS boundary.
#   cas_exhaust  every closure-strip CAS miscompares until the retry bound is
#                exhausted -> wfail, P299-CLOSURE-INCOMPLETE, rc=-EIO, and the
#                XFS-layer line must read INCOMPLETE.  This shape deliberately
#                breaks BOTH halves, so the prober is NOT expected to be
#                released — only the reporting invariants hold.
#
# Env: RECOVERY_WAIT (default 150), VICTIM_LOAD (default 6).
# Leaves a durable quarantine — re-prep before anything else.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"

N="${1:?usage: closure_fault_matrix.sh <N> <victim> <shape>}"
VICTIM="${2:?usage: closure_fault_matrix.sh <N> <victim> <shape>}"
SHAPE="${3:?usage: closure_fault_matrix.sh <N> <victim> <shape>}"
SKIP=0
MNT=/mnt/shared
AGMASK=0x2
RECOVERY_WAIT="${RECOVERY_WAIT:-150}"
VICTIM_LOAD="${VICTIM_LOAD:-6}"

[ "$VICTIM" = "${PROBE_HOST:-test1}" ] && { echo "FAIL: victim and probe host are the same node — set PROBE_HOST"; exit 1; }

# knob=count for this shape
case "$SHAPE" in
  gate_read)   KNOB=dl_inject_closure_read;   CNT=1  ;;
  gate_crc)    KNOB=dl_inject_closure_crc;    CNT=1  ;;
  gate_mask)   KNOB=dl_inject_closure_mask;   CNT=1  ;;
  gate_percas) KNOB=caw_inject_closure_gate;  CNT=1; SKIP=2 ;;
  cas_exhaust) KNOB=caw_inject_closure_cas;   CNT=200;;
  *) echo "unknown shape '$SHAPE'"; exit 2 ;;
esac

T0=$(date -u +%FT%TZ)
echo "=== closure_fault_matrix: N=$N victim=$VICTIM shape=$SHAPE ($KNOB=$CNT) @ $T0 ==="

survivors=()
for i in $(seq 1 "$N"); do
    h="test$i"
    [ "$h" = "$VICTIM" ] || survivors+=("$h")
done

echo "--- arming refusal + fault $KNOB=$CNT on ${#survivors[@]} survivors"
for h in "${survivors[@]}"; do
    "$SSH" "$h" "echo $AGMASK > /sys/module/mxfs/parameters/freplay_force_ag_mask;
                 echo 1 > /sys/module/mxfs/parameters/freplay_force_refusal;
                 echo -1 > /sys/module/mxfs/parameters/freplay_force_slot;
                 echo ${SKIP:-0} > /sys/module/mxfs/parameters/caw_inject_closure_gate_skip;
                 echo $CNT > /sys/module/mxfs/parameters/$KNOB;
                 dmesg --clear" >/dev/null 2>&1 &
done
wait
armed=0
for h in "${survivors[@]}"; do
    v=$("$SSH" "$h" "cat /sys/module/mxfs/parameters/freplay_force_refusal;
                     cat /sys/module/mxfs/parameters/$KNOB" 2>/dev/null \
        | tr '\n' ' ' | tr -d '[:space:]')
    [ "$v" = "1$CNT" ] && armed=$((armed+1))
done
[ "$armed" -eq "${#survivors[@]}" ] || {
    echo "FAIL: armed on $armed/${#survivors[@]} survivors — aborting, no kill issued"; exit 1; }
echo "refusal + fault CONFIRMED armed on all $armed survivors"

PROBE_HOST="${PROBE_HOST:-test1}"
[ "$PROBE_HOST" = "$VICTIM" ] && PROBE_HOST=test2

echo "--- victim takes a HOT root-dir EX (${VICTIM_LOAD}s of un-synced churn)"
"$SSH" "$VICTIM" "nohup bash -c '
    end=\$((SECONDS + ${VICTIM_LOAD} + 120))
    i=0
    while [ \$SECONDS -lt \$end ]; do
        i=\$((i+1))
        echo hot > $MNT/.cfm-victim.\$i
        rm -f $MNT/.cfm-victim.\$((i-3))
    done
' >/tmp/cfmload.log 2>&1 &" >/dev/null 2>&1
sleep "$VICTIM_LOAD"
lcnt=$("$SSH" "$PROBE_HOST" "ls -a $MNT/ 2>/dev/null | grep -c cfm-victim" 2>/dev/null | tail -1 | tr -d '[:space:]')
[ "${lcnt:-0}" -gt 0 ] || { echo "FAIL: victim root-dir churn never landed"; exit 1; }
echo "victim holds a hot root-dir EX (${lcnt} churn files visible)"

date -u "+KILL $VICTIM @ %FT%TZ"
sudo virsh -c qemu:///system destroy "$VICTIM" || { echo "FAIL: virsh destroy $VICTIM"; exit 1; }

BLOCK_BUDGET=$(( RECOVERY_WAIT + 60 ))
"$SSH" "$PROBE_HOST" "nohup bash -c '
    s=\$(date +%s)
    timeout $BLOCK_BUDGET touch $MNT/.cfm-blocked; rc=\$?
    echo \"BLOCKED_PROBE rc=\$rc elapsed=\$((\$(date +%s) - s))\" > /tmp/cfmprobe.out
' >/dev/null 2>&1 &" >/dev/null 2>&1
echo "blocked prober launched on $PROBE_HOST (budget ${BLOCK_BUDGET}s)"

echo "waiting ${RECOVERY_WAIT}s for fence+refusal+publish+repair..."
sleep "$RECOVERY_WAIT"

bp=$("$SSH" "$PROBE_HOST" "cat /tmp/cfmprobe.out 2>/dev/null" 2>/dev/null | tr -d '\r' | grep BLOCKED_PROBE | tail -1)
bp_rc=$(echo "$bp" | grep -o 'rc=[0-9]*' | cut -d= -f2)
bp_s=$(echo "$bp" | grep -o 'elapsed=[0-9]*' | cut -d= -f2)
echo "--- blocked prober: ${bp:-<still running>}"

D=$(mktemp -d)
for h in "${survivors[@]}"; do
    "$SSH" "$h" "dmesg" > "$D/$h.dmesg" 2>/dev/null &
done
wait

# disarm everything before any verdict, so a FAIL never leaves the fleet armed
for h in "${survivors[@]}"; do
    "$SSH" "$h" "echo 0 > /sys/module/mxfs/parameters/freplay_force_refusal;
                 echo 1 > /sys/module/mxfs/parameters/freplay_force_ag_mask;
                 echo -1 > /sys/module/mxfs/parameters/freplay_force_slot;
                 echo 0 > /sys/module/mxfs/parameters/$KNOB" >/dev/null 2>&1 &
done
wait

pass=1
inject_n=$(grep -h "P299-INJECT-" "$D"/*.dmesg 2>/dev/null | wc -l)
publishes=$(grep -h "terminal outcome PUBLISHED" "$D"/*.dmesg 2>/dev/null | wc -l)
purged_total=$(grep -h "P299-CLOSURE-PURGE" "$D"/*.dmesg 2>/dev/null |
               grep -o "purged=[0-9]*" | cut -d= -f2 | paste -sd+ - | bc 2>/dev/null)
purged_total=${purged_total:-0}
scrub_n=$(grep -h "P299-SCRUB-STRIP" "$D"/*.dmesg 2>/dev/null | wc -l)
refroze=$(grep -h "P299-CLOSURE-REFROZE" "$D"/*.dmesg 2>/dev/null | wc -l)
incomplete=$(grep -h "P299-CLOSURE-INCOMPLETE" "$D"/*.dmesg 2>/dev/null | wc -l)
gate_ref=$(grep -h "P299-CLOSURE-GATE" "$D"/*.dmesg 2>/dev/null | wc -l)
xfs_incomplete=$(grep -h "grant purge INCOMPLETE" "$D"/*.dmesg 2>/dev/null | wc -l)
xfs_complete=$(grep -h "grant purge complete" "$D"/*.dmesg 2>/dev/null | wc -l)
recovered_pub=$(grep -h "published as recovered\|slice recovery complete" "$D"/*.dmesg 2>/dev/null | wc -l)
shutdowns=$(grep -l "Filesystem has been shut down\|forced shutdown\|MXFS.*withdraw" "$D"/*.dmesg 2>/dev/null | wc -l)

echo "--- universal safety invariants"
echo "injection sites hit (want >=1): $inject_n"
[ "$inject_n" -ge 1 ] || { echo "FAIL: the fault never fired — this run proves NOTHING"; pass=0; }
echo "terminal publishes (want >=1): $publishes"
[ "$publishes" -ge 1 ] || { echo "FAIL: refusal was never published"; pass=0; }
echo "slot published-as-recovered (want 0): $recovered_pub"
[ "$recovered_pub" -eq 0 ] || { echo "FAIL: refused slice published as recovered"; pass=0; }
echo "survivors with shutdown/withdraw (want 0): $shutdowns"
[ "$shutdowns" -eq 0 ] || { echo "FAIL: survivor shutdown under an injected fault"; pass=0; }
mounted=0
for h in "${survivors[@]}"; do
    m=$("$SSH" "$h" "mount | grep -c 'on $MNT type mxfs'" 2>/dev/null | tail -1 | tr -d '[:space:]')
    [ "${m:-0}" -ge 1 ] && mounted=$((mounted+1))
done
echo "survivors still mounted (want ${#survivors[@]}): $mounted"
[ "$mounted" -eq "${#survivors[@]}" ] || { echo "FAIL: survivor lost its mount"; pass=0; }

echo "--- counters: purged=$purged_total scrub=$scrub_n gate_refusals=$gate_ref refroze=$refroze incomplete=$incomplete xfs(complete=$xfs_complete incomplete=$xfs_incomplete)"

echo "--- shape assertion: $SHAPE"
case "$SHAPE" in
gate_read|gate_crc)
    # Publisher must refuse at phase 0 and strip nothing...
    [ "$gate_ref" -ge 1 ] || { echo "FAIL: no P299-CLOSURE-GATE refusal logged"; pass=0; }
    [ "$purged_total" -eq 0 ] || { echo "FAIL: publisher purged $purged_total despite a refused gate"; pass=0; }
    [ "$xfs_complete" -eq 0 ] || { echo "FAIL: a refused purge was logged 'complete'"; pass=0; }
    # ...and the SURVIVOR half must still converge.  This is the redundancy
    # the two-path design exists for: a publisher that cannot prove its
    # authority must not strand the cluster.
    [ "$scrub_n" -ge 1 ] || { echo "FAIL: publisher refused AND the survivor scrub never repaired — the cluster is stranded"; pass=0; }
    if [ "${bp_rc:-1}" -ne 0 ]; then
        echo "FAIL: blocked prober not released (rc=${bp_rc:-<hung>} after ${bp_s:-?}s)"
        pass=0
    else
        echo "blocked prober released after ${bp_s}s via the survivor scrub"
    fi
    ;;
gate_mask|gate_percas)
    # A mid-scan authority/verdict change must STOP the purge, not finish it.
    [ $(( refroze + gate_ref )) -ge 1 ] || { echo "FAIL: no mid-scan stop logged"; pass=0; }
    if [ "$SHAPE" = "gate_percas" ]; then
        # SKIP=2 lets two strips land first, so the ruling's "completed CASes
        # stand" is observable rather than argued.
        echo "strips that landed before the stop (want >=1): $purged_total"
        [ "$purged_total" -ge 1 ] || { echo "FAIL: the stop discarded the CASes that had already succeeded"; pass=0; }
    fi
    [ "$xfs_complete" -eq 0 ] || { echo "FAIL: a stopped purge was logged 'complete'"; pass=0; }
    [ "$xfs_incomplete" -ge 1 ] || { echo "FAIL: the stopped purge was not reported INCOMPLETE"; pass=0; }
    # The scrub is the retry protocol; the prober must still come back.
    if [ "${bp_rc:-1}" -ne 0 ]; then
        echo "FAIL: blocked prober not released (rc=${bp_rc:-<hung>} after ${bp_s:-?}s)"
        pass=0
    else
        echo "blocked prober released after ${bp_s}s"
    fi
    ;;
cas_exhaust)
    # Both halves are broken on purpose here, so the prober is NOT expected
    # back.  What must hold is that nothing claims success.
    [ "$incomplete" -ge 1 ] || { echo "FAIL: CAS exhaustion did not report P299-CLOSURE-INCOMPLETE"; pass=0; }
    [ "$xfs_complete" -eq 0 ] || { echo "FAIL: an incomplete purge was logged 'complete'"; pass=0; }
    [ "$xfs_incomplete" -ge 1 ] || { echo "FAIL: the XFS layer did not report INCOMPLETE"; pass=0; }
    echo "blocked prober (not expected back): rc=${bp_rc:-<hung>} elapsed=${bp_s:-?}s"
    ;;
esac

echo "--- evidence"
grep -h "P299-INJECT-" "$D"/*.dmesg | head -4
grep -h "P299-CLOSURE-GATE\|P299-CLOSURE-REFROZE\|P299-CLOSURE-INCOMPLETE\|P299-CLOSURE-PURGE" "$D"/*.dmesg | head -6
grep -h "grant purge" "$D"/*.dmesg | head -3
grep -h "P299-SCRUB-STRIP" "$D"/*.dmesg | head -3

echo "dmesg harvest kept in $D"
if [ "$pass" -eq 1 ]; then
    echo "=== closure_fault_matrix PASS shape=$SHAPE @ $(date -u +%FT%TZ) ==="
    exit 0
fi
echo "=== closure_fault_matrix FAIL shape=$SHAPE @ $(date -u +%FT%TZ) ==="
exit 1
