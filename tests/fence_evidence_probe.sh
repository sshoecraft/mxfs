#!/bin/bash
# tests/fence_evidence_probe.sh — does a peer death now produce a FENCE
# CERTIFICATE, and does exactly ONE node issue the PREEMPT AND ABORT?
#
# WHY THIS EXISTS (sess93)
#   sess91 proved by exhaustive grep that the whole fence-evidence subsystem —
#   fence_intent / fence_certify / fence_takeover / recovery_claim /
#   replay_authorized, shipped in 0.11.415-416 with an on-disk wire format and a
#   proto_gen bump — had ZERO callers.  Every descriptor the cluster published
#   reached stage=FENCED with fence_kind=NONE via recovery_begin(), i.e. an
#   uncertified fence, and every foreign-slice replay ran ungated.  That is the
#   mechanism behind D-FENCED-STAGE-WITHOUT-PROVEN-EXCLUSION and
#   D-VICTIM-REPLAY-WITHOUT-PROVEN-EXCLUSION.
#
#   0.11.422 wires it.  This probe is the positive test: it must show a real
#   certificate being produced by one node and CONSUMED by the (usually
#   different) elected replayer.
#
# THE MEASUREMENT — no injection.  Hard-kill one node and read the logs.
#
# WHAT IT ASSERTS
#   1. SINGLE PROVER.  Exactly ONE survivor logs P236-FENCE-INTENT for the
#      victim's slot, and exactly ONE logs P236-FENCEKIND.  This is the direct
#      evidence for the sess93 RULE-5 ruling Q1: "one durable intent, one
#      issuing prover, one command result, one possible certificate."  Before
#      0.11.422 all 31 survivors issued a PREEMPT AND ABORT, 30 of them losing
#      the race — and a loser that removes the key first makes the intent
#      owner observe KEY_ABSENT_UNPROVEN, converting a provable fence into an
#      unrecoverable one.  A count of 31 here IS that defect.
#   2. CERTIFICATE EXISTS.  Exactly one P236-FENCE-CERTIFIED for the slot.
#   3. CERTIFICATE IS CONSUMED.  Some node logs P238-RECOV-LEASE for the slot —
#      the elected replayer taking the execution lease against that proof.
#      Whether it is the same node as the prover is RECORDED, not asserted:
#      sess73 measured them differing, which is the entire reason the channel
#      exists.
#   4. RECOVERY PUBLISHES.  P163-RECOVERY-COMPLETE for the slot.  A gate that
#      is correct but blocks every recovery is not a fix.
#   5. NO UNGATED WORK.  Zero P238-COMPLETE-UNFENCED anywhere.
#
# TIMING (RULE 0 — derived, not chosen)
#   declare dead : DEAD_THRESHOLD(31) * HB_INTERVAL_MS(2000)      = 62s
#   fence        : intent CAS + READ KEYS + P&A + verify + certify
#                  (5 SCSI round trips + 2 CAW writes)            ~  5s
#   dispatch+replay+publish                                       ~ 20s
#                                                                 = 87s
#   WINDOW default 150 is that plus ssh/log-harvest slack.  A run that needs
#   longer has found something and should be reported, not waited out.
#
# NOTE: this leaves the victim VM destroyed.  Re-prep afterwards:
#   MXFS_FORCE_PREP=1 ./run.sh 32 caw prep_cluster
#
# usage: fence_evidence_probe.sh [victim=test32] [window_s=150]
set -u
VICTIM="${1:-test32}"
WINDOW_S="${2:-150}"
NODES_N="${MXFS_NODES:-32}"

cd "$(dirname "$0")/.." || exit 2
SSH=tools/mxfs_sshpass.sh

MARK="FENCEV-$$-$(date -u +%s)"
echo "probe: victim=$VICTIM nodes=$NODES_N window=${WINDOW_S}s mark=$MARK"

claim=$($SSH "$VICTIM" \
    "dmesg | grep -a 'claimed heartbeat slot' | tail -1; \
     journalctl -k --no-pager 2>/dev/null | grep -a 'claimed heartbeat slot' | tail -1" \
    2>/dev/null | grep -a 'claimed heartbeat slot' | tail -1)
SLOT=$(printf '%s\n' "$claim" | sed -n 's/.*claimed heartbeat slot \([0-9]*\) .*/\1/p')
NODEID=$(printf '%s\n' "$claim" | sed -n 's/.*for node \([0-9]*\).*/\1/p')
[ -n "${SLOT:-}" ] && [ -n "${NODEID:-}" ] || {
    echo "probe: could not learn $VICTIM's slot/node_id: '$claim'" >&2; exit 2; }
echo "probe: victim slot=$SLOT node=$NODEID"

SURV=()
for i in $(seq 1 "$NODES_N"); do [ "test$i" = "$VICTIM" ] || SURV+=("test$i"); done

# Window marker on every survivor, so the harvest scopes to THIS death and not
# to a previous run still sitting in the ring buffer (the sess42 staleness trap).
for n in "${SURV[@]}"; do ( $SSH "$n" "echo '$MARK' > /dev/kmsg" >/dev/null 2>&1 ) & done
wait

echo "probe: destroying $VICTIM at $(date -u +%H:%M:%S)Z"
virsh -c qemu:///system destroy "$VICTIM" >/dev/null 2>&1 || {
    echo "probe: virsh destroy failed" >&2; exit 2; }

echo "probe: waiting ${WINDOW_S}s for detect -> fence -> certify -> claim -> publish"
sleep "$WINDOW_S"

TD=$(mktemp -d)
for n in "${SURV[@]}"; do
    ( $SSH "$n" "dmesg | sed -n '/$MARK/,\$p'" > "$TD/$n.log" 2>/dev/null ) &
done
wait

# ── harvest ────────────────────────────────────────────────────────────────
count_nodes() {   # count_nodes <grep-pattern> -> "N node1 node2 ..."
    local pat="$1" n c=0 lst=""
    for n in "${SURV[@]}"; do
        if grep -qa -- "$pat" "$TD/$n.log" 2>/dev/null; then
            c=$((c+1)); lst="$lst $n"
        fi
    done
    printf '%d%s\n' "$c" "$lst"
}

INTENT=$(count_nodes "P236-FENCE-INTENT slot=$SLOT ")
KIND=$(count_nodes "P236-FENCEKIND node=$NODEID ")
CERT=$(count_nodes "P236-FENCE-CERTIFIED slot=$SLOT ")
LEASE=$(count_nodes "P238-RECOV-LEASE slot=$SLOT ")
DONE=$(count_nodes "P163-RECOVERY-COMPLETE slot=$SLOT ")
UNFENCED=$(count_nodes "P238-COMPLETE-UNFENCED slot=$SLOT ")
REFUSED=$(count_nodes "P236-REPLAY-REFUSED site=.* slot=$SLOT ")
WAIT=$(count_nodes "foreign replay slot=$SLOT: NOT replayed")

echo
echo "=== fence-evidence probe: slot=$SLOT node=$NODEID ==="
printf '  intent (P236-FENCE-INTENT)      nodes=%s\n' "$INTENT"
printf '  P&A issued (P236-FENCEKIND)     nodes=%s\n' "$KIND"
printf '  certified (P236-FENCE-CERTIFIED) nodes=%s\n' "$CERT"
printf '  lease taken (P238-RECOV-LEASE)  nodes=%s\n' "$LEASE"
printf '  published (P163-RECOVERY-COMPLETE) nodes=%s\n' "$DONE"
printf '  gate waits (replay refused)     nodes=%s\n' "$WAIT"
printf '  UNGATED completes (must be 0)   nodes=%s\n' "$UNFENCED"
printf '  gate refusals (P236-REPLAY-REFUSED) nodes=%s\n' "$REFUSED"
echo
echo "--- the actual certificate lines ---"
grep -ha "P236-FENCE-INTENT slot=$SLOT \|P236-FENCE-CERTIFIED slot=$SLOT \|P236-FENCEKIND node=$NODEID \|P238-RECOV-LEASE slot=$SLOT \|P163-RECOVERY-COMPLETE slot=$SLOT " \
    "$TD"/*.log 2>/dev/null | sed 's/^/  /' | head -30
echo
echo "--- refusals / blocked states (expected non-empty only on failure) ---"
grep -ha "P238-FENCE-\|P238-COMPLETE-\|P238-RECOV-TAKEOVER\|P236-REPLAY-REFUSED\|P236-CLAIM-UNCERTIFIED" \
    "$TD"/*.log 2>/dev/null | sed 's/^/  /' | head -20

fail=0
[ "${INTENT%% *}" = 1 ]  || { echo "FAIL: intent nodes=${INTENT%% *}, want exactly 1 (single-prover rule)"; fail=1; }
[ "${KIND%% *}" = 1 ]    || { echo "FAIL: PREEMPT-AND-ABORT issued by ${KIND%% *} nodes, want exactly 1"; fail=1; }
[ "${CERT%% *}" = 1 ]    || { echo "FAIL: certificates=${CERT%% *}, want exactly 1"; fail=1; }
[ "${LEASE%% *}" -ge 1 ] || { echo "FAIL: no node took the execution lease — the certificate was not consumed"; fail=1; }
[ "${DONE%% *}" -ge 1 ]  || { echo "FAIL: recovery never published — the gate blocks a legitimate recovery"; fail=1; }
[ "${UNFENCED%% *}" = 0 ] || { echo "FAIL: ${UNFENCED%% *} node(s) completed a recovery with NO certificate"; fail=1; }

echo
if [ "$fail" = 0 ]; then
    echo "PROBE PASS — one prover, one certificate, consumed, recovery published"
else
    echo "PROBE FAIL — logs kept in $TD"
fi
echo "logs: $TD"
exit "$fail"
