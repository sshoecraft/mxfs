#!/bin/bash
# pr_unregister_fail_restamp.sh — D-CLEAN-RELEASE-THEN-UNREGISTER-FAIL-LEAVES-
# UNFENCEABLE-STALE-REGISTRANT-0356 and phase (v) of the sess377 two-phase
# departure (D-PR-RETIREMENT-FAILURE-NOT-FAIL-CLOSED-377), landed 0.58.0;
# 0.59.0 (sess450) made the release stamp RETIRE_PENDING so the handoff
# survives a crash between the release and the unregister.
#
# MODES (4th arg, default restamp):
#   restamp  the 0.58.0 arm below: unregister fails, the victim re-stamps
#            WITHDRAWN itself (P303).  Also asserts the 0.59.0 release stamp
#            (P304-RETIRE-PENDING-RELEASED on the victim) and, in the control
#            umount, the CLEAN path: a peer completes the retirement
#            (P304-RETIRE-COMPLETED-BY-PEER) and retires the tracking
#            (P163-CLEAN-DEPART), the key absent, no fence.
#   crash    unregister fails AND the re-stamp is skipped
#            (dbg_retire_skip_restamp=1) — models a crash after the
#            RETIRE_PENDING stamp.  Peers must settle it alone:
#            P304-RETIRE-PENDING-SEEN, then (key present past the 30 s grace)
#            P304-RETIRE-EXPIRED-WITHDRAWN -> P163-WITHDRAW-SEEN -> fence
#            certified -> key absent; victim remounts without P305.
#
# THE INVARIANT: a clean departure whose late PR unregister cannot prove the
# key gone must NOT leave slot=RELEASED + key=PRESENT (unfenceable: nothing
# names the incarnation, this initiator keeps write privilege forever, and
# the host's own next mount is refused with P305-PR-PREDECESSOR-KEY-PRESENT).
# The departing node now CASes its RELEASED record back to WITHDRAWN with the
# key (P303-RETIRE-PENDING-RESTAMPED), which is the durable "storage
# authority retirement pending" handoff: peers take the sess9 withdraw path
# on first sight (P163-WITHDRAW-SEEN) -> PREEMPT AND ABORT the key
# (P236-FENCE-CERTIFIED kind 16) -> replay the clean slice -> purge the slot.
#
# Sequence (cluster must be prepped and mounted, N nodes):
#   1. snapshot the PR key table (chk_mxfs --pr-keys from PROBE)
#   2. arm mxfs.dbg_pr_unregister_fail=1 on VICTIM (one-shot: the late
#      unregister reports NOT RETIRED without issuing it — the key STAYS)
#   3. clean umount on VICTIM; assert its dmesg has P301-DEPARTURE-INCOMPLETE
#      AND P303-RETIRE-PENDING-RESTAMPED ... rc=0 (no P303-INDETERMINATE)
#   4. wait for a peer: P163-WITHDRAW-SEEN node=<victim> and
#      P236-FENCE-CERTIFIED victim=<victim> within FENCE_WAIT; then the
#      victim's key must be ABSENT from --pr-keys (the fence retired it)
#   5. VICTIM remounts via tests/setup/prep_node.sh -> NODE_PREP_OK with NO
#      P305-PR-PREDECESSOR-KEY-PRESENT (the host is not locked out)
#   6. negative control: a second clean umount of VICTIM with the knob OFF
#      leaves no P303 line and its key absent (the ordinary path is intact)
#
# Usage: tests/pr_unregister_fail_restamp.sh <N> <victim> [probe] [mode]
#   N       nodes prepped (test1..testN); victim != probe; probe default test1
# budget: umount ≤ 15 s + WITHDRAWN first-sight (monitor lap ≤ 5 s) + fence
# + replay of a clean slice + purge ≈ 30 s (FENCE_WAIT 90 s bound) + remount
# via prep_node ≈ 40 s + control umount/remount ≈ 60 s → bound 300 s.
# crash mode adds the 30 s retirement grace (FENCE_WAIT 120) → bound 330 s.
# Exit 0 PASS, 1 FAIL, 2 INFRA-FAIL.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"
N="${1:?usage: pr_unregister_fail_restamp.sh <N> <victim> [probe]}"
VICTIM="${2:?usage}"
PROBE="${3:-test1}"
MODE="${4:-restamp}"
MNT=/mnt/shared
case "$MODE" in restamp) FENCE_WAIT="${FENCE_WAIT:-90}";; crash) FENCE_WAIT="${FENCE_WAIT:-120}";; *) echo "FAIL: mode $MODE"; exit 1;; esac
KNOB=/sys/module/mxfs/parameters/dbg_pr_unregister_fail
KNOB2=/sys/module/mxfs/parameters/dbg_retire_skip_restamp
CHK=/src/mxfs/tools/chk_mxfs
# sess53 (2-node TCP rig): prep_node.sh's first argument is the transport the
# remount loads the module for; it was hardcoded to caw.
TRANSPORT=${MXFS_TRANSPORT:-caw}
[ "$VICTIM" = "$PROBE" ] && { echo "FAIL: victim == probe"; exit 1; }
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUT="$REPO/tests/evidence/${STAMP}_pr_restamp"
mkdir -p "$OUT"
FAILS=0
say() { echo "[pr_restamp] $*"; }

DEV=$("$SSH" "$VICTIM" "mount -t mxfs | awk '{print \$1; exit}'" 2>/dev/null | tr -d ' \r\n')
[ -n "$DEV" ] || { say "INFRA-FAIL: $VICTIM has no mxfs mount"; exit 2; }
keys() { timeout 40 "$SSH" "$PROBE" "$CHK --pr-keys $DEV" 2>/dev/null | grep -oE '^  0x[0-9a-f]+' | tr -d ' ' | sort -u; }
echo "=== pr_unregister_fail_restamp: N=$N victim=$VICTIM probe=$PROBE mode=$MODE dev=$DEV @ $STAMP ==="
keys > "$OUT/keys_before.txt"; say "keys before: $(wc -l < "$OUT/keys_before.txt")"

# 2. arm + 3. umount
v=$("$SSH" "$VICTIM" "echo 1 > $KNOB && cat $KNOB" 2>/dev/null | tail -1 | tr -d '[:space:]')
[ "$v" = 1 ] || { say "INFRA-FAIL: knob not armed on $VICTIM (module lacks dbg_pr_unregister_fail?)"; exit 2; }
if [ "$MODE" = crash ]; then
    v=$("$SSH" "$VICTIM" "echo 1 > $KNOB2 && cat $KNOB2" 2>/dev/null | tail -1 | tr -d '[:space:]')
    [ "$v" = 1 ] || { say "INFRA-FAIL: crash knob not armed on $VICTIM (module lacks dbg_retire_skip_restamp?)"; exit 2; }
fi
for i in $(seq 1 "$N"); do "$SSH" "test$i" "dmesg --clear" >/dev/null 2>&1 & done; wait
T0=$(date +%s)
"$SSH" "$VICTIM" "timeout 60 umount $MNT; echo UMOUNT_RC=\$?; sleep 1; dmesg" > "$OUT/victim_umount.log" 2>&1
say "umount wall $(( $(date +%s) - T0 )) s rc=$(sed -n 's/^UMOUNT_RC=//p' "$OUT/victim_umount.log")"
# sess455: normalise to chk_mxfs's 16-digit padded form (kernel prints 0x%llx
# unpadded; a key with a zero top nibble otherwise reads as absent)
KEY=$(grep -o 'P301-DEPARTURE-INCOMPLETE PR key 0x[0-9a-f]*' "$OUT/victim_umount.log" | head -1 | grep -o '0x[0-9a-f]*')
[ -n "$KEY" ] && KEY=$(printf '0x%016x' "$KEY")
p301=$(grep -c 'P301-DEPARTURE-INCOMPLETE' "$OUT/victim_umount.log")
p303=$(grep -c 'P303-RETIRE-PENDING-RESTAMPED.*rc=0' "$OUT/victim_umount.log")
p303bad=$(grep -c 'P303-DEPARTURE-INDETERMINATE\|P303-RESTAMP-REFUSED\|P303-RESTAMP-READFAIL' "$OUT/victim_umount.log")
rel=$(grep -c 'P304-RETIRE-PENDING-RELEASED' "$OUT/victim_umount.log")
skip=$(grep -c 'P-DBG-RETIRE-SKIP-RESTAMP' "$OUT/victim_umount.log")
say "victim: RELEASED=$rel P301=$p301 P303_ok=$p303 P303_bad=$p303bad skip=$skip key=${KEY:-?}"
[ "$rel" -ge 1 ] || { say "FAIL: release did not stamp RETIRE_PENDING (P304-RETIRE-PENDING-RELEASED missing)"; FAILS=$((FAILS+1)); }
[ "$p301" -ge 1 ] || { say "FAIL: injection did not produce P301 (vacuous)"; FAILS=$((FAILS+1)); }
if [ "$MODE" = restamp ]; then
    [ "$p303" -ge 1 ] || { say "FAIL: no successful P303-RETIRE-PENDING-RESTAMPED"; FAILS=$((FAILS+1)); }
    [ "$p303bad" -eq 0 ] || { say "FAIL: re-stamp refused/indeterminate"; FAILS=$((FAILS+1)); }
else
    [ "$skip" -ge 1 ] || { say "FAIL: crash knob did not fire (vacuous)"; FAILS=$((FAILS+1)); }
    [ "$p303" -eq 0 ] || { say "FAIL: crash arm still re-stamped (P303) — the knob did not model the crash"; FAILS=$((FAILS+1)); }
fi
[ -n "$KEY" ] || { say "FAIL: cannot read the victim key from P301"; FAILS=$((FAILS+1)); }
fleet_count() { # <mark> → sum over peers of dmesg matches (parallel, per-node files)
    local m="$1" d i; d=$(mktemp -d)
    for i in $(seq 1 "$N"); do h="test$i"; [ "$h" = "$VICTIM" ] && continue; timeout 20 "$SSH" "$h" "dmesg | grep -c '$m'" > "$d/$h" 2>/dev/null & done; wait
    cat "$d"/* 2>/dev/null | awk '{s+=$1} END{print s+0}'
}
if [ -n "$KEY" ] && ! keys | grep -qx "$KEY"; then
    # sess452 (chain 68 anomaly, chain 71 restamp lap): in restamp mode the
    # victim's WITHDRAWN re-stamp is fenced by a peer on its next monitor lap
    # (<= 5 s), which is INSIDE this read window (umount + 1 s + dmesg +
    # chk_mxfs --pr-keys); an absence explained by an already-certified fence
    # is the arm's own success path, not a knob failure.  crash mode keeps the
    # key for the 30 s grace, so there the absence is a real failure.
    cf=0; [ "$MODE" = restamp ] && cf=$(fleet_count P236-FENCE-CERTIFIED)
    if [ "$cf" -ge 1 ]; then say "key $KEY absent right after the departure: a peer had ALREADY certified its fence (P236-FENCE-CERTIFIED=$cf inside the read window)"
    else say "FAIL: key $KEY is NOT in the table right after the injected failure — the knob did not model NOT-RETIRED"; FAILS=$((FAILS+1)); fi
fi

# 4. peer fence
seen=0; cert=0; end=$((SECONDS + FENCE_WAIT))
while [ $SECONDS -lt $end ]; do
    for i in $(seq 1 "$N"); do
        h="test$i"; [ "$h" = "$VICTIM" ] && continue
        "$SSH" "$h" "dmesg | grep -c 'P163-WITHDRAW-SEEN'; dmesg | grep -c 'P236-FENCE-CERTIFIED'; dmesg | grep -c 'P304-RETIRE-PENDING-SEEN'; dmesg | grep -c 'P304-RETIRE-EXPIRED-WITHDRAWN'; dmesg | grep -c 'P304-RETIRE-COMPLETED-BY-PEER'" > "$OUT/peer_$h.cnt" 2>/dev/null &
    done; wait
    seen=$(cat "$OUT"/peer_*.cnt 2>/dev/null | awk 'NR%5==1{s+=$1} END{print s+0}')
    cert=$(cat "$OUT"/peer_*.cnt 2>/dev/null | awk 'NR%5==2{s+=$1} END{print s+0}')
    rpseen=$(cat "$OUT"/peer_*.cnt 2>/dev/null | awk 'NR%5==3{s+=$1} END{print s+0}')
    expired=$(cat "$OUT"/peer_*.cnt 2>/dev/null | awk 'NR%5==4{s+=$1} END{print s+0}')
    completed=$(cat "$OUT"/peer_*.cnt 2>/dev/null | awk 'NR%5==0{s+=$1} END{print s+0}')
    [ "$seen" -ge 1 ] && [ "$cert" -ge 1 ] && break
    sleep 5
done
say "peers: WITHDRAW-SEEN=$seen FENCE-CERTIFIED=$cert RETIRE-PENDING-SEEN=$rpseen EXPIRED=$expired COMPLETED-BY-PEER=$completed after $(( SECONDS - (end - FENCE_WAIT) )) s"
[ "$seen" -ge 1 ] || { say "FAIL: no peer saw the WITHDRAWN stamp"; FAILS=$((FAILS+1)); }
[ "$cert" -ge 1 ] || { say "FAIL: no peer certified a fence of the victim"; FAILS=$((FAILS+1)); }
[ "$completed" -eq 0 ] || { say "FAIL: a peer completed the retirement (published EMPTY) while the key was STILL REGISTERED"; FAILS=$((FAILS+1)); }
if [ "$MODE" = crash ]; then
    [ "$rpseen" -ge 1 ] || { say "FAIL: no peer saw the RETIRE_PENDING record"; FAILS=$((FAILS+1)); }
    [ "$expired" -ge 1 ] || { say "FAIL: no peer expired the RETIRE_PENDING record to WITHDRAWN"; FAILS=$((FAILS+1)); }
fi
for i in $(seq 1 "$N"); do h="test$i"; [ "$h" = "$VICTIM" ] && continue; "$SSH" "$h" "dmesg" > "$OUT/peer_$h.dmesg" 2>/dev/null & done; wait
sleep 5
keys > "$OUT/keys_after_fence.txt"
if [ -n "$KEY" ] && grep -qx "$KEY" "$OUT/keys_after_fence.txt"; then say "FAIL: key $KEY still registered after the peer fence"; FAILS=$((FAILS+1)); else say "key $KEY absent after fence"; fi
faults=$(grep -ciE 'kernel BUG|BUG:|Oops|general protection|Call Trace' "$OUT"/peer_*.dmesg "$OUT/victim_umount.log" | awk -F: '{s+=$2} END{print s+0}')
shut=$(grep -l 'Filesystem has been shut down\|forced shutdown' "$OUT"/peer_*.dmesg 2>/dev/null | wc -l)
[ "$faults" -eq 0 ] || { say "FAIL: kernel faults=$faults"; FAILS=$((FAILS+1)); }
[ "$shut" -eq 0 ] || { say "FAIL: $shut peers shut down"; FAILS=$((FAILS+1)); }

# 5. remount — sess453 (D-0519): first wait for the elected replayer to
#    complete the fenced slot's recovery; with 31 live members on a 32-slice
#    volume the claim has no slot until P163-RECOVERY-COMPLETE
#    (P300-CLAIM-EXHAUSTED otherwise).  Prints the fence->complete latency.
T_R0=$(date +%s); rdone=0; end=$((SECONDS + 150))
while [ $SECONDS -lt $end ]; do rdone=$(fleet_count P163-RECOVERY-COMPLETE); [ "$rdone" -ge 1 ] && break; sleep 5; done
say "recovery of the fenced slot: P163-RECOVERY-COMPLETE=$rdone after $(( $(date +%s) - T_R0 )) s more (fence->complete latency, D-0519)"
[ "$rdone" -ge 1 ] || { say "FAIL: the fenced slot's recovery did not complete within 150 s"; FAILS=$((FAILS+1)); }
"$SSH" "$VICTIM" "dmesg --clear; MXFS_DEV=$DEV timeout 120 /src/mxfs/tests/setup/prep_node.sh $TRANSPORT; echo PREP_RC=\$?; dmesg | grep -c 'P305-PR-PREDECESSOR-KEY-PRESENT'" > "$OUT/victim_remount.log" 2>&1
grep -q NODE_PREP_OK "$OUT/victim_remount.log" || { say "FAIL: victim did not remount (prep_node)"; FAILS=$((FAILS+1)); }
[ "$(tail -1 "$OUT/victim_remount.log")" = 0 ] || { say "FAIL: victim remount hit P305-PR-PREDECESSOR-KEY-PRESENT"; FAILS=$((FAILS+1)); }

# 6. control = the CLEAN path (0.59.0): knobs off, umount, a peer must
#    complete the retirement (READ KEYS absent -> EMPTY) and retire the
#    tracking without a fence; then remount.
for i in $(seq 1 "$N"); do "$SSH" "test$i" "dmesg --clear" >/dev/null 2>&1 & done; wait
"$SSH" "$VICTIM" "echo 0 > $KNOB; echo 0 > $KNOB2 2>/dev/null; timeout 60 umount $MNT; echo UMOUNT_RC=\$?; dmesg | grep -c 'P303\|P301'; dmesg | grep -c 'P304-RETIRE-PENDING-RELEASED'" > "$OUT/victim_control.log" 2>&1
ctl=$(sed -n '/^UMOUNT_RC=/{n;p}' "$OUT/victim_control.log" | head -1)
crel=$(sed -n '/^UMOUNT_RC=/{n;n;p}' "$OUT/victim_control.log" | head -1)
[ "${ctl:-1}" = 0 ] || { say "FAIL: control umount printed P301/P303 lines ($ctl) with the knob off"; FAILS=$((FAILS+1)); }
[ "${crel:-0}" -ge 1 ] || { say "FAIL: control umount did not stamp RETIRE_PENDING"; FAILS=$((FAILS+1)); }
ccomp=0; cclean=0; cfence=0; cseen=0; end=$((SECONDS + 60))
while [ $SECONDS -lt $end ]; do
    for i in $(seq 1 "$N"); do
        h="test$i"; [ "$h" = "$VICTIM" ] && continue
        "$SSH" "$h" "dmesg | grep -c 'P304-RETIRE-COMPLETED-BY-PEER'; dmesg | grep -c 'P163-CLEAN-DEPART'; dmesg | grep -c 'P236-FENCE-CERTIFIED\|P163-WITHDRAW-SEEN\|P304-RETIRE-EXPIRED'" > "$OUT/ctl_$h.cnt" 2>/dev/null &
    done; wait
    ccomp=$(cat "$OUT"/ctl_*.cnt 2>/dev/null | awk 'NR%3==1{s+=$1} END{print s+0}')
    cclean=$(cat "$OUT"/ctl_*.cnt 2>/dev/null | awk 'NR%3==2{s+=$1} END{print s+0}')
    cfence=$(cat "$OUT"/ctl_*.cnt 2>/dev/null | awk 'NR%3==0{s+=$1} END{print s+0}')
    [ "$ccomp" -ge 1 ] && [ "$cclean" -ge 1 ] && break
    sleep 5
done
say "control (clean path): COMPLETED-BY-PEER=$ccomp CLEAN-DEPART=$cclean fence/withdraw/expired=$cfence after $(( SECONDS - (end - 60) )) s"
[ "$ccomp" -ge 1 ] || { say "FAIL: no peer completed the clean retirement (READ KEYS absent -> EMPTY)"; FAILS=$((FAILS+1)); }
[ "$cclean" -ge 1 ] || { say "FAIL: no peer retired the tracking (P163-CLEAN-DEPART) after the clean unmount"; FAILS=$((FAILS+1)); }
[ "$cfence" -eq 0 ] || { say "FAIL: the clean path fired the death machinery ($cfence)"; FAILS=$((FAILS+1)); }
keys > "$OUT/keys_control.txt"
[ "$(wc -l < "$OUT/keys_control.txt")" -eq $(( $(wc -l < "$OUT/keys_before.txt") - 1 )) ] || { say "FAIL: key table after the clean unmount has $(wc -l < "$OUT/keys_control.txt") keys, expected $(( $(wc -l < "$OUT/keys_before.txt") - 1 )) (victim key not retired, or a peer lost its key)"; FAILS=$((FAILS+1)); }
"$SSH" "$VICTIM" "dmesg --clear; MXFS_DEV=$DEV timeout 120 /src/mxfs/tests/setup/prep_node.sh $TRANSPORT; echo PREP_RC=\$?; dmesg | grep -c 'P305-PR-PREDECESSOR-KEY-PRESENT\|P274-CLAIM-RETIRE-PENDING-SKIP'" >> "$OUT/victim_control.log" 2>&1
grep -q NODE_PREP_OK "$OUT/victim_control.log" || { say "FAIL: control remount failed"; FAILS=$((FAILS+1)); }
[ "$(tail -1 "$OUT/victim_control.log")" = 0 ] || { say "FAIL: control remount hit P305 or had to skip its own RETIRE_PENDING slot (retirement never completed)"; FAILS=$((FAILS+1)); }
keys > "$OUT/keys_end.txt"

echo "evidence: $OUT"
if [ "$FAILS" = 0 ]; then echo "=== pr_unregister_fail_restamp PASS @ $(date -u +%FT%TZ) ==="; exit 0; fi
echo "=== pr_unregister_fail_restamp FAIL fails=$FAILS @ $(date -u +%FT%TZ) ==="; exit 1
