#!/bin/bash
# d_recov_advance_bounded_verify.sh — D-RECOV-ADVANCE-UNBOUNDED-RETRY
# verification (sess420 landing, 0.31.0): the completion ladder's failures
# are CLASSIFIED and BOUNDED, and every terminating outcome is loud and
# hands the recovery to a survivor instead of looping quietly for ever.
#
# Arms (one per invocation; the fleet must be prepped 32/caw before each):
#   transient  recov_complete_inject=3 on the elected replayer R: ONE -EIO at
#              the IMAGES_REPLAYED advance.  Expect exactly one
#              P234-COMPLETE-RETRY (site=replayed-advance attempt=1), then
#              P163-RECOVERY-COMPLETE on R; no deadline, no withdrawal.
#   deadline   inject=1: every advance fails.  Expect bounded RETRY lines
#              with 5/10/20/40 s backoff (jitter +-20%), then within ~120 s
#              P234-COMPLETE-DEADLINE (relinquish_rc=0) +
#              P236-RECOV-RELINQUISH-SLOT + 'WITHDRAWING this mount' on R;
#              R's heartbeat then expires and the next-lowest survivor R2
#              takes the UNOWNED descriptor and publishes
#              P163-RECOVERY-COMPLETE for the victim's slot.
#   invariant  inject=2: the in-memory auth token is corrupted once, so
#              recov_auth_holds() refuses a descriptor that is ours and
#              unchanged.  Expect P234-COMPLETE-INVARIANT + withdrawal on R,
#              the descriptor left as GUARD on the platter, and a survivor's
#              takeover completing the recovery after R's heartbeat expires.
#
# R = the node holding the LOWEST heartbeat slot (positional election);
# V = the node holding the highest slot below the slice count.
# Enforcement knobs (target_cache_protected=1 foreign_replay_token_enforce=1)
# are armed fleet-wide first: without them the replay is the designed blanket
# refusal and the ladder's advance is never reached (rman_matrix.sh, sess407).
#
# the budget rule (derived): V expiry 62 s + replay ~20 s + ladder; transient: +5 s
# backoff +10 s => bound 150 s.  deadline: +120 s deadline (5+10+20+40+40 s
# backoffs) + R expiry 62 s + takeover/replay ~60 s => ~330 s, bound 420 s.
# invariant: R withdraws at ~+85 s, R expiry 62 s, abandoned-owner takeover
# (MXFS_RECOV_ABANDON_MS) + replay => bound 420 s.  Caller bound 480 s.
# After a deadline/invariant arm R is withdrawn and V is down: the caller
# MUST prep_cluster before the next arm.
#
# Usage: tests/d_recov_advance_bounded_verify.sh <label> <transient|deadline|invariant> [N=32]
set -u
LABEL=${1:?label}
ARM=${2:?arm}
N=${3:-32}
cd "$(dirname "$0")/.." || exit 2
SSH=tools/mxfs_sshpass.sh
VIRSH="sudo virsh -c qemu:///system"
IMG=$(tools/mxfs_host_image.sh) || { echo "$IMG"; exit 2; }
MNT=${MXFS_MNT:-/mnt/shared}
P=/sys/module/mxfs/parameters
MARK="RADV-$LABEL-$ARM-$(date -u +%H%M%S)"
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_radv_$ARM
mkdir -p "$OUT"
TREE_SV=$(modinfo mxfs.ko 2>/dev/null | awk '/srcversion/{print $2}')
#   takeover   (sess91 ruling item 4) inject=1 on R so the ladder is retrying;
#              after the FIRST P234-COMPLETE-RETRY rewrite the descriptor's
#              owner_epoch on the platter (tests/hb_epoch_inject.py setowner:
#              same owner node, a LATER incarnation, crc resealed).  The next
#              attempt must classify TAKEOVER (P234-COMPLETE-TAKEOVER,
#              outcome SUPERSEDED, auth dropped, nothing re-armed) — never
#              INVARIANT and never a withdrawal.  Bound: 62 + 20 + 5 + 10 s.
case "$ARM" in transient) INJ=3; BOUND=150 ;; deadline) INJ=1; BOUND=420 ;; invariant) INJ=2; BOUND=420 ;; takeover) INJ=1; BOUND=150 ;; *) echo "unknown arm $ARM"; exit 2 ;; esac
fails=0
pass() { echo "  PASS $1"; }
fail() { echo "  FAIL $1"; fails=$((fails+1)); }
info() { echo "  INFO $1"; }
sshq() { timeout "$1" "$SSH" "$2" "$3" 2>/dev/null | grep -av '^Unauthorized\|^Warning\|^If you'; }
echo "=== d_recov_advance_bounded_verify label=$LABEL arm=$ARM inject=$INJ N=$N out=$OUT $(date -u +%FT%TZ) ==="
T0=$(date +%s)

# 1. srcgate + slot map (per-node evidence files)
for i in $(seq 1 "$N"); do
    sshq 20 "test$i" "cat /sys/module/mxfs/srcversion; mountpoint -q $MNT && echo MOUNTED; dmesg | grep -ao 'claimed heartbeat slot [0-9]* for node [0-9]*' | tail -1" > "$OUT/test$i.gate" &
done; wait
: > "$OUT/slotmap.txt"
for i in $(seq 1 "$N"); do
    if grep -q "^$TREE_SV" "$OUT/test$i.gate" && grep -q MOUNTED "$OUT/test$i.gate"; then
        s=$(grep -ao 'slot [0-9]*' "$OUT/test$i.gate" | awk '{print $2}'); nid=$(grep -ao 'node [0-9]*' "$OUT/test$i.gate" | awk '{print $2}')
        [ -n "$s" ] && echo "$s test$i $nid" >> "$OUT/slotmap.txt" || fail "test$i: no claim line in dmesg"
    else
        fail "srcgate test$i: $(tr '\n' ' ' < "$OUT/test$i.gate")"
    fi
done
[ $fails -eq 0 ] || { echo "=== d_recov_advance_bounded_verify $LABEL/$ARM: fails=$fails (setup) out=$OUT ==="; exit 1; }
sort -n "$OUT/slotmap.txt" -o "$OUT/slotmap.txt"
R=$(head -1 "$OUT/slotmap.txt" | awk '{print $2}'); RSLOT=$(head -1 "$OUT/slotmap.txt" | awk '{print $1}'); RNODE=$(head -1 "$OUT/slotmap.txt" | awk '{print $3}')
R2=$(sed -n '2p' "$OUT/slotmap.txt" | awk '{print $2}')
V=$(awk -v n="$N" '$1 < n' "$OUT/slotmap.txt" | tail -1 | awk '{print $2}'); VSLOT=$(awk -v n="$N" '$1 < n' "$OUT/slotmap.txt" | tail -1 | awk '{print $1}'); VNODE=$(awk -v n="$N" '$1 < n' "$OUT/slotmap.txt" | tail -1 | awk '{print $3}')
[ -n "$R" ] && [ -n "$V" ] && [ "$R" != "$V" ] && pass "replayer R=$R (slot $RSLOT), next R2=$R2, victim V=$V (slot $VSLOT node $VNODE)" || { fail "could not pick R/V from $OUT/slotmap.txt"; exit 1; }

# 2. arm enforcement fleet-wide, then the injector on R; markers
tests/fleet_set_params.sh "target_cache_protected=1 foreign_replay_token_enforce=1" "$N" "$OUT/knobs.txt" > "$OUT/knobs.log" 2>&1 && pass "enforcement armed on $N nodes" || fail "fleet_set_params: $(tail -2 "$OUT/knobs.log" | tr '\n' ' ')"
k=$(sshq 15 "$R" "echo $INJ > $P/recov_complete_inject && cat $P/recov_complete_inject")
[ "$k" = "$INJ" ] && pass "recov_complete_inject=$INJ set on $R" || fail "inject knob on $R: '$k'"
for i in $(seq 1 "$N"); do [ "test$i" = "$V" ] || sshq 10 "test$i" "echo $MARK > /dev/kmsg" >/dev/null & done; wait
[ $fails -eq 0 ] || { echo "=== d_recov_advance_bounded_verify $LABEL/$ARM: fails=$fails (arm) out=$OUT ==="; exit 1; }

# 3. kill V
TK=$(date +%s)
$VIRSH destroy "$V" >/dev/null 2>&1 && info "destroyed $V at $(date -u +%T)" || { fail "virsh destroy $V"; exit 1; }

# 4. watch R (and, for the terminating arms, the survivors) until the arm's
#    terminal line lands or the bound expires
rdmesg() { sshq 20 "$R" "dmesg | sed -n '/$MARK/,\$p' | grep -a 'slot=$VSLOT\|COMPLETE-INJECT\|WITHDRAW\|P-WITHDRAW' | cut -c1-260"; }
done_line=""
# sess437 (design-consult ruling, ccmemory ccloop-c7ee71c6-sess437-GPT-ruling-incarnation-
# owner-liveness-and-whole-cluster-restart): the takeover arm's terminal line
# is no longer P234-COMPLETE-TAKEOVER.  The rewritten descriptor names R's OWN
# node under an epoch R does not hold; the retry re-enters the lease acquire,
# which must classify that incarnation REVOKED (v5_incarnation_state) and take
# the stale lease over with owner_term+1 (P238-RECOV-TAKEOVER ... why='our OWN
# earlier incarnation', then P238-RECOV-TAKEN) — or lose that CAW to a survivor
# that classified the same tuple 'a LATER incarnation of the same node is
# heartbeating'.  Either way the recovery COMPLETES; waiting on "owner_node is
# alive" (the pre-0.41.11 behaviour, chain-7 s436g: P238-RECOV-OWNED for ever,
# fails=4) is the defect.
case "$ARM" in transient) done_line="P163-RECOVERY-COMPLETE slot=$VSLOT" ;; deadline) done_line="P234-COMPLETE-DEADLINE slot=$VSLOT" ;; invariant) done_line="P234-COMPLETE-INVARIANT slot=$VSLOT" ;; takeover) done_line="P238-RECOV-TAKEN slot=$VSLOT\|P163-RECOVERY-COMPLETE slot=$VSLOT" ;; esac
rewrote=0
while [ $(( $(date +%s) - TK )) -lt $BOUND ]; do
    sleep 5
    rdmesg > "$OUT/R.dmesg" 2>/dev/null
    if [ "$ARM" = takeover ] && [ $rewrote -eq 0 ] && grep -aq "P234-COMPLETE-RETRY slot=$VSLOT" "$OUT/R.dmesg"; then
        # the ladder is now retrying under inject=1: move the descriptor to a
        # later incarnation of the SAME owner node, then release the injector
        # so the next attempt's advance meets the real descriptor.
        python3 tests/hb_epoch_inject.py "$IMG" "$VSLOT" show > "$OUT/desc_before.txt" 2>&1
        oe=$(grep -ao 'owner=[0-9]*/[0-9]*' "$OUT/desc_before.txt" | head -1 | cut -d/ -f2)
        # owner_epoch is a random u64: bash $(( )) is SIGNED and wraps negative
        # for values >= 2^63 (chain 15 s438a: 11135932352591552525 -> negative,
        # setowner refused, no takeover ever provoked).  Do the +1 in python mod 2^64.
        ne=$(python3 -c "import sys; print((int(sys.argv[1]) + 1) % (1 << 64))" "${oe:-1}")
        python3 tests/hb_epoch_inject.py "$IMG" "$VSLOT" setowner "$ne" > "$OUT/desc_setowner.txt" 2>&1; src=$?
        [ $src -eq 0 ] && rewrote=1
        info "descriptor owner_epoch $oe -> $ne rewritten at +$(( $(date +%s) - TK ))s (rc=$src): $(grep -ao 'desc{[^}]*}' "$OUT/desc_setowner.txt" | tail -1)"
        sshq 15 "$R" "echo 0 > $P/recov_complete_inject" >/dev/null
    fi
    grep -aq "$done_line" "$OUT/R.dmesg" && break
done
info "R reached '$done_line' at +$(( $(date +%s) - TK ))s (or timed out)"
inj=$(grep -ac "P234-COMPLETE-INJECT slot=$VSLOT" "$OUT/R.dmesg"); retry=$(grep -ac "P234-COMPLETE-RETRY slot=$VSLOT" "$OUT/R.dmesg")
dl=$(grep -ac "P234-COMPLETE-DEADLINE slot=$VSLOT" "$OUT/R.dmesg"); inv=$(grep -ac "P234-COMPLETE-INVARIANT slot=$VSLOT" "$OUT/R.dmesg")
wd=$(grep -ac "WITHDRAWING this mount" "$OUT/R.dmesg"); rcpl=$(grep -ac "P163-RECOVERY-COMPLETE slot=$VSLOT" "$OUT/R.dmesg")
info "R: inject=$inj retry=$retry deadline=$dl invariant=$inv withdraw=$wd complete=$rcpl"
[ "$inj" -ge 1 ] && pass "injector fired on R" || fail "injector never fired on R (was R the elected replayer? slotmap: $(head -2 "$OUT/slotmap.txt" | tr '\n' ' '))"
case "$ARM" in
transient)
    [ "$retry" -eq 1 ] && pass "exactly one bounded RETRY" || fail "RETRY count $retry (want 1)"
    grep -aq "P234-COMPLETE-RETRY slot=$VSLOT .*site=replayed-advance .*attempt=1 " "$OUT/R.dmesg" && pass "retry names site=replayed-advance attempt=1" || fail "retry line lacks site/attempt: $(grep -a 'COMPLETE-RETRY' "$OUT/R.dmesg" | head -1)"
    [ "$rcpl" -ge 1 ] && pass "R published P163-RECOVERY-COMPLETE after the retry" || fail "no completion on R"
    [ "$dl" -eq 0 ] && [ "$inv" -eq 0 ] && [ "$wd" -eq 0 ] && pass "no deadline / invariant / withdrawal" || fail "unexpected terminal outcome (dl=$dl inv=$inv wd=$wd)"
    ;;
deadline)
    [ "$retry" -ge 3 ] && [ "$retry" -le 8 ] && pass "bounded RETRY count $retry (5/10/20/40/40 s ladder inside 120 s)" || fail "RETRY count $retry outside [3,8]"
    grep -ao 'next_ms=[0-9]*' "$OUT/R.dmesg" | cut -d= -f2 | head -4 | tr '\n' ' ' > "$OUT/backoffs.txt"
    info "backoffs: $(cat "$OUT/backoffs.txt")"
    python3 - "$OUT/backoffs.txt" <<'PY' && pass "backoff sequence is exponential within +-20% jitter and capped by the deadline" || fail "backoff sequence off: $(cat "$OUT/backoffs.txt")"
import sys
v=[int(x) for x in open(sys.argv[1]).read().split()]
ok = len(v)>=3 and all(3200<=x<=50000 for x in v) and v[0]<v[1]<v[2] and v[1]>=1.6*v[0] and v[2]>=1.6*v[1]
sys.exit(0 if ok else 1)
PY
    [ "$dl" -eq 1 ] && pass "P234-COMPLETE-DEADLINE fired once" || fail "DEADLINE count $dl"
    grep -aq "P234-COMPLETE-DEADLINE slot=$VSLOT .*relinquish_rc=0 " "$OUT/R.dmesg" && pass "lease given back (relinquish_rc=0)" || fail "relinquish did not land: $(grep -a 'COMPLETE-DEADLINE' "$OUT/R.dmesg" | grep -ao 'relinquish_rc=[-0-9]*')"
    sf=$(grep -a "P234-COMPLETE-DEADLINE slot=$VSLOT" "$OUT/R.dmesg" | grep -ao 'since_first_fail_ms=[0-9]*' | cut -d= -f2)
    [ "${sf:-0}" -ge 120000 ] && [ "${sf:-0}" -le 200000 ] && pass "deadline honoured at ${sf} ms since first failure" || fail "deadline at '${sf}' ms (want 120000..200000)"
    [ "$wd" -ge 1 ] && pass "R withdrew its mount (fail-stop)" || fail "R did not withdraw"
    [ "$inv" -eq 0 ] && pass "no invariant arm" || fail "INVARIANT fired in the deadline arm"
    ;;
invariant)
    grep -aq "P234-COMPLETE-INJECT slot=$VSLOT .*kind=2" "$OUT/R.dmesg" && pass "auth corrupted once (kind=2)" || fail "kind=2 injector line missing"
    [ "$inv" -eq 1 ] && pass "P234-COMPLETE-INVARIANT fired once" || fail "INVARIANT count $inv"
    [ "$wd" -ge 1 ] && pass "R withdrew its mount (fail-stop)" || fail "R did not withdraw"
    [ "$dl" -eq 0 ] && [ "$retry" -eq 0 ] && pass "no retry / no deadline (stopped at once)" || fail "retry=$retry dl=$dl (want 0/0)"
    python3 tests/hb_epoch_inject.py "$IMG" "$VSLOT" show > "$OUT/record_after_inv.txt" 2>&1
    grep -q 'flags=GUARD' "$OUT/record_after_inv.txt" && pass "descriptor left standing (platter slot $VSLOT is GUARD)" || fail "platter slot $VSLOT: $(tail -1 "$OUT/record_after_inv.txt" | cut -c1-120)"
    ;;
takeover)
    [ $rewrote -eq 1 ] && pass "descriptor owner_epoch rewritten while the ladder was retrying" || fail "never saw a RETRY to rewrite under (retry=$retry)"
    grep -q 'crc_ok=1}$' "$OUT/desc_setowner.txt" && pass "descriptor crc resealed (reads valid)" || fail "descriptor crc after rewrite: $(grep -ao 'desc{[^}]*}' "$OUT/desc_setowner.txt" | tail -1)"
    # R must see its own stale tuple as REVOKED, never as a live owner to wait on
    rdmesg > "$OUT/R.dmesg" 2>/dev/null
    rto=$(grep -ac "P238-RECOV-TAKEOVER slot=$VSLOT .*owner=$RNODE/$(( ${oe:-1} + 1 )) " "$OUT/R.dmesg")
    rown=$(grep -ac "P238-RECOV-OWNED slot=$VSLOT .*owner=$RNODE/$(( ${oe:-1} + 1 )) " "$OUT/R.dmesg")
    [ "$rto" -ge 1 ] && pass "R classified its own stale incarnation REVOKED and attempted takeover ($rto line(s))" || fail "R never attempted takeover of owner=$RNODE/$(( ${oe:-1} + 1 )) (RECOV-TAKEOVER lines=$rto)"
    grep -aq "P238-RECOV-TAKEOVER slot=$VSLOT .*why='our OWN earlier incarnation" "$OUT/R.dmesg" && pass "takeover reason names the own-earlier-incarnation case" || fail "takeover reason: $(grep -a 'P238-RECOV-TAKEOVER' "$OUT/R.dmesg" | head -1 | grep -ao "why='[^']*'")"
    [ "$rown" -eq 0 ] && pass "R never waited on itself (no RECOV-OWNED for owner=$RNODE/$(( ${oe:-1} + 1 )))" || fail "R waited on its own stale incarnation $rown time(s) (P238-RECOV-OWNED)"
    [ "$inv" -eq 0 ] && pass "NOT misclassified as INVARIANT" || fail "INVARIANT fired ($inv)"
    [ "$dl" -eq 0 ] && [ "$wd" -eq 0 ] && pass "no deadline, no withdrawal" || fail "dl=$dl wd=$wd"
    # the DLM ladder must never call this TOKEN-MISMATCH (that is a stale/foreign auth, not a takeover)
    tm=$(sshq 15 "$R" "dmesg | sed -n '/$MARK/,\$p' | grep -a 'P234-RECOV-NOTOURS slot=$VSLOT ' | grep -ac 'TOKEN-MISMATCH'")
    [ "${tm:-0}" -eq 0 ] && pass "no TOKEN-MISMATCH misclassification on R" || fail "NOTOURS said TOKEN-MISMATCH $tm time(s)"
    ;;
esac
# clear the injector on R regardless (module stays loaded after withdrawal)
sshq 15 "$R" "echo 0 > $P/recov_complete_inject" >/dev/null

# 5. terminating arms: a survivor must finish the recovery after R's expiry
if [ "$ARM" != transient ]; then
    TW=$(date +%s); who=""
    while [ $(( $(date +%s) - TK )) -lt $BOUND ]; do
        sleep 15
        for i in $(seq 1 "$N"); do
            # sess437: in the takeover arm R itself may be the one that completes
            # (it takes its own stale lease over with a new term), so R is swept too.
            [ "test$i" = "$V" ] || { [ "test$i" = "$R" ] && [ "$ARM" != takeover ]; } || sshq 15 "test$i" "dmesg | sed -n '/$MARK/,\$p' | grep -a 'P163-RECOVERY-COMPLETE slot=$VSLOT \|P234-RECOV-TAKEOVER slot=$VSLOT\|P238-RECOV-TAKEOVER slot=$VSLOT\|P238-RECOV-TAKEN slot=$VSLOT\|P234-COMPLETE-UNOWNED slot=$VSLOT\|foreign replay of slot $VSLOT' | cut -c1-200" > "$OUT/test$i.surv" 2>/dev/null &
        done; wait
        who=$(grep -al "P163-RECOVERY-COMPLETE slot=$VSLOT " "$OUT"/test*.surv 2>/dev/null | head -1 | xargs -r basename | cut -d. -f1)
        [ -n "$who" ] && break
    done
    [ -n "$who" ] && pass "survivor $who published P163-RECOVERY-COMPLETE for slot $VSLOT at +$(( $(date +%s) - TK ))s (successor wait $(( $(date +%s) - TW ))s)" || fail "no survivor completed slot $VSLOT within ${BOUND}s of the kill"
    if [ "$ARM" = takeover ]; then
        tkn=$(cat "$OUT"/test*.surv 2>/dev/null | grep -ac "P238-RECOV-TAKEN slot=$VSLOT")
        [ "$tkn" -ge 1 ] && pass "the stale lease was taken over with a new term (P238-RECOV-TAKEN x$tkn)" || fail "no P238-RECOV-TAKEN for slot $VSLOT on any node"
    fi
    cat "$OUT"/test*.surv 2>/dev/null | grep -a 'TAKEOVER\|TAKEN\|UNOWNED' | head -4 | sed 's/^/    /'
fi

# 6. cleanup: V back up; R is withdrawn — caller must prep_cluster
$VIRSH start "$V" >/dev/null 2>&1 && info "$V started — caller must prep_cluster" || fail "virsh start $V"
info "wall=$(( $(date +%s) - T0 ))s"
echo "=== d_recov_advance_bounded_verify $LABEL/$ARM: fails=$fails out=$OUT $(date -u +%FT%TZ) ==="
[ $fails -eq 0 ]
