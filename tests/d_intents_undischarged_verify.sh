#!/bin/bash
# d_intents_undischarged_verify.sh — D-FOREIGN-SLICE-INTENTS-ABANDONED interim
# closure step (sess420 barrier ruling, ccmemory
# docs/rulings/mount-barrier-items-3-4-6c-window-arm.md):
# a foreign slice whose intent obligations are NOT discharged inside the
# slice must FAIL BEFORE PURGE — refused through the D-513 terminal-outcome
# path with reason INTENTS_UNDISCHARGED (8) — never published as recovered.
#
# Two arms, each on a freshly prepped 32/caw fleet with enforcement armed
# (without the token knobs the blanket ATOMIC-SKIP refuses every image
# transaction as POLICY_REFUSED and the census never gets to decide):
#
#   burst   V=test8 owns 8 heavily fragmented files (4096 x 4 KiB extents
#           each, written with holes); mxfs.dbg_efd_hold_ms=60000 is armed
#           on V, the files are removed in parallel, and V is virsh-
#           destroyed once its P-EFD-HOLD line shows the first EFI forced
#           durable with its EFD transaction held (0.41.7+).  The earlier
#           timed destroy (2 s after the rm started; 8 files sess421/423,
#           48 files sess436) always found P226-ICENSUS intents=0: the
#           frees run in inactivation after unlink returns and the destroy
#           never landed inside a chain.  Each extent free is one deferred
#           roll (EFD(i)+EFI(i+1) per transaction), so the last durable
#           checkpoint of V's slice carries an EFI whose EFD never landed.
#           Assert on O=test1 (elected replayer): P226-ICENSUS with open>=1,
#           P226-FR-INTENTS-UNDISCHARGED, P241-RECOV-TERMINAL reason=8,
#           'slice replay refused (INTENTS-UNDISCHARGED', ZERO
#           P163-RECOVERY-COMPLETE for V's slot; survivors stay writable.
#   clean   V has synced, idle files and is destroyed with nothing in
#           flight.  Assert: P226-ICENSUS open=0, ZERO reason=8, ZERO
#           P226-FR-INTENTS-UNDISCHARGED, P163-RECOVERY-COMPLETE for V's slot.
#
# the budget rule (derived): file build ~2 s (8 x 0.19 s measured) + hold wait
# <=30 s (typically <5 s) + destroy + 31x2 s dead window 62 s + fence/replay
# ~15 s + harvest ~25 s => ~115 s.  Caller bound 180 s.
#
# Usage: tests/d_intents_undischarged_verify.sh <label> <burst|clean> [O] [V]
set -u
LABEL=${1:?label}; ARM=${2:?arm}; O=${3:-test1}; V=${4:-test8}
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd); cd "$REPO"
SSH=tools/mxfs_sshpass.sh
VIRSH="sudo virsh -c qemu:///system"
MNT=${MXFS_MNT:-/mnt/shared}
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_intents_$ARM
mkdir -p "$OUT"
fails=0
ck() { if [ "$2" = "$3" ]; then echo "  PASS $1 ($2)"; else echo "  FAIL $1 got=$2 want=$3"; fails=$((fails+1)); fi; }
ge1() { [ "${1:-0}" -ge 1 ] && echo yes || echo no; }
# rs/rsx/measure/window_count_into/mxfs_dev_resolve (tests/lib/rig.sh):
# every count a verdict is taken from is acquired into its own file and
# validated in the parent shell first; a failed ssh is an ABORT, never a
# count of zero.
. "$(dirname "$0")/lib/rig.sh"
# cnt: POLLING ONLY (waitfor); never feeds a verdict
cnt() { rs 20 "$1" "dmesg | sed -n \"/$MARK/,\\\$p\" | grep -ac '$2'" | tr -dc '0-9'; }
waitfor() { # waitfor <node> <pattern> <max_s>
    local i=0; while [ $i -lt "$3" ]; do [ "$(cnt "$1" "$2")" -ge 1 ] 2>/dev/null && { echo $i; return 0; }; sleep 3; i=$((i+3)); done; echo timeout; return 1; }

echo "=== d_intents_undischarged_verify label=$LABEL arm=$ARM O=$O V=$V out=$OUT $(date -u +%FT%TZ) ==="
want=$(modinfo mxfs.ko | awk '/^srcversion:/{print $2}')
for n in $O $V; do
    nsv=$(rs 15 "$n" "cat /sys/module/mxfs/srcversion" | tr -dc 'A-F0-9')
    [ "$nsv" = "$want" ] || { echo "ABORT: $n srcversion '$nsv' != tree '$want'"; exit 2; }
done
tests/fleet_set_params.sh "target_cache_protected=1 foreign_replay_token_enforce=1" 32 "$OUT/knobs.txt" > "$OUT/knobs.log" 2>&1 || { echo "ABORT: enforcement arming failed: $(tail -2 "$OUT/knobs.log" | tr '\n' ' ')"; exit 2; }
echo "  INFO enforcement armed fleet-wide ($OUT/knobs.txt)"
# sess423: the replayer is the LOWEST LIVE SLOT, and slots are random per
# mount — never assume test1.  Map the fleet's slots and pick the lowest
# that is not V (an explicit 3rd argument still overrides).
if [ -z "${3:-}" ]; then
    SM=$(mktemp -d)
    for i in $(seq 1 32); do
        ( rs 15 "test$i" "dmesg | grep -ao 'claimed heartbeat slot [0-9]*' | tail -1 | grep -o '[0-9]*\$'" | tr -dc '0-9' > "$SM/test$i" ) &
    done; wait
    oslot=999
    for i in $(seq 1 32); do
        n=test$i; [ "$n" = "$V" ] && continue
        sl=$(cat "$SM/$n"); [ -n "$sl" ] || continue
        [ "$sl" -lt "$oslot" ] && { oslot=$sl; O=$n; }
    done
    echo "  INFO replayer O=$O slot=$oslot (lowest live slot; V=$V excluded)"
fi
MARK="ICENSUS-$LABEL-$ARM-$$"
# sess423: capture O's kernel lines on EVERY exit path (the s421 burst arm
# timed out before its dmesg dump and the evidence dir held only knobs).
capture_on_exit() {
    [ -s "$OUT/dmesg_$O.txt" ] || rs 25 "$O" "dmesg | sed -n \"/$MARK/,\\\$p\"" > "$OUT/dmesg_$O.txt" 2>/dev/null
    echo "  INFO exit capture: $O=$(wc -l < "$OUT/dmesg_$O.txt" 2>/dev/null || echo 0) lines"
}
trap capture_on_exit EXIT
# sess436: the caller's `timeout` delivers TERM, which does not run the EXIT
# trap — the s436b lap's evidence dir held only knobs.  Capture, then exit 124.
trap 'capture_on_exit; exit 124' TERM
rs 12 "$O" "echo '$MARK' > /dev/kmsg" >/dev/null
DIR=$MNT/.icensus_$LABEL
case "$ARM" in
  burst)
    # 8 files x 4096 single-block extents, written with one-block holes so
    # every block is its own extent; synced so the extents are durable and
    # the removal below is pure deferred-free work (EFI/EFD chains).
    rs 60 "$V" "mkdir -p $DIR && python3 - <<'EOF'
import os
d='$DIR'
for f in range(8):
    fd=os.open(os.path.join(d,'frag%d'%f), os.O_CREAT|os.O_WRONLY|os.O_TRUNC, 0o644)
    for i in range(4096):
        os.pwrite(fd, b'\\xa5'*4096, i*8192)
    os.fsync(fd); os.close(fd)
print('ok')
EOF" | grep -q ok || { echo "ABORT: V fragmented-file build failed"; exit 2; }
    # sess423: filefrag's SUMMARY count merges logically-separate extents that
    # are PHYSICALLY adjacent (delalloc places the strided blocks contiguously,
    # s421 measured "6 extents" for a 4096-hole file); count the FIEMAP rows.
    value_now_into ext "$V" 20 "$OUT/rv_ext_1.txt" '^[0-9]+$' "ext on $V" "filefrag -v $DIR/frag0 2>/dev/null | grep -ac '^ *[0-9][0-9]*:' || [ \$? = 1 ]"
    echo "  INFO frag0 extents=$ext (want ~4096)"
    ck "V's files are fragmented (>=2000 extents)" "$([ "${ext:-0}" -ge 2000 ] && echo yes || echo no)" "yes"
    # sess475 (chain 105 s472m was VACUOUS for fix A): the frag files were
    # created and removed on V only, so they were UNPUBLISHED (sess44
    # local-only EX grant, no slot) and every certificate install was refused
    # with try=7 = MXFS_AUTH_TRY_UNPUB (the sess467 Q3 approved classless
    # case) -> the rm transactions stayed POLICY-REFUSED reason=1, the very
    # outcome fix A exists to remove.  Publish them first: a peer lists the
    # directory and reads the head of every file (PR acquire -> BAST -> V
    # releases EX and publishes the dinodes), so V's rm re-acquires EX and
    # installs the replay certificate (P-INACT-CERT installed=1).
    P=${INTENTS_PEER:-test2}
    { [ "$P" = "$O" ] || [ "$P" = "$V" ]; } && P=test3
    { [ "$P" = "$O" ] || [ "$P" = "$V" ]; } && P=test4
    measure "$P" 60 "$OUT/rv_pub_2.txt" '^[0-9]+$' "the listing and read of the 8 frag files on $P" "ls -l $DIR | grep -c frag; for f in $DIR/frag*; do head -c 4096 \$f | wc -c; done | grep -c 4096 || [ \$? = 1 ]"; pub=$(cat "$OUT/rv_pub_2.txt")
    echo "  INFO publish via $P: listed=$(echo "$pub" | sed -n 1p | tr -dc '0-9') read=$(echo "$pub" | sed -n 2p | tr -dc '0-9')"
    ck "peer $P listed and read all 8 frag files (published before the rm)" "$(echo "$pub" | sed -n 2p | tr -dc '0-9')" "8"
    # sess436: DETERMINISTIC open intent.  Arm mxfs.dbg_efd_hold_ms on V:
    # the first extent free after arming forces the log (EFI durable) and
    # holds its EFD transaction for 60 s.  Start the removal, wait for V's
    # P-EFD-HOLD start line, then destroy V inside the hold.  (The timed
    # 2 s destroy never landed inside a roll chain: sess421/423/436 all
    # measured P226-ICENSUS intents=0.)
    rs 15 "$V" "echo 60000 > /sys/module/mxfs/parameters/dbg_efd_hold_ms && cat /sys/module/mxfs/parameters/dbg_efd_hold_ms" | grep -qx 60000 || { echo "ABORT: could not arm dbg_efd_hold_ms on $V (build lacks the knob?)"; exit 2; }
    # sess476 (CANCEL authority tokens, design-consult negative arms): FORGE=1 skews
    # every CANCEL record's grant epoch on V, FORGE=2 mis-targets its resource
    # — the replayer must REFUSE the rm transactions on the forged CANCEL, keep
    # their cancel entries out of the pass-1 table and suppress NO image.
    if [ "${FORGE:-0}" != 0 ]; then
        rs 15 "$V" "echo $FORGE > /sys/module/mxfs/parameters/dbg_cancel_token_forge && cat /sys/module/mxfs/parameters/dbg_cancel_token_forge" | grep -qx "$FORGE" || { echo "ABORT: could not arm dbg_cancel_token_forge=$FORGE on $V (build lacks the knob?)"; exit 2; }
        echo "  INFO negative arm: dbg_cancel_token_forge=$FORGE armed on $V"
    fi
    rs 15 "$V" "echo '$MARK' > /dev/kmsg; setsid nohup sh -c 'for f in $DIR/frag*; do rm -f \$f & done; wait' >/dev/null 2>&1 & echo started" | grep -q started || { echo "ABORT: could not start the unlink burst on $V"; exit 2; }
    wait_for_into t "$V" 30 "$MARK" "P-EFD-HOLD start"; ck "$V entered the EFD hold with a durable EFI (${t}s)" "$([ "$t" != timeout ] && echo yes || echo no)" "yes"
    [ "$t" != timeout ] || { echo "ABORT: no P-EFD-HOLD on $V — nothing to destroy into"; rs 10 "$V" "echo 0 > /sys/module/mxfs/parameters/dbg_efd_hold_ms"; exit 2; }
    # sess470: the PRODUCER-side proof lives on V and dies with it.  Chain
    # 103's fix-B census read 'agclass=0' because it swept test1/test2 while
    # the victim was test8 (tests/evidence/20260902T144543Z_intents_burst
    # held only dmesg_test1.txt).  Snapshot V's rm-side lines NOW, inside the
    # 60 s hold (bounded 15 s; the destroy below still lands in the hold):
    # dmesg_<V>_prekill.txt joins the dmesg_*.txt census of every chain.
    measure "$V" 15 "$OUT/dmesg_${V}_prekill.txt" '^DMESG_END$' "the victim's pre-kill kernel log on $V" "dmesg | sed -n \"/$MARK/,\\\$p\" | grep -a 'P-INACT-CERT\|P-IUNLINK-AGCLASS\|P228-TOKCLASS\|P239-OWNAUTH-NONDUR\|P240-AUTHCAP\|P-AUTHCAP-VOID\|P-DBG-CANCEL-FORGE\|P-EFD-HOLD\|P-INACT-EX \|P-UNLPRE'; echo DMESG_END"
    echo "  INFO victim pre-kill capture: $(wc -l < "$OUT/dmesg_${V}_prekill.txt") lines, P-IUNLINK-AGCLASS=$(grep -ac 'P-IUNLINK-AGCLASS ' "$OUT/dmesg_${V}_prekill.txt") P-INACT-CERT=$(grep -ac 'P-INACT-CERT ' "$OUT/dmesg_${V}_prekill.txt")"
    ;;
  clean)
    rs 30 "$V" "mkdir -p $DIR && for i in 1 2 3 4; do dd if=/dev/urandom of=$DIR/v\$i bs=4096 count=2 2>/dev/null; done; sync; sleep 2; echo ok" | grep -q ok || { echo "ABORT: V setup failed"; exit 2; }
    ;;
  *) echo "ABORT: unknown arm $ARM"; exit 2 ;;
esac
$VIRSH destroy "$V" >/dev/null 2>&1; echo "  INFO virsh destroy $V rc=$? at $(date -u +%T)"

wait_for_into t "$O" 110 "$MARK" "elected (slot"; ck "$O elected to replay $V's slice (${t}s)" "$([ "$t" != timeout ] && echo yes || echo no)" "yes"
vline=$(rs 20 "$O" "dmesg | sed -n \"/$MARK/,\\\$p\" | grep -a 'lease expired/died' | head -1")
vid=$(echo "$vline" | grep -ao 'node [0-9]* (slot' | tr -dc '0-9'); vslot=$(echo "$vline" | grep -ao '(slot [0-9]*' | tr -dc '0-9')
echo "  INFO victim node=$vid slot=$vslot"
[ -n "$vslot" ] || { echo "ABORT: could not parse victim slot"; fails=$((fails+1)); }

wait_for_into t "$O" 90 "$MARK" "P226-ICENSUS victim_slot=$vslot "; ck "census summary printed for slot $vslot (${t}s)" "$([ "$t" != timeout ] && echo yes || echo no)" "yes"
cl=$(rs 20 "$O" "dmesg | sed -n \"/$MARK/,\\\$p\" | grep -a 'P226-ICENSUS victim_slot=$vslot ' | tail -1")
echo "  INFO $cl"
open=$(echo "$cl" | grep -ao ' open=[0-9]*' | tr -dc '0-9')
intents=$(echo "$cl" | grep -ao ' intents=[0-9]*' | tr -dc '0-9')
if [ "$ARM" = burst ]; then
    ck "census saw intents in the slice (intents>=1)" "$(ge1 "$intents")" "yes"
    ck "census left >=1 intent undischarged" "$(ge1 "$open")" "yes"
    # sess436: with enforcement armed every dirty victim's images are
    # unauthorized, so the untagged-skip predicate refuses FIRST
    # (POLICY-REFUSED, reason=1) and the census WIDENS that verdict's
    # domain (design: xfs_log.c sess421 block).  reason=8 stands alone only
    # once images are token-authorized (D-FOREIGN-REPLAY-UNGATED-IMAGES).
    # The fail-before-purge claim is: open>=1 recorded, the obligation
    # named (P226-ICENSUS-OPEN), the slice REFUSED (either reason), a
    # terminal verdict durable, and NO publication of the slot.
    window_count_into wc1 "$O" 20 "$MARK" 'P226-ICENSUS-OPEN ' "open obligation named (P226-ICENSUS-OPEN)"
    ck "open obligation named (P226-ICENSUS-OPEN)" "$(ge1 "$wc1")" "yes"
    wait_for_into t "$O" 60 "$MARK" "P241-RECOV-TERMINAL slot=$vslot .*REFUSED"; ck "terminal verdict REFUSED durable on slot $vslot (${t}s)" "$([ "$t" != timeout ] && echo yes || echo no)" "yes"
    tl=$(rs 20 "$O" "dmesg | sed -n \"/$MARK/,\\\$p\" | grep -a 'P241-RECOV-TERMINAL slot=$vslot ' | tail -1")
    reason=$(echo "$tl" | grep -ao 'reason=[0-9]*' | head -1 | tr -dc '0-9')
    echo "  INFO terminal: $(echo "$tl" | cut -c1-200)"
    ck "refusal reason is POLICY-REFUSED(1) or INTENTS-UNDISCHARGED(8)" "$([ "${reason:-0}" = 1 ] || [ "${reason:-0}" = 8 ] && echo yes || echo no)" "yes"
    # sess476 (0.64.34+ CANCEL authority tokens).  STRICT_TOKENS=1 = the
    # ruling's positive assertion set: every image (CANCEL records included)
    # tokened and admitted, so the ONLY refusal left is the undischarged EFD
    # (reason=8), zero ATOMIC-SKIPs, zero untagged CANCELs, zero capture
    # voids, the pass-1 cancel decision refused nothing, pass-1/pass-2 agree.
    # FORGE=1|2 = the negative set: the forged CANCEL proof must REFUSE the rm
    # transactions (reason=1), their cancel entries must be put back out in
    # pass 1 and NO image may be suppressed by the table.
    cp1=$(rs 20 "$O" "dmesg | sed -n \"/$MARK/,\\\$p\" | grep -a 'P-FR-CANCEL-PASS1' | tail -1")
    echo "  INFO cancel-pass1: $(echo "$cp1" | grep -ao 'txns=.*' | cut -c1-160)"
    cp1_txns=$(echo "$cp1" | grep -ao 'txns=[0-9]*' | tr -dc '0-9'); cp1_ref=$(echo "$cp1" | grep -ao 'refused=[0-9]*' | tr -dc '0-9'); cp1_supp=$(echo "$cp1" | grep -ao 'cancel_suppressed=[0-9]*' | tr -dc '0-9'); cp1_miss=$(echo "$cp1" | grep -ao 'put_miss=[0-9]*' | tr -dc '0-9')
    window_into "$OUT/rv_untag_cancel_nz_3.txt" "$O" 20 "$MARK"; untag_cancel_nz=$(cat "$OUT/rv_untag_cancel_nz_3.txt" | grep -a 'P227-TOKENSUM' | grep -ao 'untag_cancel=[0-9]*' | grep -vc 'untag_cancel=0$' | tr -dc '0-9')
    if [ "${STRICT_TOKENS:-0}" = 1 ] || [ "${FORGE:-0}" != 0 ]; then
        ck "pass-1 CANCEL decision ran (P-FR-CANCEL-PASS1 txns>=1)" "$(ge1 "$cp1_txns")" "yes"
        window_count_into wc2 "$O" 20 "$MARK" 'P-FR-CANCEL-PUT-MISS' "ZERO P-FR-CANCEL-PUT-MISS / put_miss"
        ck "ZERO P-FR-CANCEL-PUT-MISS / put_miss" "$(( $wc2 + ${cp1_miss:-0} ))" "0"
        window_count_into wc3 "$O" 20 "$MARK" 'P-FR-PASS-VERDICT-MISMATCH' "ZERO P-FR-PASS-VERDICT-MISMATCH"
        ck "ZERO P-FR-PASS-VERDICT-MISMATCH" "$wc3" "0"
        ck "ZERO untagged CANCEL records (every TOKENSUM untag_cancel=0)" "${untag_cancel_nz:-x}" "0"
    fi
    if [ "${STRICT_TOKENS:-0}" = 1 ] && [ "${FORGE:-0}" = 0 ]; then
        ck "STRICT: refusal reason is INTENTS-UNDISCHARGED(8) only" "${reason:-0}" "8"
        window_count_into wc4 "$O" 20 "$MARK" 'P227-FR-ATOMIC-SKIP' "STRICT: ZERO P227-FR-ATOMIC-SKIP (policy_refused_txns==0)"
        ck "STRICT: ZERO P227-FR-ATOMIC-SKIP (policy_refused_txns==0)" "$wc4" "0"
        window_into "$OUT/rv_rv4_4.txt" "$O" 20 "$MARK"; rv4=$(cat "$OUT/rv_rv4_4.txt" | grep -a 'P227-TOKENSUM' | grep -ao 'classless=[0-9]*' | grep -vc 'classless=0$' | tr -dc '0-9')
        ck "STRICT: ZERO classless images (TOKENSUM classless!=0)" "$rv4" "0"
        ck "STRICT: pass-1 CANCEL decision refused nothing (refused=0)" "${cp1_ref:-x}" "0"
        ck "STRICT: ZERO P-AUTHCAP-VOID on the victim (pre-kill capture)" "$(grep -ac 'P-AUTHCAP-VOID' "$OUT/dmesg_${V}_prekill.txt")" "0"
        # sess479: the design-consult ruling's assertion set has SIX members, and
        # authority_mismatch_images==0 was never actually checked here -- it is
        # measured, as `resmis` on the P273-SHADOW-EVAL line, but nothing
        # asserted it, so the record could not be closed on the ruling's own
        # terms however many laps came back clean.  Assert it, and fail when
        # the line is absent rather than passing on an empty string (an
        # assertion that cannot observe its subject is not an assertion).
        sev=$(rs 20 "$O" "dmesg | sed -n \"/$MARK/,\\\$p\" | grep -a 'P273-SHADOW-EVAL' | tail -1")
        resmis=$(echo "$sev" | grep -ao 'resmis=[0-9]*' | head -1 | cut -d= -f2)
        echo "  INFO shadow-eval: $(echo "$sev" | grep -ao 'victim_slot=[0-9]* .*nolineage=[0-9]*' | cut -c1-200)"
        ck "STRICT: ZERO authority-mismatch images (P273-SHADOW-EVAL resmis)" "${resmis:-absent}" "0"
    fi
    if [ "${FORGE:-0}" != 0 ]; then
        ck "NEG: the victim forged >=1 CANCEL proof (P-DBG-CANCEL-FORGE, pre-kill capture)" "$(ge1 "$(grep -ac 'P-DBG-CANCEL-FORGE' "$OUT/dmesg_${V}_prekill.txt")")" "yes"
        ck "NEG: refusal reason is POLICY-REFUSED(1) on the forged CANCEL" "${reason:-0}" "1"
        window_count_into wc5 "$O" 20 "$MARK" 'P227-FR-ATOMIC-SKIP' "NEG: >=1 P227-FR-ATOMIC-SKIP"
        ck "NEG: >=1 P227-FR-ATOMIC-SKIP" "$(ge1 "$wc5")" "yes"
        ck "NEG: pass-1 CANCEL decision refused >=1 txn and put its entries back out" "$([ "${cp1_ref:-0}" -ge 1 ] && [ "${cp1_supp:-0}" -ge 1 ] && echo yes || echo no)" "yes"
        window_count_into wc6 "$O" 20 "$MARK" 'P-FR-IMAGE-CANCELLED-SKIP' "NEG: ZERO images suppressed by a refused CANCEL (P-FR-IMAGE-CANCELLED-"
        ck "NEG: ZERO images suppressed by a refused CANCEL (P-FR-IMAGE-CANCELLED-SKIP)" "$wc6" "0"
    fi
    if [ "${reason:-0}" = 1 ]; then
        # sess479: this assertion could never pass in its own AG-scoped branch.
        # It reads "FSWIDE or ag_mask covers the intent", but the else-arm
        # emitted the ag_mask STRING and compared it to the literal "yes", so
        # any AG-scoped widening failed by construction (s479hc:
        # got=ag_mask=0x40000000 want=yes) and the check only ever passed when
        # the verdict happened to come back FSWIDE.  Test the coverage it
        # claims to test: the verdict's mask must be a superset of the census's
        # intent mask, and a zero intent mask proves nothing.
        vmask=$(echo "$tl" | grep -ao 'ag_mask=0x[0-9a-f]*' | head -1 | cut -d= -f2)
        cmask=$(echo "$cl" | grep -ao 'ag_mask=0x[0-9a-f]*' | head -1 | cut -d= -f2)
        if echo "$tl" | grep -aq 'domain=1\|domain=FSWIDE'; then
            cov=yes
        else
            cov=$(python3 -c "v=int('${vmask:-0x0}',16); c=int('${cmask:-0x0}',16); print('yes' if c and (v & c) == c else 'no')" 2>/dev/null)
        fi
        echo "  INFO widening: verdict_ag_mask=${vmask:-none} census_ag_mask=${cmask:-none} covered=${cov:-no}"
        ck "reason=1 verdict widened by the census (FSWIDE, or the verdict ag_mask covers the census intent mask)" "${cov:-no}" "yes"
    else
        window_count_into wc7 "$O" 20 "$MARK" "P226-FR-INTENTS-UNDISCHARGED slot $vslot" "P226-FR-INTENTS-UNDISCHARGED printed"
        ck "P226-FR-INTENTS-UNDISCHARGED printed" "$(ge1 "$wc7")" "yes"
        # sess462 (item 5 increment 2): with the images admitted the census
        # classifies the open set; a RECOVER entry's extents are made durable
        # as TERMINAL EVIDENCE (obligation record + list) in the same CAS as
        # the verdict, and chk_mxfs must read them back VALID.
        sl=$(rs 20 "$O" "dmesg | sed -n \"/$MARK/,\\\$p\" | grep -a 'P226-ICENSUS-SPLIT victim_slot=$vslot ' | tail -1")
        echo "  INFO split: $(echo "$sl" | cut -c1-220)"
        recover=$(echo "$sl" | grep -ao ' recover=[0-9]*' | tr -dc '0-9')
        if [ "${recover:-0}" -ge 1 ]; then
            window_count_into wc8 "$O" 20 "$MARK" "P226-OBL-WRITE slot=$vslot " "obligation list written (P226-OBL-WRITE slot= vslot)"
            ck "obligation list written (P226-OBL-WRITE slot=$vslot)" "$(ge1 "$wc8")" "yes"
            window_count_into wc9 "$O" 20 "$MARK" "P226-OBL-EVIDENCE count=" "obligation evidence published with the verdict (P226-OBL-EVIDENCE)"
            ck "obligation evidence published with the verdict (P226-OBL-EVIDENCE)" "$(ge1 "$wc9")" "yes"
            window_count_into wc10 "$O" 20 "$MARK" 'P226-OBL-EVIDENCE-FAIL\|P226-OBL-EVIDENCE-LOST' "ZERO P226-OBL-EVIDENCE-FAIL/-LOST"
            ck "ZERO P226-OBL-EVIDENCE-FAIL/-LOST" "$wc10" "0"
            # the device is O's live mount (never another rig's path); the
            # tool's own list verdict line is the shape, so its error text
            # (absent device, tool missing) is an ABORT, never a clean zero
            mxfs_dev_resolve "$O"
            measure "$O" 60 "$OUT/chk_quarantine_$O.txt" 'obligation list +(VALID|INVALID)' "chk_mxfs --show-quarantine on $O" "/src/mxfs/tools/chk_mxfs --show-quarantine $MXFS_DEV_RESOLVED 2>&1"
            echo "  INFO chk: $(grep -a 'obligations \|obligation list' "$OUT/chk_quarantine_$O.txt" | head -3 | tr '\n' '|' | cut -c1-300)"
            ck "chk_mxfs shows the obligation record as TERMINAL-EVIDENCE with count>=1" "$(grep -aq 'obligations       count=[1-9][0-9]* TERMINAL-EVIDENCE' "$OUT/chk_quarantine_$O.txt" && echo yes || echo no)" "yes"
            ck "chk_mxfs validates the obligation list (VALID)" "$(grep -aq 'obligation list   VALID' "$OUT/chk_quarantine_$O.txt" && echo yes || echo no)" "yes"
            ck "chk_mxfs reports no INVALID obligation evidence" "$(grep -ac 'obligation.*INVALID' "$OUT/chk_quarantine_$O.txt")" "0"
        else
            echo "  INFO no RECOVER entries in the split (recover=${recover:-?}) — the evidence path is not exercised by this lap"
        fi
    fi
    sleep 5
    window_count_into wc11 "$O" 20 "$MARK" "P163-RECOVERY-COMPLETE slot=$vslot " "ZERO P163-RECOVERY-COMPLETE for slot  vslot (fail-before-purge)"
    ck "ZERO P163-RECOVERY-COMPLETE for slot $vslot (fail-before-purge)" "$wc11" "0"
    window_count_into wc12 "$O" 20 "$MARK" 'P226-UNTRUSTED-INTENT-SKIP' "ZERO P226-UNTRUSTED-INTENT-SKIP silent drops (census replaced the warn"
    ck "ZERO P226-UNTRUSTED-INTENT-SKIP silent drops (census replaced the warn)" "$wc12" "0"
    # sess479: record WHICH writer failed and with what errno.  A bare count
    # cannot be diagnosed: s479dc came back 4/5 under an AG-scoped domain
    # (ag_mask=0x100000000) with no way to tell whether the odd node was
    # refused because its allocation landed in the quarantined AG (which is
    # the containment working as designed, and would make this assertion
    # wrong) or for an unrelated reason (which would be a new defect).
    wr=0; wrdetail=
    for n in $O test2 test3 test4 test5; do
        r=$(rs 25 "$n" "err=\$( { echo x > $MNT/.icensus_$LABEL.$n ; } 2>&1 ); rc=\$?; rm -f $MNT/.icensus_$LABEL.$n 2>/dev/null; if [ \$rc = 0 ]; then echo WOK; else echo \"WFAIL rc=\$rc err=\$err\"; fi")
        case "$r" in
            *WOK*) wr=$((wr+1)); wrdetail="$wrdetail $n=ok";;
            *)     wrdetail="$wrdetail $n=FAIL[$(echo "$r" | tr '\n' ' ' | cut -c1-140)]";;
        esac
    done
    echo "  INFO survivor writers:$wrdetail"
    [ "$wr" = 5 ] || for n in $O test2 test3 test4 test5; do
        rs 20 "$n" "dmesg | sed -n \"/$MARK/,\\\$p\" | grep -a 'P240-QUAR-AG-EIO\|P241-RECOV-TERMINAL\|quarantin\|EROFS\|Read-only\|shutdown\|Corruption' | tail -6" | sed "s/^/  INFO writer-refusal $n: /"
    done
    # sess436: the published DOMAIN decides what survivors may do.  A
    # POLICY-REFUSED verdict whose refused images carried no AG attribution
    # publishes ag_mask=0 => FSWIDE, and a FSWIDE quarantine freezes every
    # survivor's writes by design (that containment is D-513/-356 material,
    # not this defect's).  An AG-scoped domain must leave the survivors'
    # own work alone.
    if echo "$tl" | grep -aq 'domain=1\|domain=FSWIDE'; then
        ck "FSWIDE quarantine: survivor writes refused, not silently accepted" "$wr" "0"
    else
        ck "AG-scoped quarantine leaves the survivors' own work alone (5 writers)" "$wr" "5"
    fi
else
    ck "census open=0 on an idle victim" "${open:-x}" "0"
    window_count_into wc13 "$O" 20 "$MARK" 'P226-FR-INTENTS-UNDISCHARGED' "ZERO P226-FR-INTENTS-UNDISCHARGED"
    ck "ZERO P226-FR-INTENTS-UNDISCHARGED" "$wc13" "0"
    window_count_into wc14 "$O" 20 "$MARK" 'P241-RECOV-TERMINAL .*reason=8 ' "ZERO reason=8 terminal verdicts"
    ck "ZERO reason=8 terminal verdicts" "$wc14" "0"
    wait_for_into t "$O" 90 "$MARK" "P163-RECOVERY-COMPLETE slot=$vslot "; ck "clean victim published normally (${t}s)" "$([ "$t" != timeout ] && echo yes || echo no)" "yes"
fi
measure "$O" 25 "$OUT/dmesg_$O.txt" '^DMESG_END$' "the kernel log on $O from the lap marker" "dmesg | sed -n \"/$MARK/,\\\$p\"; echo DMESG_END"
ck "zero splats on $O" "$(grep -aEc 'BUG:|Oops' "$OUT/dmesg_$O.txt")" "0"
$VIRSH start "$V" >/dev/null 2>&1; echo "  INFO virsh start $V rc=$?"
echo "=== d_intents_undischarged_verify $LABEL $ARM: fails=$fails out=$OUT $(date -u +%FT%TZ) ==="
echo "NOTE: $V was destroyed+restarted$([ "$ARM" = burst ] && echo ' and the victim slot carries an INTENTS_UNDISCHARGED quarantine') — prep_cluster before further rig work."
[ "$fails" -eq 0 ]
