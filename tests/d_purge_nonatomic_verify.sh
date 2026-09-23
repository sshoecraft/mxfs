#!/bin/bash
# d_purge_nonatomic_verify.sh — D-PURGE-NONATOMIC-PUBLICATION closure arms
# (sess419 design-consult ruling, ccmemory
# docs/rulings/purge-nonatomic-verification-design.md).
#
# The purge's interlock against a second survivor is the phase-0 freeze
# gate (purge_recov_gate: owner-only at GRANTS_RELEASED), re-derived at the
# mid-scan cadence and on the exact heartbeat image the final CAS publishes
# against.  Three arms, each on a freshly prepped 32/caw fleet, each ending
# with the victim dead and the fs needing prep (arms 2/3 leave a DBG_INJECTED
# quarantine on the victim slot by design):
#
#   concurrent  O=test1 (elected replayer: lowest live slot) pauses after
#               phase 0 (mxfs.dbg_purge_pause_ms); V=test8 is virsh-destroyed;
#               while O is paused, N=test2 invokes the NORMAL purge path for
#               V (mxfs.dbg_purge_victim).  Assert on N: P234-PURGE-FROZEN
#               naming owner O, trigger rc=-16 (EBUSY), zero P235, zero
#               writes; O then completes: P163-RECOVERY-COMPLETE, zero P229;
#               a second trigger on N after publication writes nothing
#               (rc<=0, purged=0); no live node was declared dead
#               (every 'heartbeat expired' line on the survivors names V's
#               slot); O, N and three other survivors stay writable.
#   midscan     O arms mxfs.dbg_purge_refreeze=1: at the scan start O
#               publishes a REAL QUARANTINED transition through the normal
#               refusal path (reason DBG_INJECTED=7) and forces the mid-scan
#               re-read.  Assert on O: P-DBG-PURGE-REFREEZE point=2 rc=0,
#               P241-RECOV-TERMINAL reason=7, P234-PURGE-REFROZE-MIDSCAN,
#               P229-PURGE-INCOMPLETE, P230-COMPLETE-PURGEFAIL, ZERO
#               P163-RECOVERY-COMPLETE, ZERO P235-PURGE-REFROZE.
#   prefinal    O arms mxfs.dbg_purge_refreeze=2: the transition lands after
#               the record scan, before the final heartbeat gate.  Assert on
#               O: P-DBG-PURGE-REFREEZE point=3 rc=0, P235-PURGE-REFROZE,
#               ZERO P234-PURGE-REFROZE-MIDSCAN, P229, P230-COMPLETE-PURGEFAIL,
#               ZERO P163-RECOVERY-COMPLETE.
#
# the budget rule (derived): destroy + 31x2 s dead window 62 s + fence/replay ~15 s
# + pause 25 s (concurrent) + harvest ~25 s => ~130 s.  Caller bound 200 s.
#
# Usage: tests/d_purge_nonatomic_verify.sh <label> <concurrent|midscan|prefinal> [O] [N] [V]
set -u
LABEL=${1:?label}; ARM=${2:?arm}; O=${3:-test1}; N=${4:-test2}; V=${5:-test8}
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd); cd "$REPO"
SSH=tools/mxfs_sshpass.sh
VIRSH="sudo virsh -c qemu:///system"
MNT=${MXFS_MNT:-/mnt/shared}
P=/sys/module/mxfs/parameters
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_purge_$ARM
mkdir -p "$OUT"
fails=0
ck() { if [ "$2" = "$3" ]; then echo "  PASS $1 ($2)"; else echo "  FAIL $1 got=$2 want=$3"; fails=$((fails+1)); fi; }
ge1() { [ "${1:-0}" -ge 1 ] && echo yes || echo no; }
# rs/rsx/measure/window_count_into (tests/lib/rig.sh): every count a verdict
# is taken from is acquired into its own file and validated in the parent
# shell first; a failed ssh is an ABORT, never a count of zero.
. "$(dirname "$0")/lib/rig.sh"
# cnt: POLLING ONLY (waitfor); never feeds a verdict
cnt() { rs 20 "$1" "dmesg | sed -n \"/$MARK/,\\\$p\" | grep -ac '$2'" | tr -dc '0-9'; }
waitfor() { # waitfor <node> <pattern> <max_s>
    local i=0; while [ $i -lt "$3" ]; do [ "$(cnt "$1" "$2")" -ge 1 ] 2>/dev/null && { echo $i; return 0; }; sleep 3; i=$((i+3)); done; echo timeout; return 1; }

echo "=== d_purge_nonatomic_verify label=$LABEL arm=$ARM O=$O N=$N V=$V out=$OUT $(date -u +%FT%TZ) ==="
want=$(modinfo mxfs.ko | awk '/^srcversion:/{print $2}')
for n in $O $N $V; do
    nsv=$(rs 15 "$n" "cat /sys/module/mxfs/srcversion" | tr -dc 'A-F0-9')
    [ "$nsv" = "$want" ] || { echo "ABORT: $n srcversion '$nsv' != tree '$want'"; exit 2; }
done
for k in dbg_purge_pause_ms dbg_purge_refreeze dbg_purge_victim; do
    rs 10 "$O" "test -e $P/$k && echo ok" | grep -q ok || { echo "ABORT: $O lacks $P/$k (build without the sess419 injectors?)"; exit 2; }
done
# sess420 fix (the sess407 trap, again): without the enforcement knobs the
# foreign replay is the DESIGNED blanket refusal (ledger #1 default) and the
# recovery never reaches the purge phase — all three s419 arms sat in
# waitfor until the caller's 200 s bound (rc=124).  Arm fleet-wide first.
tests/fleet_set_params.sh "target_cache_protected=1 foreign_replay_token_enforce=1" 32 "$OUT/knobs.txt" > "$OUT/knobs.log" 2>&1 || { echo "ABORT: enforcement arming failed: $(tail -2 "$OUT/knobs.log" | tr '\n' ' ')"; exit 2; }
echo "  INFO enforcement armed fleet-wide ($OUT/knobs.txt)"
MARK="PURGE-$LABEL-$ARM-$$"
for n in $O $N; do rs 12 "$n" "echo '$MARK' > /dev/kmsg" >/dev/null; done
# a few files on V so it owns real ACTIVE lock records at death
rs 30 "$V" "mkdir -p $MNT/.purge_$LABEL && for i in 1 2 3 4; do dd if=/dev/urandom of=$MNT/.purge_$LABEL/v\$i bs=4096 count=2 2>/dev/null; done; sync; echo ok" | grep -q ok || { echo "ABORT: V setup failed"; exit 2; }

case "$ARM" in
  concurrent) rs 10 "$O" "echo 25000 > $P/dbg_purge_pause_ms; cat $P/dbg_purge_pause_ms" | grep -q 25000 || { echo "ABORT: could not arm pause on $O"; exit 2; } ;;
  midscan)    rs 10 "$O" "echo 1 > $P/dbg_purge_refreeze; cat $P/dbg_purge_refreeze" | grep -q '^1' || { echo "ABORT: could not arm refreeze=1"; exit 2; } ;;
  prefinal)   rs 10 "$O" "echo 2 > $P/dbg_purge_refreeze; cat $P/dbg_purge_refreeze" | grep -q '^2' || { echo "ABORT: could not arm refreeze=2"; exit 2; } ;;
  *) echo "ABORT: unknown arm $ARM"; exit 2 ;;
esac
$VIRSH destroy "$V" >/dev/null 2>&1; echo "  INFO virsh destroy $V rc=$? at $(date -u +%T)"

wait_for_into t "$O" 110 "$MARK" "elected (slot"; ck "$O elected to replay $V's slice (${t}s)" "$([ "$t" != timeout ] && echo yes || echo no)" "yes"
vline=$(rs 20 "$O" "dmesg | sed -n \"/$MARK/,\\\$p\" | grep -a 'lease expired/died' | head -1")
vid=$(echo "$vline" | grep -ao 'node [0-9]* (slot' | tr -dc '0-9'); vslot=$(echo "$vline" | grep -ao '(slot [0-9]*' | tr -dc '0-9')
window_into "$OUT/rv_oid_1.txt" "$O" 15; oid=$(cat "$OUT/rv_oid_1.txt" | grep -ao 'MXFS-MEMBERSHIP local=[0-9]*' | tail -1 | tr -dc '0-9')
echo "  INFO victim node=$vid slot=$vslot owner(O) node=$oid"
[ -n "$vid" ] || { echo "ABORT: could not parse victim node id"; fails=$((fails+1)); }

if [ "$ARM" = concurrent ]; then
    wait_for_into t "$O" 120 "$MARK" "P-DBG-PURGE-PAUSE"; ck "$O paused after phase 0 (${t}s)" "$([ "$t" != timeout ] && echo yes || echo no)" "yes"
    rs 12 "$N" "echo '$MARK' > /dev/kmsg" >/dev/null
    rs 90 "$N" "echo $vid > $P/dbg_purge_victim; echo rc=\$?" > "$OUT/n_trigger1.txt"
    sleep 2
    window_count_into wc1 "$N" 20 "$MARK" 'P234-PURGE-FROZEN' "N refused at phase 0: P234-PURGE-FROZEN"
    ck "$N refused at phase 0: P234-PURGE-FROZEN" "$(ge1 "$wc1")" "yes"
    window_count_into wc2 "$N" 20 "$MARK" "P234-PURGE-FROZEN node=$vid .*owner=$oid" "N s refusal names owner  oid"
    ck "$N's refusal names owner $oid" "$(ge1 "$wc2")" "yes"
    window_count_into wc3 "$N" 20 "$MARK" 'P-DBG-PURGE-TRIGGER node='$vid' rc=-16' "N trigger returned -EBUSY"
    ck "$N trigger returned -EBUSY" "$(ge1 "$wc3")" "yes"
    window_count_into wc4 "$N" 20 "$MARK" 'P235-PURGE' "N zero P235 (no CAS retry exhaustion)"
    ck "$N zero P235 (no CAS retry exhaustion)" "$wc4" "0"
    window_count_into wc5 "$N" 20 "$MARK" 'P-DBG-PURGE-TRIGGER node='$vid' rc=-16 purged=0' "N zeroed nothing (P-DBG-PURGE-TRIGGER purged=0)"
    ck "$N zeroed nothing (P-DBG-PURGE-TRIGGER purged=0)" "$(ge1 "$wc5")" "yes"
    wait_for_into t "$O" 90 "$MARK" "P163-RECOVERY-COMPLETE"; ck "$O published normally after the pause (${t}s)" "$([ "$t" != timeout ] && echo yes || echo no)" "yes"
    window_count_into wc6 "$O" 20 "$MARK" 'P229-PURGE-INCOMPLETE' "O zero P229-PURGE-INCOMPLETE"
    ck "$O zero P229-PURGE-INCOMPLETE" "$wc6" "0"
    rs 90 "$N" "echo $vid > $P/dbg_purge_victim; echo rc=\$?" > "$OUT/n_trigger2.txt"
    sleep 2
    window_count_into wc7 "$N" 20 "$MARK" 'P-DBG-PURGE-TRIGGER node='$vid' rc=[-0-9]* purged=0' "N post-publication trigger wrote nothing (purged=0)"
    ck "$N post-publication trigger wrote nothing (purged=0)" "$(ge1 "$wc7")" "yes"
    window_count_into wc8 "$N" 20 "$MARK" 'P235-PURGE' "N still zero P235"
    ck "$N still zero P235" "$wc8" "0"
    # no live node declared dead anywhere: every expiry line names V's slot
    D=$(mktemp -d)
    for i in $(seq 1 32); do
        [ "test$i" = "$V" ] && continue
        ( timeout 15 $SSH "test$i" "dmesg | sed -n \"/$MARK/,\\\$p\" | grep -a 'heartbeat expired' | grep -avc 'slot $vslot '" 2>/dev/null | filt | tr -dc '0-9' > "$D/test$i" ) &
    done; wait
    bad=0; for f in "$D"/test*; do v=$(cat "$f"); [ "${v:-0}" != 0 ] && bad=$((bad+1)); done
    ck "no live node declared dead on any survivor (expiry lines not naming slot $vslot)" "$bad" "0"
    wr=0; for n in $O $N test3 test4 test5; do rs 20 "$n" "echo x > $MNT/.purge_$LABEL.$n && rm -f $MNT/.purge_$LABEL.$n && echo WOK" | grep -q WOK && wr=$((wr+1)); done
    ck "survivors writable after the concurrent attempt" "$wr" "5"
else
    pt=2; [ "$ARM" = prefinal ] && pt=3
    wait_for_into t "$O" 130 "$MARK" "P-DBG-PURGE-REFREEZE point=$pt"; ck "$O injected the transition at point $pt (${t}s)" "$([ "$t" != timeout ] && echo yes || echo no)" "yes"
    window_count_into wc9 "$O" 20 "$MARK" "P-DBG-PURGE-REFREEZE point=$pt .*rc=0" "transition published through the normal refusal path (rc=0)"
    ck "transition published through the normal refusal path (rc=0)" "$(ge1 "$wc9")" "yes"
    window_count_into wc10 "$O" 20 "$MARK" 'P241-RECOV-TERMINAL .*reason=7' "P241-RECOV-TERMINAL reason=7 (DBG_INJECTED) on  O"
    ck "P241-RECOV-TERMINAL reason=7 (DBG_INJECTED) on $O" "$(ge1 "$wc10")" "yes"
    sleep 8
    if [ "$ARM" = midscan ]; then
        window_count_into wc11 "$O" 20 "$MARK" 'P234-PURGE-REFROZE-MIDSCAN' "mid-scan re-derivation refused: P234-PURGE-REFROZE-MIDSCAN"
        ck "mid-scan re-derivation refused: P234-PURGE-REFROZE-MIDSCAN" "$(ge1 "$wc11")" "yes"
        window_count_into wc12 "$O" 20 "$MARK" 'P235-PURGE-REFROZE' "no final-HB refreeze (scan stopped first)"
        ck "no final-HB refreeze (scan stopped first)" "$wc12" "0"
    else
        window_count_into wc13 "$O" 20 "$MARK" 'P235-PURGE-REFROZE' "final-HB gate refused on the exact image: P235-PURGE-REFROZE"
        ck "final-HB gate refused on the exact image: P235-PURGE-REFROZE" "$(ge1 "$wc13")" "yes"
        window_count_into wc14 "$O" 20 "$MARK" 'P234-PURGE-REFROZE-MIDSCAN' "no mid-scan refreeze (transition landed after the scan)"
        ck "no mid-scan refreeze (transition landed after the scan)" "$wc14" "0"
    fi
    window_count_into wc15 "$O" 20 "$MARK" 'P229-PURGE-INCOMPLETE' "purge reported INCOMPLETE (P229)"
    ck "purge reported INCOMPLETE (P229)" "$(ge1 "$wc15")" "yes"
    window_count_into wc16 "$O" 20 "$MARK" 'P230-COMPLETE-PURGEFAIL' "recovery NOT published (P230-COMPLETE-PURGEFAIL)"
    ck "recovery NOT published (P230-COMPLETE-PURGEFAIL)" "$(ge1 "$wc16")" "yes"
    window_count_into wc17 "$O" 20 "$MARK" "P163-RECOVERY-COMPLETE slot=$vslot " "ZERO P163-RECOVERY-COMPLETE for the victim"
    ck "ZERO P163-RECOVERY-COMPLETE for the victim" "$wc17" "0"
fi
for n in $O $N; do measure "$n" 20 "$OUT/dmesg_$n.txt" '^DMESG_END$' "the kernel log on $n from the lap marker" "dmesg | sed -n \"/$MARK/,\\\$p\"; echo DMESG_END"; ck "zero splats on $n" "$(grep -aEc 'BUG:|Oops' "$OUT/dmesg_$n.txt")" "0"; done
rs 10 "$O" "echo 0 > $P/dbg_purge_pause_ms; echo 0 > $P/dbg_purge_refreeze; true" >/dev/null
$VIRSH start "$V" >/dev/null 2>&1; echo "  INFO virsh start $V rc=$?"
echo "=== d_purge_nonatomic_verify $LABEL $ARM: fails=$fails out=$OUT $(date -u +%FT%TZ) ==="
echo "NOTE: $V was destroyed+restarted$([ "$ARM" != concurrent ] && echo ' and the victim slot carries a DBG_INJECTED quarantine') — prep_cluster before further rig work."
[ "$fails" -eq 0 ]
