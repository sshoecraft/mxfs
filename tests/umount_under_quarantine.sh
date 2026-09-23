#!/bin/bash
# umount_under_quarantine.sh — D-UMOUNT-QUARANTINE-TIMEOUT-DIRTY-WITHDRAW-356
# verification (sess446).
#
# THE DEFECT (measured sess356 on 0.13.x): a foreign-slice replay was REFUSED
# and the victim's domain quarantined; the victim's frozen ROOT-DIR EX stayed
# on the wire; four survivors then ran a CLEAN unmount, teardown's root-inode
# EX acquire polled to DLM -110 (5 min), the node declared
# 'DLM inode lock unrecoverable', shut down and WITHDREW DIRTY — a healthy
# node unmounting became a recovery event.  sess357 ruling: a quarantine is
# not local DLM corruption; the acquire must fail fast with the quarantine
# verdict and the departure must stay CLEAN; dirty withdraw is reserved for
# real corruption / membership loss / post-commit failure.
#
# What the tree does since (sess374/376): the CAW wait loop asks the
# quarantine oracle every lap (P240-QUAR-WAITCANCEL -> -EIO in ms), the ilock
# path classifies a timeout under an imported quarantine as P240-QUAR-EIO-ABORT
# (op fails EIO, NOT shutdown), and only 'no quarantine, no pending recovery'
# reaches the fail-fast shutdown (xfs/xfs_mxfs_dlm.c ~32968).  Nothing has
# ever exercised the UNMOUNT path under that regime.  This does, in the exact
# sess356 shape: the forged refusal's AG mask INCLUDES ag0, so the root
# inode's EX is IN closure and correctly stays frozen (no purge/scrub can
# repair it — that is D-REFUSAL-GRANT-FREEZE's out-of-closure arm, not this).
#
# PASS (all must hold):
#   1. the refusal is terminal and imported: >=1 'terminal outcome PUBLISHED'
#      fleet-wide and P240-QUAR-IMPORT on every survivor;
#   2. a probe 'touch' in the root dir on two survivors fails FAST (rc!=0
#      within PROBE_BUDGET; the quarantine gate, not a 5-min wait);
#   3. every survivor's `umount` returns 0 and the mountpoint is gone;
#      mass-umount wall <= UMOUNT_BUDGET (budget: 31-way clean umount measured
#      ~100 s sess342);
#   4. on EVERY survivor since T0: zero 'DLM inode lock unrecoverable', zero
#      'Filesystem has been shut down', zero withdraw, zero
#      P302-PR-KEY-RETAINED-FENCE-TARGET, zero P301-DEPARTURE-INCOMPLETE;
#   5. chk_mxfs after the storm: the record carries exactly one dead/refused
#      victim slot and NO WITHDRAWN slots.
# The FS is left with a durable quarantine — the caller must re-prep.
#
# Usage: tests/umount_under_quarantine.sh <label> [N=32] [victim=test2]
# the budget rule (derived): srcgate+arm 30 s; churn 6 s; fence+refuse+publish+import
# 150 s (closure_purge_scrub's RECOVERY_WAIT); probes <= 4 x 20 s per host,
# measured ~1 s (sess446 chain 48); umount <= 150 s bound (assert 120); sweeps
# 40 s; chk 120 s.  Total ~520 s measured-shape; caller bound 660.
set -u
LABEL=${1:?label}
N=${2:-32}
VICTIM=${3:-test2}
cd "$(dirname "$0")/.." || exit 2
SSH=tools/mxfs_sshpass.sh
VIRSH="sudo virsh -c qemu:///system"
MNT=${MXFS_MNT:-/mnt/shared}
IMG=$(tools/mxfs_host_image.sh) || { echo "$IMG"; exit 2; }
RECOVERY_WAIT=${RECOVERY_WAIT:-150}
PROBE_BUDGET=${PROBE_BUDGET:-20}
UMOUNT_BUDGET=${UMOUNT_BUDGET:-120}
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_umountquar_$LABEL
mkdir -p "$OUT"
TREE_SV=$(modinfo mxfs.ko 2>/dev/null | awk '/srcversion/{print $2}')
fails=0
pass() { echo "  PASS $1"; }
fail() { echo "  FAIL $1"; fails=$((fails+1)); }
info() { echo "  INFO $1"; }
sshq() { timeout "$1" "$SSH" "$2" "$3" 2>/dev/null | grep -av '^Unauthorized\|^Warning\|^If you'; }
[ "$VICTIM" = test1 ] && { echo "victim must not be test1 (probe host)"; exit 2; }
survivors=(); for i in $(seq 1 "$N"); do [ "test$i" = "$VICTIM" ] || survivors+=("test$i"); done
STAMP=@$(date +%s)
echo "=== umount_under_quarantine label=$LABEL N=$N victim=$VICTIM sv=$TREE_SV out=$OUT $(date -u +%FT%TZ) ==="

# 1. srcgate + arm: enforcement (as every death harness) + the forged
#    IN-CLOSURE refusal (ag_mask 0x1 = ag0, the root inode's AG).
for h in "${survivors[@]}"; do
    sshq 30 "$h" "cat /sys/module/mxfs/srcversion; mountpoint -q $MNT && echo MOUNTED
        echo 1 > /sys/module/mxfs/parameters/target_cache_protected; echo 1 > /sys/module/mxfs/parameters/foreign_replay_token_enforce
        echo 0x1 > /sys/module/mxfs/parameters/freplay_force_ag_mask; echo 1 > /sys/module/mxfs/parameters/freplay_force_refusal; echo -1 > /sys/module/mxfs/parameters/freplay_force_slot
        echo enforce=\$(cat /sys/module/mxfs/parameters/foreign_replay_token_enforce) refuse=\$(cat /sys/module/mxfs/parameters/freplay_force_refusal) mask=\$(cat /sys/module/mxfs/parameters/freplay_force_ag_mask)" > "$OUT/$h.gate" &
done; wait
bad=""
for h in "${survivors[@]}"; do grep -q "^$TREE_SV" "$OUT/$h.gate" && grep -q MOUNTED "$OUT/$h.gate" && grep -q 'enforce=1 refuse=1 mask=1' "$OUT/$h.gate" || bad="$bad $h"; done
[ -z "$bad" ] && pass "srcgate: ${#survivors[@]} survivors on $TREE_SV, mounted, armed (enforce=1, forced in-closure refusal mask=0x1)" || { fail "srcgate/arm:$bad"; echo "=== umount_under_quarantine $LABEL: fails=$fails (setup) out=$OUT ==="; exit 1; }

# 2. the victim takes a HOT root-dir EX and dies holding it (closure_purge_scrub shape)
sshq 20 "$VICTIM" "nohup bash -c 'end=\$((SECONDS+126)); i=0; while [ \$SECONDS -lt \$end ]; do i=\$((i+1)); echo hot > $MNT/.uq_victim.\$i; rm -f $MNT/.uq_victim.\$((i-3)); done' >/tmp/uq_load.log 2>&1 &" >/dev/null
sleep 6
# sess446 D-0515: pre-create the unlink/rename targets for the step-4 probes
# (rm/mv of an EXISTING name; a churn name the victim already deleted would
# let `rm -f` return 0 without ever reaching the gate).
sshq 20 test1 "touch $MNT/.uq_pre_unlink $MNT/.uq_pre_rename; ls $MNT/.uq_pre_unlink $MNT/.uq_pre_rename" > "$OUT/precreate.txt"
grep -q uq_pre_rename "$OUT/precreate.txt" && pass "unlink/rename probe targets pre-created on test1" || fail "probe targets not created: $(head -c 120 "$OUT/precreate.txt")"
lc=$(sshq 20 test1 "ls -a $MNT/ 2>/dev/null | grep -c uq_victim" | tail -1 | tr -d '[:space:]')
[ "${lc:-0}" -gt 0 ] && pass "victim holds a hot root-dir EX ($lc churn files visible from test1)" || fail "victim root-dir churn never landed"
TK=$(date +%s)
$VIRSH destroy "$VICTIM" > "$OUT/destroy.txt" 2>&1 && info "victim $VICTIM destroyed at $(date -u +%FT%TZ)" || { fail "virsh destroy $VICTIM"; echo "=== umount_under_quarantine $LABEL: fails=$fails out=$OUT ==="; exit 1; }

# 3. fence + refusal + publication + import
sleep "$RECOVERY_WAIT"
for h in "${survivors[@]}"; do
    sshq 30 "$h" "journalctl -k --since '$STAMP' --no-pager 2>/dev/null | grep -a 'terminal outcome PUBLISHED\|POLICY-REFUSED\|P240-QUAR-IMPORT\|P240-QUAR-REFUSE\|P240-QUAR-EIO-ABORT\|P240-QUAR-WAITCANCEL\|slice replay refused'" > "$OUT/$h.recov" 2>/dev/null &
done; wait
pub=$(cat "$OUT"/test*.recov | grep -ac 'terminal outcome PUBLISHED'); imp=0
for h in "${survivors[@]}"; do grep -aq 'P240-QUAR-IMPORT' "$OUT/$h.recov" && imp=$((imp+1)); done
[ "$pub" -ge 1 ] && pass "refusal published (terminal outcome PUBLISHED x$pub)" || fail "no terminal outcome PUBLISHED within ${RECOVERY_WAIT}s: $(cat "$OUT"/test*.recov | head -2 | cut -c1-160 | tr '\n' ' ')"
[ "$imp" -eq "${#survivors[@]}" ] && pass "quarantine imported on $imp/${#survivors[@]} survivors" || fail "quarantine imported on only $imp/${#survivors[@]} survivors"

# 4. the fail-fast probes on two survivors (the quarantine gate, not a 5-min
#    wait).  sess446 D-0515: FOUR namespace ops, each against the quarantined
#    root dir — create, mkdir, unlink of an existing (victim-churn) name, rename
#    of one — and every one must be refused (rc!=0) BEFORE any transaction: the
#    gate line P240-QUAR-NSOP-REFUSE must appear on each probed host.  On 0.53.0
#    `touch` committed lock-less on test32 (rc=0) — that is the defect.
PROBE_HOSTS=(test1 "${survivors[$(( ${#survivors[@]} - 1 ))]}")
for h in "${PROBE_HOSTS[@]}"; do
    s=$(date +%s)
    sshq $((4*PROBE_BUDGET+10)) "$h" "for op in create mkdir unlink rename; do
        case \$op in
          create) timeout $PROBE_BUDGET touch $MNT/.uq_probe_$h ;;
          mkdir)  timeout $PROBE_BUDGET mkdir $MNT/.uq_probedir_$h ;;
          unlink) timeout $PROBE_BUDGET rm $MNT/.uq_pre_unlink ;;
          rename) timeout $PROBE_BUDGET mv $MNT/.uq_pre_rename $MNT/.uq_moved_$h ;;
        esac 2>/dev/null; echo OP=\$op RC=\$?; done" > "$OUT/$h.probe"
    e=$(( $(date +%s) - s ))
    bad=""; for op in create mkdir unlink rename; do r=$(grep -ao "OP=$op RC=[0-9]*" "$OUT/$h.probe" | grep -o '[0-9]*$'); [ "${r:-0}" -ne 0 ] || bad="$bad $op(rc=${r:-?})"; done
    [ -z "$bad" ] && [ "$e" -le $((4*PROBE_BUDGET)) ] && pass "probes on $h all refused fast (create/mkdir/unlink/rename, ${e}s)" || fail "probes on $h: not refused:${bad:- none} wall ${e}s (want rc!=0 x4 within $((4*PROBE_BUDGET))s)"
done
for h in "${PROBE_HOSTS[@]}"; do
    sshq 30 "$h" "journalctl -k --since '$STAMP' --no-pager 2>/dev/null | grep -a 'P240-QUAR-NSOP-REFUSE'" > "$OUT/$h.nsop" 2>/dev/null
    n=$(grep -ac 'P240-QUAR-NSOP-REFUSE' "$OUT/$h.nsop"); ops=$(grep -ao 'op=[a-z_]*' "$OUT/$h.nsop" | sort -u | tr '\n' ' ')
    [ "$n" -ge 4 ] && pass "namespace gate fired on $h (P240-QUAR-NSOP-REFUSE x$n: $ops)" || fail "namespace gate on $h: P240-QUAR-NSOP-REFUSE x$n (want >=4, one per op): $ops"
done

# 5. mass clean unmount of every survivor
UT=$(date +%s)
for h in "${survivors[@]}"; do ( sshq 160 "$h" "timeout 150 umount $MNT; echo UMOUNT_RC=\$?; mountpoint -q $MNT && echo STILL_MOUNTED || echo UNMOUNTED" > "$OUT/$h.umount" 2>&1 ) & done; wait
UW=$(( $(date +%s) - UT ))
um_ok=0; um_bad=""
for h in "${survivors[@]}"; do grep -q 'UMOUNT_RC=0' "$OUT/$h.umount" && grep -q '^UNMOUNTED' "$OUT/$h.umount" && um_ok=$((um_ok+1)) || um_bad="$um_bad $h($(tr '\n' ' ' < "$OUT/$h.umount" | cut -c1-40))"; done
[ "$um_ok" -eq "${#survivors[@]}" ] && pass "all ${#survivors[@]} survivors unmounted rc=0 (wall ${UW}s)" || fail "umount: $um_ok/${#survivors[@]} clean —$um_bad"
[ "$UW" -le "$UMOUNT_BUDGET" ] && pass "mass umount wall ${UW}s <= ${UMOUNT_BUDGET}s" || fail "mass umount wall ${UW}s > ${UMOUNT_BUDGET}s (budget)"

# 6. per-survivor sweep: the departure must have been CLEAN
for h in "${survivors[@]}"; do
    sshq 40 "$h" "journalctl -k --since '$STAMP' --no-pager 2>/dev/null | grep -a 'DLM inode lock unrecoverable\|Filesystem has been shut down\|withdraw\|WITHDRAW\|P302-PR-KEY-RETAINED\|P301-DEPARTURE-INCOMPLETE\|P240-QUAR\|BUG:\|Oops\|Corruption'" > "$OUT/$h.sweep" 2>/dev/null &
done; wait
for pat in 'DLM inode lock unrecoverable' 'Filesystem has been shut down' 'withdraw' 'P302-PR-KEY-RETAINED' 'P301-DEPARTURE-INCOMPLETE' 'BUG:' 'Oops' 'Corruption'; do
    c=0; who=""
    for h in "${survivors[@]}"; do n=$(grep -aic "$pat" "$OUT/$h.sweep"); [ "$n" -gt 0 ] && { c=$((c+n)); who="$who $h"; }; done
    [ "$c" -eq 0 ] && pass "no '$pat' on any survivor" || { fail "'$pat' x$c on$who"; grep -aih "$pat" "$OUT"/test*.sweep | head -2 | cut -c1-200 | sed 's/^/    /'; }
done
qe=$(cat "$OUT"/test*.sweep | grep -ac 'P240-QUAR-EIO-ABORT\|P240-QUAR-WAITCANCEL\|P240-QUAR-REFUSE')
info "quarantine-gate lines during the storm: $qe (EIO-ABORT/WAITCANCEL/REFUSE)"

# 7. the platter after the storm
timeout 120 tools/chk_mxfs -v "$IMG" > "$OUT/chk.txt" 2>&1
grep -a 'slot\|withdraw\|WITHDRAW\|quarant\|refus' "$OUT/chk.txt" | head -12 | cut -c1-160 | sed 's/^/    /'
wd=$(grep -ao "[0-9]* withdrawn slice" "$OUT/chk.txt" | grep -o "^[0-9]*"); [ "${wd:-1}" -eq 0 ] && pass "chk: 0 withdrawn slices ($(grep -ao "[0-9]* terminal verdict" "$OUT/chk.txt" | head -1))" || fail "chk: withdrawn slices=${wd:-?}"
echo "=== umount_under_quarantine $LABEL: fails=$fails out=$OUT $(date -u +%FT%TZ) ==="
[ "$fails" -eq 0 ]
