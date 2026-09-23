#!/bin/bash
# tests/settle_token_arms.sh — 0.61.0 (sess454) landing-group-2 verification:
# the RETIRE_PENDING ABSENT settlement now runs on the retire settle worker
# under the host-wide departure mutex with a single-use proof token (design-consult
# design rulings D1/D6/D8, docs/pr-fencing-departure.md "0.61.0").
#
# usage: settle_token_arms.sh <N> <victim> <probe> <arm> [dev]
#   arm = plain     a clean unmount (key retired) is settled EMPTY by a peer's
#                   WORKER (P304-RETIRE-WORKER result=EMPTY, P-PR-SETTLE-ABSENT,
#                   P304-RETIRE-COMPLETED-BY-PEER exactly once), never by the
#                   heartbeat thread, and no PROUT ran outside the mutex.
#         inval     dbg_settle_inval_after_mint=1 on every peer: the first
#                   settle attempt's token is refused at the CAS
#                   (P-PR-PROOF-REFUSED why=invalidated-since-mint), NOTHING is
#                   published on it, and a later attempt settles the record.
#         double    dbg_settle_double_consume=1 on every peer: a second consume
#                   of the same token is refused (proof replay), the record is
#                   published exactly once.
#         probehang dbg_probe_hang_ms=15000 on the victim: its probe thread
#                   ignores the stop; the unmount's bounded join quarantines
#                   (P-PR-PROBE-STUCK, P304-DEPARTURE-QUARANTINED, key RETAINED,
#                   no release stamp), an immediate remount is refused
#                   (P-PR-QUARANTINE-REFUSED), the thread is reaped once it
#                   exits (P-PR-PROBE-REAPED), and the dirty predecessor is
#                   fenced + recovered by the peers before the victim rejoins.
#         slowrace  (D9 "key reuse / later incarnation" + "slow settler / CAW
#                   compare mismatch") dbg_settle_pause_ms=8000 on every peer:
#                   the victim unmounts cleanly; the peers' workers see the
#                   RETIRE_PENDING record on their next lap, mint an ABSENCE
#                   proof and pause 8 s before the CAS; 3.5 s after the umount
#                   the victim REMOUNTS — its REGISTER puts the SAME key back
#                   (same host, same boot) and its P305 settles its own record
#                   by key PRESENCE (P305-RETIRE-SETTLED-OWN, not the absence
#                   path).  Exactly ONE EMPTY may land across victim + peers
#                   (SETTLED-OWN + COMPLETED-BY-PEER == 1): whichever CAS lands
#                   first wins on the exact image, every other paused settler
#                   loses the compare (CHANGED / "CAS lost"), nothing publishes
#                   twice, nothing runs unheld, the remount is admitted.
#                   (chain 77's first shape — pause 3 s, immediate remount —
#                   never reached a peer's settle: the own-key path has no
#                   pause and won within 1 s.)
#         latewait  (0.61.1 landing group 3 as re-ruled in sess455) dbg_depart_late_token_ms=6000
#                   on the victim: at the departure freeze one extra token is
#                   taken and retired 6 s later.  The drain must WAIT for it
#                   (P304-RETIRE-DRAIN inflight=1, then P304-RETIRE-DRAIN-STALL
#                   each 2 s round, then P304-RETIRE-DRAINED after 3-4 rounds),
#                   P-DBG-DEPART-LATE-TOKEN-RETIRED inflight_now=0 must precede
#                   the release, the departure must then be CLEAN (QUIESCED,
#                   release stamp, key retired, no P302), umount wall 6..10 s,
#                   no kernel BUG/Oops/refcount report, and a peer settles the
#                   record EMPTY exactly once as in the plain arm.
#         latecomp  (0.61.0 build 923EB92D ONLY — the bounded-drain semantics
#                   the sess455 review rejected; superseded by latewait)
#                   dbg_depart_late_token_ms=6000
#                   on the victim: at the departure freeze one synthetic I/O
#                   token is taken and retired 6 s later, past the 2 s drain
#                   bound.  The unmount must report P304-RETIRE-DRAIN then
#                   P304-RETIRE-DRAIN-TIMEOUT and P304-RETIRE-NOT-QUIESCED, write
#                   NO release stamp, retain the key (P302), and return within
#                   the bound; the late retire must then land on LIVE accounting
#                   (P-DBG-DEPART-LATE-TOKEN-RETIRED inflight_now=0) with no
#                   kernel BUG/Oops/KASAN report on the victim, and the peers
#                   fence the retained key and recover the dirty slot.
#         untokened (sess459, review #5 condition 8) dbg_depart_inject=1
#                   on the victim: at the departure freeze one buffer completion
#                   that never entered xfs_buf_submit_ex is injected.  The gate
#                   must fail closed: P304-IOCNT-UNTOKENED, NOT-QUIESCED
#                   untokened=1, no release stamp, key retained, drain not
#                   abandoned, umount < 8 s, peers fence + recover.
#                   Budget: umount ~3 s + 62 s stale + ~10 s recovery + 40 s prep
#                   ≈ 115 s → 160.
#         postteardown / orphantoken / orphanrejected / overflow / underflow
#                   (sess459, review #5 condition 1) dbg_depart_inject=2..6 on
#                   the victim: the deterministic G3 accounting arms — a
#                   submission after the teardown (rejected at the take, the
#                   FINAL assertion blocks: io_after_freeze=1), a buffer freed
#                   holding a token (ORPHAN, corrupt, drain ABANDONED after one
#                   2 s round), a buffer freed with a pending post-freeze
#                   rejection (ORPHAN, corrupt), 256 takes on one buffer (255
#                   admitted, P304-IOCNT-OVERFLOW, corrupt), a forced invalid
#                   decrement (corrupt).  All: NOT-QUIESCED, no release stamp,
#                   key retained, no fault, umount < 12 s, peers fence + recover.
#                   Budget each: umount ≤ 4 s + 62 s stale + ~10 s recovery +
#                   40 s prep ≈ 116 s → 160.
#         carryfreeze (sess459, review #5 condition 1 "retry carry") dbg_depart_inject=7:
#                   pre-freeze one token + a pending-retry mark; the resubmit
#                   lands 3 s later inside the drain: carry take REJECTED
#                   after the freeze, its completion retires the ONE token
#                   (DRAINED, no orphan/corrupt), FINAL assertion NOT-QUIESCED
#                   io_after_freeze=1, no release, key retained, umount 3..10 s,
#                   peers fence + recover.  Budget ≈ 120 s → 160.
#         carrylive (same condition, the real path) buf_inject_write_eio_live=1
#                   on the victim + 8 small creates + sync: the next live
#                   metadata write fails at submit, xfs_buf_ioend_handle_error
#                   resubmits it carrying its token (P304-TOKEN-CARRY kept),
#                   the retry completes; the clean unmount is QUIESCED with
#                   carried>=1, releases, key retired, peer settles EMPTY once.
#                   Budget: workload 5 s + umount 5 s + settle + prep ≈ 95 s → 130.
#         workerhang (sess460, review #5 condition 2) dbg_retire_hang_ms=15000
#                   on the victim: the RETIRE SETTLE WORKER ignores its stop
#                   (parked at its loop top, no lock held); the unmount's 5 s
#                   bounded join quarantines the whole DLM context
#                   (P304-RETIRE-WORKER-STUCK, P304-DEPARTURE-QUARANTINED, no
#                   release stamp, key RETAINED), the immediate remount is
#                   refused (P-PR-QUARANTINE-REFUSED), the context is reaped
#                   once the worker exits (P304-RETIRE-WORKER-REAPED), peers
#                   fence + recover.  Budget as probehang → 200.
#         workerhangheld (same condition, mutex-held shape) the victim's
#                   worker is parked INSIDE a settle (dbg_settle_pause_ms=30000
#                   on every peer, SETTLE_VICTIM2's clean umount supplies the
#                   RETIRE_PENDING record); the victim then unmounts: STUCK +
#                   QUARANTINED, and put_super's late phase WAITS on the
#                   departure mutex the parked worker holds (measured wall).
#                   Budget: 30 s pause + 5 s join + 62 s stale + recovery +
#                   remounts ≈ 170 s → 240.
# derived time budgets (derived): plain/inval/double = umount 5 s + worker settle
# (2 s lap + bracket) x2 laps + sweeps 4x8 s + prep 40 s ≈ 90 s → 120;
# probehang = 5 s join + 11 s hang + 62 s stale + ~10 s recovery + 40 s prep
# ≈ 130 s → 200; latecomp = 2 s drain + 6 s token + 62 s stale + ~10 s
# recovery + 40 s prep ≈ 120 s → 160; latewait = umount 5 s + 6 s wait +
# worker settle x2 laps + sweeps 3x8 s + prep 40 s ≈ 90 s → 120; slowrace = umount 5 s + 3.5 s
# + remount ~8 s + peers' 8 s pause + sweeps 3x8 s + prep 40 s ≈ 95 s → 130.
set -u
N=${1:?N}; VICTIM=${2:?victim}; PROBE=${3:?probe}; ARM=${4:?arm}
# the device under test by identity, not by path: the LUN this rig declares
# (data/rigs.json), verified by its WWID on the node, and the node's live mxfs
# mount when it has one; MXFS_DEV names a candidate that must be that LUN.
# mxfs_dev_resolve (tests/lib/rig.sh) ABORTs on anything else, never defaults
. "$(dirname "$0")/lib/rig.sh"
MXFS_DEV=${5:-${MXFS_DEV:-}}; mxfs_dev_resolve "$PROBE"; DEV=$MXFS_DEV_RESOLVED
MNT=/mnt/shared
SSH=/src/mxfs/tools/mxfs_sshpass.sh
OUT=/src/mxfs/tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_settle_token_$ARM
mkdir -p "$OUT"
say() { echo "[settle_token/$ARM] $*"; }
fails=0
fail() { say "FAIL: $*"; fails=$((fails+1)); }
echo "=== settle_token_arms arm=$ARM N=$N victim=$VICTIM probe=$PROBE dev=$DEV @ $(date -u +%Y%m%dT%H%M%SZ) sv=$(modinfo /src/mxfs/mxfs.ko | awk '/srcversion/{print $2}') ==="

nodes() { local i; for i in $(seq 1 "$N"); do echo "test$i"; done; }
# fleet_do <tag> <cmd>: run cmd on every node in parallel, per-node files
fleet_do() { local tag="$1" cmd="$2" h; for h in $(nodes); do ( timeout 25 "$SSH" "$h" "$cmd" > "$OUT/${tag}_$h.txt" 2>/dev/null; echo "rc=$?" >> "$OUT/${tag}_$h.txt" ) & done; wait; }
sweep() { fleet_do "$1" "dmesg"; }
count() { # <tag> <mark> [exclude] → fleet sum of matches in the sweep files
    local tag="$1" m="$2" ex="${3:-}" h s=0 c
    for h in $(nodes); do [ "$h" = "$ex" ] && continue; c=$(grep -ac -- "$m" "$OUT/${tag}_$h.txt" 2>/dev/null); s=$((s + ${c:-0})); done; echo "$s"
}
wait_count() { # <tag> <mark> <want> <bound_s> [exclude]
    local tag="$1" m="$2" want="$3" end=$((SECONDS + $4)) ex="${5:-}" c=0
    while [ $SECONDS -lt $end ]; do sweep "$tag"; c=$(count "$tag" "$m" "$ex"); [ "$c" -ge "$want" ] && break; sleep 3; done; echo "$c"
}
knob() { fleet_do knob "echo $2 > /sys/module/mxfs/parameters/$1 && cat /sys/module/mxfs/parameters/$1"; }
disarm() { fleet_do disarm "for k in dbg_settle_inval_after_mint dbg_settle_double_consume dbg_settle_pause_ms dbg_probe_hang_ms dbg_depart_late_token_ms dbg_depart_inject dbg_retire_hang_ms dbg_depart_crash_cut; do echo 0 > /sys/module/mxfs/parameters/\$k 2>/dev/null; done; echo ok"; }
# sess462 (D-0522): the chain-86 workerhang victims PANICKED inside the
# post-hang remount and the only trace was on the libvirt serial console —
# the ssh never returned and dmesg died with the guest.  Mark the victim's
# serial log before a risky step and count kernel-fault lines written AFTER
# the mark; the harness itself must never block on a dead guest, so every
# remount ssh below is bounded.
SERIAL_DIR=/var/log/libvirt/qemu
serial_mark() { sudo -n wc -l "$SERIAL_DIR/$1-serial.log" 2>/dev/null | awk '{print $1}' | tr -dc '0-9'; }
serial_faults() { # <node> <mark-line> -> count of fault lines after the mark (persisted)
    local n=$1 m=${2:-0}
    sudo -n tail -n +$(( m + 1 )) "$SERIAL_DIR/$n-serial.log" 2>/dev/null > "$OUT/serial_${n}_after.txt"
    grep -acE 'BUG:|Oops|Kernel panic|KASAN|general protection|refcount_t: (underflow|use-after-free|saturated)|UBSAN' "$OUT/serial_${n}_after.txt"
}

# every node starts this arm with an empty ring: the sweeps below read whole dmesg
fleet_do clear "dmesg --clear; echo cleared"
disarm

case "$ARM" in
plain|inval|double)
    case "$ARM" in
    inval)  knob dbg_settle_inval_after_mint 1 ;;
    double) knob dbg_settle_double_consume 1 ;;
    esac
    T0=$(date +%s)
    "$SSH" "$VICTIM" "timeout 60 umount $MNT; echo UMOUNT_RC=\$?; sleep 1; dmesg" > "$OUT/victim_umount.log" 2>&1
    say "victim umount rc=$(sed -n 's/^UMOUNT_RC=//p' "$OUT/victim_umount.log") wall=$(( $(date +%s) - T0 )) s released=$(grep -ac 'P304-RETIRE-PENDING-RELEASED' "$OUT/victim_umount.log") unreg_incomplete=$(grep -ac 'P301-DEPARTURE-INCOMPLETE' "$OUT/victim_umount.log")"
    done_n=$(wait_count settle 'P304-RETIRE-COMPLETED-BY-PEER' 1 60 "$VICTIM")
    T_SETTLE=$(( $(date +%s) - T0 ))
    worker=$(count settle 'P304-RETIRE-WORKER slot=.*result=EMPTY' "$VICTIM")
    absent=$(count settle 'P-PR-SETTLE-ABSENT' "$VICTIM")
    unheld=$(count settle 'P-PR-SETTLE-UNHELD' "$VICTIM")
    refused=$(count settle 'P-PR-PROOF-REFUSED' "$VICTIM")
    refused_inval=$(count settle 'P-PR-PROOF-REFUSED.*why=invalidated-since-mint' "$VICTIM")
    dbl_ok=$(count settle 'P-DBG-SETTLE-DOUBLE-CONSUME second consume.*refused as required' "$VICTIM")
    dbl_bad=$(count settle 'P-DBG-SETTLE-DOUBLE-CONSUME second consume.*ACCEPTED' "$VICTIM")
    nocaw=$(count settle 'P304-CAS-NOCAW' "$VICTIM")
    say "settle: COMPLETED-BY-PEER=$done_n after ${T_SETTLE}s worker_empty=$worker settle_absent=$absent unheld=$unheld proof_refused=$refused (inval=$refused_inval) double_ok=$dbl_ok double_bad=$dbl_bad nocaw=$nocaw"
    [ "$done_n" -eq 1 ] || fail "the released record must be published EMPTY exactly once (got $done_n)"
    [ "$worker" -ge 1 ] || fail "no peer's retire settle WORKER published it (result=EMPTY)"
    [ "$absent" -ge 1 ] || fail "no P-PR-SETTLE-ABSENT proof line"
    [ "$unheld" -eq 0 ] || fail "settle-absent ran without the departure mutex"
    [ "$nocaw" -eq 0 ] || fail "a CAS reported unsupported"
    [ "$dbl_bad" -eq 0 ] || fail "a proof token was consumed TWICE"
    case "$ARM" in
    plain)  [ "$refused" -eq 0 ] || fail "a proof was refused in the plain arm ($refused)" ;;
    inval)  [ "$refused_inval" -ge 1 ] || fail "the invalidated token was not refused (P-PR-PROOF-REFUSED why=invalidated-since-mint)"
            [ "$(count settle 'P-DBG-SETTLE-INVAL-AFTER-MINT' "$VICTIM")" -ge 1 ] || fail "the injector never fired" ;;
    double) [ "$dbl_ok" -ge 1 ] || fail "the second consume was not exercised/refused"
            [ "$(count settle 'P-DBG-SETTLE-DOUBLE-CONSUME:' "$VICTIM")" -ge 1 ] || fail "the injector never fired" ;;
    esac
    ;;
probehang)
    T0=$(date +%s)
    "$SSH" "$VICTIM" "echo 15000 > /sys/module/mxfs/parameters/dbg_probe_hang_ms; sleep 0.5; timeout 60 umount $MNT; echo UMOUNT_RC=\$?; sleep 1; dmesg" > "$OUT/victim_umount.log" 2>&1
    T_UM=$(( $(date +%s) - T0 ))
    stuck=$(grep -ac 'P-PR-PROBE-STUCK' "$OUT/victim_umount.log")
    quar=$(grep -ac 'P304-DEPARTURE-QUARANTINED' "$OUT/victim_umount.log")
    retained=$(grep -ac 'P302-PR-KEY-RETAINED-FENCE-TARGET' "$OUT/victim_umount.log")
    released=$(grep -ac 'P304-RETIRE-PENDING-RELEASED' "$OUT/victim_umount.log")
    say "victim umount rc=$(sed -n 's/^UMOUNT_RC=//p' "$OUT/victim_umount.log") wall=${T_UM}s probe_stuck=$stuck quarantined=$quar key_retained=$retained release_stamp=$released"
    [ "$stuck" -ge 1 ] || fail "the bounded join did not report the parked probe thread"
    [ "$quar" -ge 1 ] || fail "the departure was not marked quarantined"
    [ "$retained" -ge 1 ] || fail "the PR key was not retained as the fence target"
    [ "$released" -eq 0 ] || fail "a quarantined departure must not release its slot"
    [ "$T_UM" -ge 5 ] && [ "$T_UM" -lt 15 ] || fail "umount wall ${T_UM}s is outside the 5 s join bound (expected 5..14 s)"
    # immediate remount: refused while the thread is parked
    "$SSH" "$VICTIM" "dmesg --clear; timeout 60 mount -t mxfs $DEV $MNT; echo MOUNT_RC=\$?; dmesg" > "$OUT/remount_refused.log" 2>&1
    say "immediate remount rc=$(sed -n 's/^MOUNT_RC=//p' "$OUT/remount_refused.log") quarantine_refused=$(grep -ac 'P-PR-QUARANTINE-REFUSED' "$OUT/remount_refused.log")"
    [ "$(sed -n 's/^MOUNT_RC=//p' "$OUT/remount_refused.log")" != 0 ] || fail "a remount was ADMITTED while a quarantined thread was parked"
    grep -aq 'P-PR-QUARANTINE-REFUSED' "$OUT/remount_refused.log" || fail "the refusal was not the quarantine (P-PR-QUARANTINE-REFUSED)"
    # after the hang: reaped; the dirty predecessor record blocks the same-boot
    # remount until the peers fence and recover it
    while [ $(( $(date +%s) - T0 )) -lt 17 ]; do sleep 1; done
    "$SSH" "$VICTIM" "dmesg --clear; timeout 60 mount -t mxfs $DEV $MNT; echo MOUNT_RC=\$?; umount $MNT 2>/dev/null; dmesg" > "$OUT/remount_reaped.log" 2>&1
    say "post-hang remount rc=$(sed -n 's/^MOUNT_RC=//p' "$OUT/remount_reaped.log") reaped=$(grep -ac 'P-PR-PROBE-REAPED' "$OUT/remount_reaped.log") quarantine_refused=$(grep -ac 'P-PR-QUARANTINE-REFUSED' "$OUT/remount_reaped.log") dirty_pred=$(grep -ac 'P305-PR-SAME-BOOT-DIRTY-PREDECESSOR\|P305-PR-PREDECESSOR-KEY-PRESENT' "$OUT/remount_reaped.log")"
    grep -aq 'P-PR-PROBE-REAPED' "$OUT/remount_reaped.log" || fail "the exited probe thread was not reaped at the next mount"
    grep -aq 'P-PR-QUARANTINE-REFUSED' "$OUT/remount_reaped.log" && fail "still refused as quarantined after the thread exited"
    # the peers must fence the retained key and recover the dirty slot
    rdone=$(wait_count recov 'P163-RECOVERY-COMPLETE' 1 120 "$VICTIM")
    say "peers: RECOVERY-COMPLETE=$rdone FENCE-CERTIFIED=$(count recov 'P236-FENCE-CERTIFIED' "$VICTIM") after $(( $(date +%s) - T0 ))s"
    [ "$rdone" -ge 1 ] || fail "the quarantined (dirty) departure was never fenced and recovered by the peers"
    ;;
workerhang)
    # sess460 (review #5 condition 2): the RETIRE SETTLE WORKER, not the probe
    # thread, ignores its stop for 15 s (dbg_retire_hang_ms, one-shot,
    # consumed at the worker's loop top — it holds no lock while parked).
    T0=$(date +%s)
    "$SSH" "$VICTIM" "echo 15000 > /sys/module/mxfs/parameters/dbg_retire_hang_ms; sleep 0.5; timeout 60 umount $MNT; echo UMOUNT_RC=\$?; sleep 1; dmesg" > "$OUT/victim_umount.log" 2>&1
    T_UM=$(( $(date +%s) - T0 ))
    fired=$(grep -ac 'P-DBG-RETIRE-HANG' "$OUT/victim_umount.log")
    stuck=$(grep -ac 'P304-RETIRE-WORKER-STUCK' "$OUT/victim_umount.log")
    quar=$(grep -ac 'P304-DEPARTURE-QUARANTINED' "$OUT/victim_umount.log")
    retained=$(grep -ac 'P302-PR-KEY-RETAINED-FENCE-TARGET' "$OUT/victim_umount.log")
    released=$(grep -ac 'P304-RETIRE-PENDING-RELEASED' "$OUT/victim_umount.log")
    unreg=$(grep -ac 'P301-DEPARTURE-INCOMPLETE\|P303-' "$OUT/victim_umount.log")
    oops=$(grep -acE 'BUG:|Oops|KASAN|general protection|refcount_t: (underflow|use-after-free|saturated)|UBSAN' "$OUT/victim_umount.log")
    say "victim umount rc=$(sed -n 's/^UMOUNT_RC=//p' "$OUT/victim_umount.log") wall=${T_UM}s hang_fired=$fired worker_stuck=$stuck quarantined=$quar key_retained=$retained release_stamp=$released unreg_lines=$unreg oops=$oops"
    [ "$fired" -eq 1 ] || fail "the worker hang injector did not fire exactly once ($fired)"
    # sess462 (D-0522): STUCK exactly once — twice means the second stop
    # re-quarantined the context (self-looped list, panic at the next mount)
    [ "$stuck" -eq 1 ] || fail "P304-RETIRE-WORKER-STUCK must fire exactly once (got $stuck; 2 = D-0522 double quarantine)"
    again=$(grep -ac 'P304-RETIRE-QUARANTINE-AGAIN' "$OUT/victim_umount.log"); dup=$(grep -ac 'P304-RETIRE-QUARANTINE-DUP' "$OUT/victim_umount.log")
    say "second stop: quarantine_again=$again dup_refused=$dup"
    [ "$again" -ge 1 ] || fail "the second retire-worker stop did not short-circuit (no P304-RETIRE-QUARANTINE-AGAIN)"
    [ "$quar" -ge 1 ] || fail "the departure was not marked quarantined"
    [ "$retained" -ge 1 ] || fail "the PR key was not retained as the fence target"
    [ "$released" -eq 0 ] || fail "a quarantined departure must not release its slot"
    [ "$T_UM" -ge 5 ] && [ "$T_UM" -lt 15 ] || fail "umount wall ${T_UM}s is outside the 5 s join bound (expected 5..14 s)"
    [ "$oops" -eq 0 ] || fail "kernel fault report on the victim"
    "$SSH" "$VICTIM" "dmesg --clear; timeout 60 mount -t mxfs $DEV $MNT; echo MOUNT_RC=\$?; dmesg" > "$OUT/remount_refused.log" 2>&1
    say "immediate remount rc=$(sed -n 's/^MOUNT_RC=//p' "$OUT/remount_refused.log") quarantine_refused=$(grep -ac 'P-PR-QUARANTINE-REFUSED' "$OUT/remount_refused.log")"
    [ "$(sed -n 's/^MOUNT_RC=//p' "$OUT/remount_refused.log")" != 0 ] || fail "a remount was ADMITTED while the quarantined worker was parked"
    grep -aq 'P-PR-QUARANTINE-REFUSED' "$OUT/remount_refused.log" || fail "the refusal was not the quarantine (P-PR-QUARANTINE-REFUSED)"
    while [ $(( $(date +%s) - T0 )) -lt 17 ]; do sleep 1; done
    smark=$(serial_mark "$VICTIM")
    timeout 110 "$SSH" "$VICTIM" "dmesg --clear; timeout 60 mount -t mxfs $DEV $MNT; echo MOUNT_RC=\$?; timeout 30 umount $MNT 2>/dev/null; dmesg" > "$OUT/remount_reaped.log" 2>&1
    sfaults=$(serial_faults "$VICTIM" "$smark")
    say "post-hang remount rc=$(sed -n 's/^MOUNT_RC=//p' "$OUT/remount_reaped.log") reaped=$(grep -ac 'P304-RETIRE-WORKER-REAPED' "$OUT/remount_reaped.log") worker_exit=$(grep -ac 'P304-RETIRE-WORKER exiting' "$OUT/remount_reaped.log") quarantine_refused=$(grep -ac 'P-PR-QUARANTINE-REFUSED' "$OUT/remount_reaped.log") dirty_pred=$(grep -ac 'P305-PR-SAME-BOOT-DIRTY-PREDECESSOR\|P305-PR-PREDECESSOR-KEY-PRESENT' "$OUT/remount_reaped.log") serial_faults=$sfaults"
    [ "$sfaults" -eq 0 ] || fail "kernel fault on the victim's serial console during the post-hang remount (D-0522 shape; $OUT/serial_${VICTIM}_after.txt)"
    grep -aq '^MOUNT_RC=' "$OUT/remount_reaped.log" || fail "the post-hang remount never returned (ssh bound hit; the guest died or the mount wedged)"
    grep -aq 'P304-RETIRE-WORKER-REAPED' "$OUT/remount_reaped.log" || fail "the exited retire worker was not reaped at the next mount"
    grep -aq 'P-PR-QUARANTINE-REFUSED' "$OUT/remount_reaped.log" && fail "still refused as quarantined after the worker exited"
    rdone=$(wait_count recov 'P163-RECOVERY-COMPLETE' 1 120 "$VICTIM")
    say "peers: RECOVERY-COMPLETE=$rdone FENCE-CERTIFIED=$(count recov 'P236-FENCE-CERTIFIED' "$VICTIM") after $(( $(date +%s) - T0 ))s"
    [ "$rdone" -ge 1 ] || fail "the quarantined (dirty) departure was never fenced and recovered by the peers"
    ;;
workerhangheld)
    # sess460 (review #5 condition 2, the mutex-held shape): the victim's
    # worker is parked INSIDE a settle — proof minted, departure mutex held —
    # when the victim unmounts.  Requires a RETIRE_PENDING record to settle:
    # SETTLE_VICTIM2 (default test$((N-1))) unmounts cleanly first; every
    # peer pauses 30 s between mint and CAS (dbg_settle_pause_ms).  Measured,
    # not asserted: how long put_super waits on the departure mutex behind
    # its own quarantined worker (the late phase takes the mutex after the
    # bounded stop).  Asserted: STUCK + QUARANTINED, no release stamp, key
    # retained, victim-2's record published EMPTY exactly once fleet-wide,
    # no PROUT/settle unheld, no kernel fault, the victim fenced + recovered.
    V2=${SETTLE_VICTIM2:-test$((N-1))}
    [ "$V2" != "$VICTIM" ] || { say "INFRA: SETTLE_VICTIM2 must differ from the victim"; exit 2; }
    knob dbg_settle_pause_ms 30000
    T0=$(date +%s)
    "$SSH" "$V2" "timeout 60 umount $MNT; echo UMOUNT_RC=\$?" > "$OUT/victim2_umount.log" 2>&1
    say "victim2 $V2 umount rc=$(sed -n 's/^UMOUNT_RC=//p' "$OUT/victim2_umount.log") at +$(( $(date +%s) - T0 ))s"
    # wait until the victim's worker is parked in the pause (its own P-DBG-SETTLE-PAUSE)
    paused=0
    while [ $(( $(date +%s) - T0 )) -lt 25 ]; do
        timeout 15 "$SSH" "$VICTIM" "dmesg | grep -ac 'P-DBG-SETTLE-PAUSE'" > "$OUT/victim_pause_poll.txt" 2>/dev/null
        [ "$(tr -dc '0-9' < "$OUT/victim_pause_poll.txt")" -ge 1 ] 2>/dev/null && { paused=1; break; }
        sleep 1
    done
    T_PAUSE=$(( $(date +%s) - T0 ))
    say "victim worker paused in settle: $paused at +${T_PAUSE}s"
    [ "$paused" = 1 ] || fail "the victim's worker never reached the paused settle (record not picked up in 25 s)"
    T1=$(date +%s)
    "$SSH" "$VICTIM" "timeout 120 umount $MNT; echo UMOUNT_RC=\$?; sleep 1; dmesg" > "$OUT/victim_umount.log" 2>&1
    T_UM=$(( $(date +%s) - T1 ))
    stuck=$(grep -ac 'P304-RETIRE-WORKER-STUCK' "$OUT/victim_umount.log")
    quar=$(grep -ac 'P304-DEPARTURE-QUARANTINED' "$OUT/victim_umount.log")
    retained=$(grep -ac 'P302-PR-KEY-RETAINED-FENCE-TARGET' "$OUT/victim_umount.log")
    released=$(grep -ac 'P304-RETIRE-PENDING-RELEASED' "$OUT/victim_umount.log")
    wres=$(grep -a 'P304-RETIRE-WORKER slot=' "$OUT/victim_umount.log" | tail -1 | grep -oE 'result=[A-Za-z]+')
    unheld=$(grep -ac 'P-PR-SETTLE-UNHELD\|P-PR-DEPARTURE-UNHELD' "$OUT/victim_umount.log")
    oops=$(grep -acE 'BUG:|Oops|KASAN|general protection|refcount_t: (underflow|use-after-free|saturated)|UBSAN' "$OUT/victim_umount.log")
    say "victim umount rc=$(sed -n 's/^UMOUNT_RC=//p' "$OUT/victim_umount.log") wall=${T_UM}s (mutex held by the parked worker until ~$(( 30 - (T1 - T0) + T_PAUSE ))s after the pause began) worker_stuck=$stuck quarantined=$quar key_retained=$retained release_stamp=$released worker_result=${wres:-none} unheld=$unheld oops=$oops"
    [ "$stuck" -eq 1 ] || fail "P304-RETIRE-WORKER-STUCK must fire exactly once (got $stuck; 2 = D-0522 double quarantine)"
    again=$(grep -ac 'P304-RETIRE-QUARANTINE-AGAIN' "$OUT/victim_umount.log")
    say "second stop: quarantine_again=$again dup_refused=$(grep -ac 'P304-RETIRE-QUARANTINE-DUP' "$OUT/victim_umount.log")"
    [ "$again" -ge 1 ] || fail "the second retire-worker stop did not short-circuit (no P304-RETIRE-QUARANTINE-AGAIN)"
    [ "$quar" -ge 1 ] || fail "the departure was not marked quarantined"
    [ "$retained" -ge 1 ] || fail "the PR key was not retained as the fence target"
    [ "$released" -eq 0 ] || fail "a quarantined departure must not release its slot"
    [ "$unheld" -eq 0 ] || fail "a settle or PROUT ran without the departure mutex"
    [ "$oops" -eq 0 ] || fail "kernel fault report on the victim"
    while [ $(( $(date +%s) - T0 )) -lt 45 ]; do sleep 1; done
    sweep settle
    p_done=$(count settle 'P304-RETIRE-COMPLETED-BY-PEER' "$VICTIM"); v_done=$(grep -ac 'P304-RETIRE-COMPLETED-BY-PEER' "$OUT/victim_umount.log")
    p_pause=$(count settle 'P-DBG-SETTLE-PAUSE' "$VICTIM"); p_unheld=$(count settle 'P-PR-SETTLE-UNHELD' "$VICTIM"); p_nocaw=$(count settle 'P304-CAS-NOCAW' "$VICTIM")
    say "victim2 record: EMPTY publishes peers=$p_done victim=$v_done pause_fired_peers=$p_pause unheld=$p_unheld nocaw=$p_nocaw"
    [ $(( p_done + v_done )) -eq 1 ] || fail "victim2's record must be published EMPTY exactly once fleet-wide (peers=$p_done victim=$v_done)"
    [ "$p_nocaw" -eq 0 ] || fail "a CAS reported unsupported"
    rdone=$(wait_count recov 'P163-RECOVERY-COMPLETE' 1 130 "$VICTIM")
    say "peers: RECOVERY-COMPLETE=$rdone FENCE-CERTIFIED=$(count recov 'P236-FENCE-CERTIFIED' "$VICTIM") after $(( $(date +%s) - T0 ))s"
    [ "$rdone" -ge 1 ] || fail "the quarantined (dirty) departure was never fenced and recovered by the peers"
    disarm
    smark=$(serial_mark "$VICTIM")
    timeout 110 "$SSH" "$VICTIM" "dmesg --clear; timeout 60 mount -t mxfs $DEV $MNT; echo MOUNT_RC=\$?; timeout 30 umount $MNT 2>/dev/null; dmesg" > "$OUT/remount_reaped.log" 2>&1
    sfaults=$(serial_faults "$VICTIM" "$smark")
    say "victim remount after recovery rc=$(sed -n 's/^MOUNT_RC=//p' "$OUT/remount_reaped.log") reaped=$(grep -ac 'P304-RETIRE-WORKER-REAPED' "$OUT/remount_reaped.log") quarantine_refused=$(grep -ac 'P-PR-QUARANTINE-REFUSED' "$OUT/remount_reaped.log") serial_faults=$sfaults"
    [ "$sfaults" -eq 0 ] || fail "kernel fault on the victim's serial console during the remount (D-0522 shape; $OUT/serial_${VICTIM}_after.txt)"
    grep -aq '^MOUNT_RC=' "$OUT/remount_reaped.log" || fail "the remount never returned (ssh bound hit; the guest died or the mount wedged)"
    grep -aq 'P304-RETIRE-WORKER-REAPED' "$OUT/remount_reaped.log" || fail "the exited retire worker was not reaped at the next mount"
    grep -aq 'P-PR-QUARANTINE-REFUSED' "$OUT/remount_reaped.log" && fail "still refused as quarantined after the worker exited"
    timeout 100 "$SSH" "$V2" "timeout 60 mount -t mxfs $DEV $MNT; echo MOUNT_RC=\$?; timeout 30 umount $MNT 2>/dev/null" > "$OUT/victim2_remount.log" 2>&1
    say "victim2 remount rc=$(sed -n 's/^MOUNT_RC=//p' "$OUT/victim2_remount.log")"
    ;;
proutsettle)
    # sess460 (review #5 condition 5): a same-host LOCAL PR OUT arriving while
    # that host's worker is parked between proof mint and CAS.  Every peer
    # parks 70 s (dbg_settle_pause_ms) on the victim's RETIRE_PENDING record;
    # 3 s later SETTLE_VICTIM2 is virsh-destroyed, so after the 62 s stale
    # window each peer's fence issues a PREEMPT — a local PROUT that must
    # wait behind the parked settle (ordering A: exclusion).  Measured per
    # peer from the timestamps: P-PR-DEPARTURE-UNHELD op=preempt (the PROUT
    # asked for the mutex) < P-PR-SETTLE-ABSENT (the settle's CAS) <
    # P236-FENCE-CERTIFIED (the PROUT ran).  Ordering B (PROUT first, the
    # worker waits) is structurally the mutex: any worker that found it
    # taken logs '(waited for the departure mutex)'.  Asserted: the record is
    # published EMPTY exactly once; every fencing peer's PREEMPT ran after its
    # own settle CAS (or its worker waited); no settle/PROUT unheld; no
    # deadlock (fence certified + recovery complete for victim 2); heartbeat
    # stall lines on the peers reported.  Budget 70 + 62 + recovery 40 +
    # VM restart 60 + prep 40 ≈ 270 s → 330.
    V2=${SETTLE_VICTIM2:-test$((N-1))}
    [ "$V2" != "$VICTIM" ] || { say "INFRA: SETTLE_VICTIM2 must differ from the victim"; exit 2; }
    knob dbg_settle_pause_ms 70000
    T0=$(date +%s)
    "$SSH" "$VICTIM" "timeout 60 umount $MNT; echo UMOUNT_RC=\$?; sleep 1; dmesg" > "$OUT/victim_umount.log" 2>&1
    say "victim umount rc=$(sed -n 's/^UMOUNT_RC=//p' "$OUT/victim_umount.log") released=$(grep -ac 'P304-RETIRE-PENDING-RELEASED' "$OUT/victim_umount.log") at +$(( $(date +%s) - T0 ))s"
    sleep 3
    timeout 60 sudo virsh -c qemu:///system destroy "$V2" > "$OUT/destroy_v2.txt" 2>&1; echo "rc=$?" >> "$OUT/destroy_v2.txt"
    say "destroyed $V2 at +$(( $(date +%s) - T0 ))s: $(tr '\n' ' ' < "$OUT/destroy_v2.txt" | cut -c1-80)"
    fenced=$(wait_count fence 'P236-FENCE-CERTIFIED' 1 170 "$VICTIM")
    rdone=$(wait_count fence 'P163-RECOVERY-COMPLETE' 1 60 "$VICTIM")
    say "fence certified=$fenced recovery_complete=$rdone at +$(( $(date +%s) - T0 ))s"
    sweep fence
    p_done=$(count fence 'P304-RETIRE-COMPLETED-BY-PEER' "$VICTIM"); p_pause=$(count fence 'P-DBG-SETTLE-PAUSE' "$VICTIM")
    p_absent=$(count fence 'P-PR-SETTLE-ABSENT' "$VICTIM"); p_unheld=$(count fence 'P-PR-SETTLE-UNHELD' "$VICTIM")
    p_waited=$(count fence 'waited for the departure mutex' "$VICTIM"); p_preempt=$(count fence 'P-PR-DEPARTURE-UNHELD.*op=preempt' "$VICTIM")
    hbstall=$(count fence 'HB-STALL\|HB-SLOW\|HB-MONSLOW\|HBFALSE' "$VICTIM")
    # per-peer ordering from the dmesg timestamps (first of each line)
    ok=0; bad=0; nofence=0
    for h in $(nodes); do
        [ "$h" = "$VICTIM" ] && continue; [ "$h" = "$V2" ] && continue
        f="$OUT/fence_$h.txt"
        ts() { grep -a -- "$1" "$f" | head -1 | grep -oE '^\[ *[0-9]+\.[0-9]+' | tr -dc '0-9.'; }
        t_ask=$(ts 'P-PR-DEPARTURE-UNHELD.*op=preempt'); t_cas=$(ts 'P-PR-SETTLE-ABSENT'); t_fence=$(ts 'P236-FENCE-CERTIFIED'); waited=$(grep -ac 'waited for the departure mutex' "$f")
        if [ -z "$t_fence" ]; then nofence=$((nofence+1)); continue; fi
        if [ -n "$t_cas" ] && awk -v a="$t_cas" -v b="$t_fence" 'BEGIN{exit !(a<b)}'; then ok=$((ok+1)); echo "$h A: ask=${t_ask:-?} cas=$t_cas fence=$t_fence" >> "$OUT/ordering.txt"
        elif [ "${waited:-0}" -ge 1 ]; then ok=$((ok+1)); echo "$h B: worker waited; fence=$t_fence cas=${t_cas:-none}" >> "$OUT/ordering.txt"
        else bad=$((bad+1)); echo "$h ??: ask=${t_ask:-?} cas=${t_cas:-none} fence=$t_fence waited=$waited" >> "$OUT/ordering.txt"; fi
    done
    say "peers: paused=$p_pause settle_absent=$p_absent EMPTY_publishes=$p_done preempt_asks=$p_preempt worker_waited=$p_waited unheld=$p_unheld hb_stall_lines=$hbstall | fencing peers ordered A/B=$ok unordered=$bad no-fence=$nofence (see $OUT/ordering.txt)"
    [ "$p_pause" -ge 1 ] || fail "no peer reached the paused settle"
    [ "$p_done" -eq 1 ] || fail "the victim's record must be published EMPTY exactly once (got $p_done)"
    [ "$p_unheld" -eq 0 ] || fail "a settle ran without the departure mutex"
    [ "$fenced" -ge 1 ] || fail "victim 2 was never fenced (PROUT deadlocked behind the parked settle?)"
    [ "$rdone" -ge 1 ] || fail "victim 2 was never recovered"
    [ "$bad" -eq 0 ] || fail "$bad fencing peer(s) ran the PREEMPT neither after their settle CAS nor with a waiting worker"
    [ "$ok" -ge 1 ] || fail "no fencing peer exercised the PROUT-vs-settle interleaving"
    disarm
    timeout 60 sudo virsh -c qemu:///system start "$V2" > "$OUT/start_v2.txt" 2>&1
    T_UP0=$(date +%s); up=0
    while [ $(( $(date +%s) - T_UP0 )) -lt 120 ]; do timeout 8 "$SSH" "$V2" "uptime" >/dev/null 2>&1 && { up=1; break; }; sleep 3; done
    # sess468 (chain 86 proutsettle: 'victim 2 not readmitted', PREP_RC=127):
    # a fresh boot has no NFS /src — restore the export before prep_node
    # (depart_crash_cuts.sh sess462 fix); keep dmesg for the admission proof.
    if [ "$up" = 1 ]; then timeout 160 "$SSH" "$V2" "mountpoint -q /src || { mkdir -p /src; timeout 12 mount -t nfs 192.168.1.4:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp; echo NFS_RC=\$?; }; MXFS_DEV=$DEV timeout 120 bash /src/mxfs/tests/setup/prep_node.sh caw; echo PREP_RC=\$?; dmesg | tail -60" > "$OUT/v2_restore.log" 2>&1; grep -q NODE_PREP_OK "$OUT/v2_restore.log" || fail "victim 2 not readmitted"; else fail "victim 2 did not come back"; fi
    # sess468: chain 86's remount here failed rc=32 'already mounted or mount
    # point busy' (= mount(2) EBUSY) with nothing else captured — record the
    # mount table and the kernel's own reason this time.
    "$SSH" "$VICTIM" "grep -a ' $MNT ' /proc/mounts; timeout 60 mount -t mxfs $DEV $MNT; echo MOUNT_RC=\$?; dmesg | tail -40" > "$OUT/victim_remount.log" 2>&1
    say "victim remount rc=$(sed -n 's/^MOUNT_RC=//p' "$OUT/victim_remount.log") victim2 ssh=$up restored=$(grep -c NODE_PREP_OK "$OUT/v2_restore.log" 2>/dev/null)"
    ;;
slowrace)
    knob dbg_settle_pause_ms 8000
    T0=$(date +%s)
    "$SSH" "$VICTIM" "timeout 60 umount $MNT; echo UMOUNT_RC=\$?; sleep 3.5; timeout 90 mount -t mxfs $DEV $MNT; echo MOUNT_RC=\$?; sleep 1; dmesg" > "$OUT/victim_cycle.log" 2>&1
    T_CYC=$(( $(date +%s) - T0 ))
    um_rc=$(sed -n 's/^UMOUNT_RC=//p' "$OUT/victim_cycle.log"); m_rc=$(sed -n 's/^MOUNT_RC=//p' "$OUT/victim_cycle.log")
    v_released=$(grep -ac 'P304-RETIRE-PENDING-RELEASED' "$OUT/victim_cycle.log")
    v_own=$(grep -ac 'P305-RETIRE-SETTLED-OWN' "$OUT/victim_cycle.log")
    v_changed=$(grep -ac 'P305-RETIRE-OWN-CHANGED' "$OUT/victim_cycle.log")
    v_pause=$(grep -ac 'P-DBG-SETTLE-PAUSE' "$OUT/victim_cycle.log")
    v_waited=$(grep -ac 'waited for the departure mutex' "$OUT/victim_cycle.log")
    v_unheld=$(grep -ac 'P-PR-SETTLE-UNHELD\|P-PR-DEPARTURE-UNHELD' "$OUT/victim_cycle.log")
    say "victim cycle: umount rc=$um_rc mount rc=$m_rc wall=${T_CYC}s released=$v_released settled_own=$v_own own_changed=$v_changed pause_fired=$v_pause worker_waited=$v_waited unheld=$v_unheld"
    [ "$um_rc" = 0 ] || fail "victim umount rc=$um_rc"
    [ "$m_rc" = 0 ] || fail "same-boot remount refused (rc=$m_rc) while settlers raced"
    [ "$v_released" -ge 1 ] || fail "the clean unmount wrote no release stamp"
    [ "$v_unheld" -eq 0 ] || fail "a settle or PROUT ran without the departure mutex on the victim"
    # let every paused peer finish its CAS (2 s lap + bracket + 8 s pause
    # from the umount), then sweep
    while [ $(( $(date +%s) - T0 )) -lt 14 ]; do sleep 1; done
    sweep settle
    p_done=$(count settle 'P304-RETIRE-COMPLETED-BY-PEER' "$VICTIM")
    p_pause=$(count settle 'P-DBG-SETTLE-PAUSE' "$VICTIM")
    p_empty=$(count settle 'P304-RETIRE-WORKER slot=.*result=EMPTY' "$VICTIM")
    p_changed=$(count settle 'P304-RETIRE-WORKER slot=.*result=CHANGED' "$VICTIM")
    p_waiting=$(count settle 'P304-RETIRE-WORKER slot=.*result=WAITING' "$VICTIM")
    p_absent=$(count settle 'P-PR-SETTLE-ABSENT' "$VICTIM")
    p_lost=$(count settle 'P-PR-SETTLE-ABSENT.*CAS lost (record moved)' "$VICTIM")
    p_unheld=$(count settle 'P-PR-SETTLE-UNHELD' "$VICTIM")
    p_refused=$(count settle 'P-PR-PROOF-REFUSED' "$VICTIM")
    p_nocaw=$(count settle 'P304-CAS-NOCAW' "$VICTIM")
    total_empty=$(( p_done + v_own ))
    say "peers: COMPLETED-BY-PEER=$p_done pause_fired=$p_pause worker EMPTY=$p_empty CHANGED=$p_changed WAITING=$p_waiting settle_absent=$p_absent cas_lost=$p_lost proof_refused=$p_refused unheld=$p_unheld nocaw=$p_nocaw | EMPTY publishes total=$total_empty"
    [ "$total_empty" -eq 1 ] || fail "the record must be published EMPTY exactly once across victim+peers (got own=$v_own peer=$p_done)"
    [ "$p_done" -le 1 ] || fail "two peers published the same record EMPTY"
    [ "$p_pause" -ge 1 ] || fail "no peer reached the paused settle (peer pause_fired=$p_pause): the key-reuse race was not exercised"
    [ "$p_absent" -ge 1 ] || fail "no peer minted an absence proof (P-PR-SETTLE-ABSENT)"
    [ "$p_unheld" -eq 0 ] || fail "settle-absent ran without the departure mutex on a peer"
    [ "$p_nocaw" -eq 0 ] || fail "a CAS reported unsupported"
    if [ "$v_own" -eq 1 ]; then
        [ $(( p_changed + p_lost )) -ge 1 ] || fail "the victim settled its own record yet no paused peer lost the CAS (CHANGED/lost)"
    else
        [ "$p_done" -eq 1 ] || fail "neither the victim (own) nor exactly one peer published the record"
    fi
    ;;
latewait)
    T0=$(date +%s)
    "$SSH" "$VICTIM" "echo 6000 > /sys/module/mxfs/parameters/dbg_depart_late_token_ms; sleep 0.5; timeout 60 umount $MNT; echo UMOUNT_RC=\$?; sleep 1; dmesg" > "$OUT/victim_umount.log" 2>&1
    T_UM=$(( $(date +%s) - T0 ))
    armed=$(grep -ac 'P-DBG-DEPART-LATE-TOKEN armed' "$OUT/victim_umount.log")
    drain=$(grep -ac 'P304-RETIRE-DRAIN at=put_super inflight=1' "$OUT/victim_umount.log")
    stall=$(grep -ac 'P304-RETIRE-DRAIN-STALL at=put_super inflight=1' "$OUT/victim_umount.log")
    drained=$(grep -ac 'P304-RETIRE-DRAINED at=put_super' "$OUT/victim_umount.log")
    abandoned=$(grep -ac 'P304-RETIRE-DRAIN-ABANDONED' "$OUT/victim_umount.log")
    late=$(grep -ac 'P-DBG-DEPART-LATE-TOKEN-RETIRED' "$OUT/victim_umount.log")
    late_zero=$(grep -ac 'P-DBG-DEPART-LATE-TOKEN-RETIRED.*inflight_now=0' "$OUT/victim_umount.log")
    quiesced=$(grep -ac 'P304-RETIRE-QUIESCED' "$OUT/victim_umount.log")
    notq=$(grep -ac 'P304-RETIRE-NOT-QUIESCED' "$OUT/victim_umount.log")
    released=$(grep -ac 'P304-RETIRE-PENDING-RELEASED' "$OUT/victim_umount.log")
    retained=$(grep -ac 'P302-PR-KEY-RETAINED-FENCE-TARGET' "$OUT/victim_umount.log")
    # order: the late retire must be logged BEFORE the quiescence assertion
    l_late=$(grep -an 'P-DBG-DEPART-LATE-TOKEN-RETIRED' "$OUT/victim_umount.log" | head -1 | cut -d: -f1)
    l_q=$(grep -an 'P304-RETIRE-QUIESCED\|P304-RETIRE-NOT-QUIESCED' "$OUT/victim_umount.log" | head -1 | cut -d: -f1)
    oops=$(grep -acE 'BUG:|Oops|KASAN|general protection|refcount_t: (underflow|use-after-free|saturated)|UBSAN' "$OUT/victim_umount.log")
    say "victim umount rc=$(sed -n 's/^UMOUNT_RC=//p' "$OUT/victim_umount.log") wall=${T_UM}s armed=$armed drain=$drain stall_rounds=$stall drained=$drained abandoned=$abandoned late_retired=$late(inflight0=$late_zero) quiesced=$quiesced not_quiesced=$notq release_stamp=$released key_retained=$retained order(late_line=${l_late:-none} quiesce_line=${l_q:-none}) oops_lines=$oops"
    [ "$armed" -eq 1 ] || fail "the injector did not arm exactly once ($armed)"
    [ "$drain" -ge 1 ] || fail "the freeze did not see the outstanding token (P304-RETIRE-DRAIN inflight=1)"
    [ "$stall" -ge 2 ] && [ "$stall" -le 3 ] || fail "expected 2-3 STALL rounds of 2 s for a 6 s token (got $stall)"
    [ "$drained" -eq 1 ] || fail "the drain did not report DRAINED exactly once ($drained)"
    [ "$abandoned" -eq 0 ] || fail "the drain was ABANDONED (account corrupt?)"
    [ "$late" -eq 1 ] && [ "$late_zero" -eq 1 ] || fail "the late token did not retire exactly once to inflight 0 before umount returned ($late/$late_zero)"
    [ -n "$l_late" ] && [ -n "$l_q" ] && [ "$l_late" -lt "$l_q" ] || fail "the late retire was not logged before the quiescence assertion"
    [ "$quiesced" -eq 1 ] && [ "$notq" -eq 0 ] || fail "the departure was not asserted QUIESCED after the wait (quiesced=$quiesced not=$notq)"
    [ "$released" -ge 1 ] || fail "no release stamp after a drained departure"
    [ "$retained" -eq 0 ] || fail "the PR key was retained although the departure drained clean"
    [ "$T_UM" -ge 6 ] && [ "$T_UM" -lt 11 ] || fail "umount wall ${T_UM}s is outside the 6 s token wait (expected 6..10 s)"
    [ "$oops" -eq 0 ] || fail "kernel fault/refcount report on the victim"
    grep -aE 'BUG:|Oops|KASAN|general protection|refcount_t|UBSAN' "$OUT/victim_umount.log" | head -5
    # the clean departure is then settled EMPTY by a peer's worker, exactly once
    done_n=$(wait_count settle 'P304-RETIRE-COMPLETED-BY-PEER' 1 60 "$VICTIM")
    say "settle: COMPLETED-BY-PEER=$done_n after $(( $(date +%s) - T0 ))s unheld=$(count settle 'P-PR-SETTLE-UNHELD' "$VICTIM") nocaw=$(count settle 'P304-CAS-NOCAW' "$VICTIM")"
    [ "$done_n" -eq 1 ] || fail "the released record must be published EMPTY exactly once (got $done_n)"
    ;;
latecomp)
    T0=$(date +%s)
    "$SSH" "$VICTIM" "echo 6000 > /sys/module/mxfs/parameters/dbg_depart_late_token_ms; sleep 0.5; timeout 60 umount $MNT; echo UMOUNT_RC=\$?; sleep 1; dmesg" > "$OUT/victim_umount.log" 2>&1
    T_UM=$(( $(date +%s) - T0 ))
    armed=$(grep -ac 'P-DBG-DEPART-LATE-TOKEN armed' "$OUT/victim_umount.log")
    drain=$(grep -ac 'P304-RETIRE-DRAIN at=put_super inflight=1' "$OUT/victim_umount.log")
    dto=$(grep -ac 'P304-RETIRE-DRAIN-TIMEOUT at=put_super inflight=1' "$OUT/victim_umount.log")
    notq=$(grep -ac 'P304-RETIRE-NOT-QUIESCED at=put_super' "$OUT/victim_umount.log")
    quiesced=$(grep -ac 'P304-RETIRE-QUIESCED' "$OUT/victim_umount.log")
    released=$(grep -ac 'P304-RETIRE-PENDING-RELEASED' "$OUT/victim_umount.log")
    retained=$(grep -ac 'P302-PR-KEY-RETAINED-FENCE-TARGET' "$OUT/victim_umount.log")
    early=$(grep -ac 'P-DBG-DEPART-LATE-TOKEN-RETIRED' "$OUT/victim_umount.log")
    say "victim umount rc=$(sed -n 's/^UMOUNT_RC=//p' "$OUT/victim_umount.log") wall=${T_UM}s armed=$armed drain=$drain drain_timeout=$dto not_quiesced=$notq quiesced=$quiesced release_stamp=$released key_retained=$retained retired_before_return=$early"
    [ "$armed" -eq 1 ] || fail "the injector did not arm exactly once ($armed)"
    [ "$drain" -ge 1 ] || fail "the freeze did not see the outstanding token (P304-RETIRE-DRAIN inflight=1)"
    [ "$dto" -ge 1 ] || fail "the 2 s drain did not time out on the 6 s token"
    [ "$notq" -ge 1 ] || fail "the departure was not asserted NOT-QUIESCED"
    [ "$quiesced" -eq 0 ] || fail "P304-RETIRE-QUIESCED printed with a token outstanding"
    [ "$released" -eq 0 ] || fail "a release stamp was written with a token outstanding"
    [ "$retained" -ge 1 ] || fail "the PR key was not retained as the fence target"
    [ "$early" -eq 0 ] || fail "the late token retired before umount returned (injector delay not honoured)"
    [ "$T_UM" -ge 2 ] && [ "$T_UM" -lt 8 ] || fail "umount wall ${T_UM}s is outside the drain bound (expected 2..7 s: 2 s drain, not 6 s token)"
    # the late retire: after the token's 6 s, on live accounting, no oops
    while [ $(( $(date +%s) - T0 )) -lt 9 ]; do sleep 1; done
    "$SSH" "$VICTIM" "dmesg" > "$OUT/victim_late.log" 2>&1
    late=$(grep -ac 'P-DBG-DEPART-LATE-TOKEN-RETIRED' "$OUT/victim_late.log")
    late_zero=$(grep -ac 'P-DBG-DEPART-LATE-TOKEN-RETIRED.*inflight_now=0' "$OUT/victim_late.log")
    late_refs=$(grep -ao 'P-DBG-DEPART-LATE-TOKEN-RETIRED.*acct_refs=[0-9]*' "$OUT/victim_late.log" | sed -n 's/.*acct_refs=//p' | head -1)
    oops=$(grep -acE 'BUG:|Oops|KASAN|general protection|refcount_t: (underflow|use-after-free|saturated)|UBSAN' "$OUT/victim_late.log")
    say "late retire: retired=$late inflight_now_zero=$late_zero acct_refs_at_retire=${late_refs:-none} oops_lines=$oops"
    [ "$late" -eq 1 ] || fail "the late token did not retire exactly once ($late)"
    [ "$late_zero" -eq 1 ] || fail "the late retire did not bring inflight to 0 on live state"
    [ "$oops" -eq 0 ] || fail "kernel fault/refcount report on the victim after the late completion"
    grep -aE 'BUG:|Oops|KASAN|general protection|refcount_t|UBSAN' "$OUT/victim_late.log" | head -5
    # the peers must fence the retained key and recover the dirty slot
    rdone=$(wait_count recov 'P163-RECOVERY-COMPLETE' 1 120 "$VICTIM")
    say "peers: RECOVERY-COMPLETE=$rdone FENCE-CERTIFIED=$(count recov 'P236-FENCE-CERTIFIED' "$VICTIM") after $(( $(date +%s) - T0 ))s"
    [ "$rdone" -ge 1 ] || fail "the DIRTY (drain-timeout) departure was never fenced and recovered by the peers"
    ;;
untokened)
    # sess459 (review #5 STOP-SHIP, condition 8): one buffer completion that
    # never entered xfs_buf_submit_ex (no token, no rejected generation, not
    # an audited software completion) is injected at the departure freeze.
    # The gate must FAIL CLOSED on it: P304-IOCNT-UNTOKENED names it,
    # P304-RETIRE-NOT-QUIESCED (untokened=1), no release stamp, key retained,
    # the drain is NOT abandoned (the completion is unclassified, not an
    # under/overflow), umount returns promptly, no kernel fault, and the
    # peers fence the retained key and recover the dirty slot.
    T0=$(date +%s)
    "$SSH" "$VICTIM" "echo 1 > /sys/module/mxfs/parameters/dbg_depart_inject; sleep 0.5; timeout 60 umount $MNT; echo UMOUNT_RC=\$?; sleep 1; dmesg" > "$OUT/victim_umount.log" 2>&1
    T_UM=$(( $(date +%s) - T0 ))
    inject=$(grep -ac 'P-DBG-DEPART-UNTOKENED-INJECT' "$OUT/victim_umount.log")
    report=$(grep -ac 'P304-IOCNT-UNTOKENED' "$OUT/victim_umount.log")
    notq=$(grep -ac 'P304-RETIRE-NOT-QUIESCED at=put_super' "$OUT/victim_umount.log")
    notq_u=$(grep -ac 'P304-RETIRE-NOT-QUIESCED at=put_super.*untokened=1' "$OUT/victim_umount.log")
    quiesced=$(grep -ac 'P304-RETIRE-QUIESCED' "$OUT/victim_umount.log")
    released=$(grep -ac 'P304-RETIRE-PENDING-RELEASED' "$OUT/victim_umount.log")
    retained=$(grep -ac 'P302-PR-KEY-RETAINED-FENCE-TARGET' "$OUT/victim_umount.log")
    abandoned=$(grep -ac 'P304-RETIRE-DRAIN-ABANDONED' "$OUT/victim_umount.log")
    oops=$(grep -acE 'BUG:|Oops|KASAN|general protection|refcount_t: (underflow|use-after-free|saturated)|UBSAN' "$OUT/victim_umount.log")
    say "victim umount rc=$(sed -n 's/^UMOUNT_RC=//p' "$OUT/victim_umount.log") wall=${T_UM}s injected=$inject reported=$report not_quiesced=$notq(untokened=1:$notq_u) quiesced=$quiesced release_stamp=$released key_retained=$retained abandoned=$abandoned oops_lines=$oops"
    [ "$inject" -eq 1 ] || fail "the injector did not fire exactly once ($inject)"
    [ "$report" -ge 1 ] || fail "the unclassified completion was not reported (P304-IOCNT-UNTOKENED)"
    [ "$notq" -ge 1 ] && [ "$notq_u" -ge 1 ] || fail "the departure was not asserted NOT-QUIESCED with untokened=1 (notq=$notq untokened1=$notq_u)"
    [ "$quiesced" -eq 0 ] || fail "P304-RETIRE-QUIESCED printed with an unclassified completion on the account"
    [ "$released" -eq 0 ] || fail "a release stamp was written despite the unclassified completion"
    [ "$retained" -ge 1 ] || fail "the PR key was not retained as the fence target"
    [ "$abandoned" -eq 0 ] || fail "the drain was ABANDONED: an unclassified completion must not be treated as an under/overflow"
    [ "$T_UM" -lt 8 ] || fail "umount wall ${T_UM}s: the untokened refusal must not stall the unmount (expected < 8 s)"
    [ "$oops" -eq 0 ] || fail "kernel fault/refcount report on the victim"
    grep -aE 'BUG:|Oops|KASAN|general protection|refcount_t|UBSAN' "$OUT/victim_umount.log" | head -5
    grep -a 'P304-IOCNT-UNTOKENED' "$OUT/victim_umount.log" | head -2 | cut -c1-300
    # the peers must fence the retained key and recover the dirty slot
    rdone=$(wait_count recov 'P163-RECOVERY-COMPLETE' 1 120 "$VICTIM")
    say "peers: RECOVERY-COMPLETE=$rdone FENCE-CERTIFIED=$(count recov 'P236-FENCE-CERTIFIED' "$VICTIM") after $(( $(date +%s) - T0 ))s"
    [ "$rdone" -ge 1 ] || fail "the DIRTY (untokened) departure was never fenced and recovered by the peers"
    ;;
postteardown|orphantoken|orphanrejected|overflow|underflow)
    # sess459 (review #5 condition 1): the deterministic G3 accounting arms,
    # each one dbg_depart_inject=<n> on the victim, consumed by put_super at
    # the phase the arm needs (pal/linux/xfs_super.c).  Every arm must leave
    # the departure DIRTY: NOT-QUIESCED, no QUIESCED, no release stamp, PR key
    # retained, no kernel fault, umount prompt, peers fence + recover.
    case "$ARM" in
    postteardown)   inj=2 ;;   # submission after xfs_shutdown_devices: rejected at the take, FINAL assertion blocks
    orphantoken)    inj=3 ;;   # buffer freed holding a token (pre-freeze): ORPHAN, corrupt, drain ABANDONED after 1 round
    orphanrejected) inj=4 ;;   # buffer freed with a pending post-freeze rejection: ORPHAN, corrupt
    overflow)       inj=5 ;;   # 256 takes on one buffer: 255 admitted, the 256th OVERFLOW, corrupt
    underflow)      inj=6 ;;   # forced invalid decrement: account-level underflow, corrupt
    esac
    T0=$(date +%s)
    "$SSH" "$VICTIM" "echo $inj > /sys/module/mxfs/parameters/dbg_depart_inject; sleep 0.5; timeout 60 umount $MNT; echo UMOUNT_RC=\$?; sleep 1; dmesg" > "$OUT/victim_umount.log" 2>&1
    T_UM=$(( $(date +%s) - T0 ))
    L="$OUT/victim_umount.log"
    inject=$(grep -ac "P-DBG-DEPART-INJECT which=$inj " "$L")
    notq=$(grep -ac 'P304-RETIRE-NOT-QUIESCED at=put_super' "$L")
    quiesced=$(grep -ac 'P304-RETIRE-QUIESCED' "$L")
    released=$(grep -ac 'P304-RETIRE-PENDING-RELEASED' "$L")
    retained=$(grep -ac 'P302-PR-KEY-RETAINED-FENCE-TARGET' "$L")
    corrupt1=$(grep -ac 'P304-RETIRE-NOT-QUIESCED at=put_super.*corrupt=1' "$L")
    after1=$(grep -ac 'P304-RETIRE-NOT-QUIESCED at=put_super.*io_after_freeze=1' "$L")
    orphan=$(grep -ac 'P304-IOCNT-ORPHAN' "$L")
    overflow=$(grep -ac 'P304-IOCNT-OVERFLOW' "$L")
    abandoned=$(grep -ac 'P304-RETIRE-DRAIN-ABANDONED' "$L")
    rejected_line=$(grep -ac 'P304-RETIRE-IO-AFTER-FREEZE' "$L")
    untok=$(grep -ac 'P304-IOCNT-UNTOKENED' "$L")
    oops=$(grep -acE 'BUG:|Oops|KASAN|general protection|refcount_t: (underflow|use-after-free|saturated)|UBSAN' "$L")
    say "victim umount rc=$(sed -n 's/^UMOUNT_RC=//p' "$L") wall=${T_UM}s injected=$inject not_quiesced=$notq(corrupt1=$corrupt1 after1=$after1) quiesced=$quiesced release_stamp=$released key_retained=$retained orphan=$orphan overflow=$overflow abandoned=$abandoned io_after_freeze_line=$rejected_line untokened=$untok oops_lines=$oops"
    grep -a 'P-DBG-DEPART-\|P304-IOCNT-\|P304-RETIRE-NOT-QUIESCED\|P304-RETIRE-DRAIN' "$L" | sed 's/^.*kernel: //' | cut -c1-260 | head -8
    [ "$inject" -eq 1 ] || fail "the injector did not fire exactly once ($inject)"
    [ "$notq" -ge 1 ] || fail "the departure was not asserted NOT-QUIESCED"
    [ "$quiesced" -eq 0 ] || fail "P304-RETIRE-QUIESCED printed on a corrupted/violated account"
    [ "$released" -eq 0 ] || fail "a release stamp was written"
    [ "$retained" -ge 1 ] || fail "the PR key was not retained as the fence target"
    [ "$untok" -eq 0 ] || fail "an injected generation was misclassified as untokened ($untok)"
    [ "$T_UM" -lt 12 ] || fail "umount wall ${T_UM}s: the refusal must not stall the unmount (expected < 12 s)"
    [ "$oops" -eq 0 ] || fail "kernel fault/refcount report on the victim"
    grep -aE 'BUG:|Oops|KASAN|general protection|refcount_t|UBSAN' "$L" | head -5
    case "$ARM" in
    postteardown)
        [ "$rejected_line" -ge 1 ] || fail "the post-teardown submission was not rejected at the token take (P304-RETIRE-IO-AFTER-FREEZE)"
        [ "$after1" -ge 1 ] || fail "the FINAL assertion did not record io_after_freeze=1"
        [ "$abandoned" -eq 0 ] || fail "the drain was abandoned in the post-teardown arm (account should not be corrupt)"
        ;;
    orphantoken)
        [ "$(grep -ac 'P-DBG-DEPART-ORPHAN-TOKEN took=1' "$L")" -eq 1 ] || fail "the pre-freeze take did not admit the token"
        [ "$(grep -ac 'P304-IOCNT-ORPHAN.*tokens=1' "$L")" -ge 1 ] || fail "no P304-IOCNT-ORPHAN tokens=1 report"
        [ "$abandoned" -ge 1 ] || fail "the drain did not ABANDON after the orphan marked the account corrupt"
        [ "$corrupt1" -ge 1 ] || fail "NOT-QUIESCED did not carry corrupt=1"
        [ "$T_UM" -ge 2 ] || fail "umount wall ${T_UM}s: the abandon should take one 2 s drain round"
        ;;
    orphanrejected)
        [ "$(grep -ac 'P-DBG-DEPART-ORPHAN-REJECTED admitted=0' "$L")" -eq 1 ] || fail "the post-freeze take was not rejected"
        [ "$(grep -ac 'P304-IOCNT-ORPHAN.*rejected_pending=1' "$L")" -ge 1 ] || fail "no P304-IOCNT-ORPHAN rejected_pending=1 report"
        [ "$corrupt1" -ge 1 ] || fail "NOT-QUIESCED did not carry corrupt=1"
        [ "$after1" -ge 1 ] || fail "NOT-QUIESCED did not carry io_after_freeze=1"
        ;;
    overflow)
        [ "$(grep -ac 'P-DBG-DEPART-OVERFLOW admitted=255' "$L")" -eq 1 ] || fail "255 of 256 takes were not admitted as expected"
        [ "$overflow" -ge 1 ] || fail "the 256th take did not report P304-IOCNT-OVERFLOW"
        [ "$corrupt1" -ge 1 ] || fail "NOT-QUIESCED did not carry corrupt=1"
        [ "$orphan" -eq 0 ] || fail "the overflow buffer was released with generations outstanding (orphan)"
        ;;
    underflow)
        [ "$(grep -ac 'P-DBG-DEPART-UNDERFLOW took=1' "$L")" -eq 1 ] || fail "the pre-freeze take did not admit the token"
        [ "$corrupt1" -ge 1 ] || fail "NOT-QUIESCED did not carry corrupt=1 after the forced underflow"
        [ "$orphan" -eq 0 ] || fail "the underflow buffer was released with a generation outstanding (orphan)"
        ;;
    esac
    # the peers must fence the retained key and recover the dirty slot
    rdone=$(wait_count recov 'P163-RECOVERY-COMPLETE' 1 120 "$VICTIM")
    say "peers: RECOVERY-COMPLETE=$rdone FENCE-CERTIFIED=$(count recov 'P236-FENCE-CERTIFIED' "$VICTIM") after $(( $(date +%s) - T0 ))s"
    [ "$rdone" -ge 1 ] || fail "the DIRTY ($ARM) departure was never fenced and recovered by the peers"
    ;;
carryfreeze)
    # sess459 (review #5 condition 1, "retry carry"): dbg_depart_inject=7 on
    # the victim — pre-freeze one token is taken and the buffer marked as a
    # pending retry; the resubmit lands 3 s later, inside the drain.  The
    # carry take must REJECT it (P304-TOKEN-CARRY ... REJECTED after the
    # freeze), its completion retires the ONE token (drain DRAINED, inflight
    # never above 1, no orphan, no corrupt), and the FINAL assertion refuses:
    # NOT-QUIESCED io_after_freeze=1 rejected>=1 corrupt=0, no release stamp,
    # key retained, umount 3..10 s, peers fence + recover.
    T0=$(date +%s)
    "$SSH" "$VICTIM" "echo 7 > /sys/module/mxfs/parameters/dbg_depart_inject; sleep 0.5; timeout 60 umount $MNT; echo UMOUNT_RC=\$?; sleep 1; dmesg" > "$OUT/victim_umount.log" 2>&1
    T_UM=$(( $(date +%s) - T0 ))
    L="$OUT/victim_umount.log"
    inject=$(grep -ac 'P-DBG-DEPART-INJECT which=7 ' "$L")
    took=$(grep -ac 'P-DBG-DEPART-CARRY-FREEZE took=1 tokens=1' "$L")
    resub=$(grep -ac 'P-DBG-DEPART-CARRY-RESUBMIT.*tokens=1 carry=1' "$L")
    carry_rej=$(grep -ac 'P304-TOKEN-CARRY.*tokens=1 inflight=1 — REJECTED after the freeze' "$L")
    carry_kept=$(grep -ac 'P304-TOKEN-CARRY.*kept' "$L")
    drain=$(grep -ac 'P304-RETIRE-DRAIN at=put_super inflight=1' "$L")
    drained=$(grep -ac 'P304-RETIRE-DRAINED at=put_super' "$L")
    abandoned=$(grep -ac 'P304-RETIRE-DRAIN-ABANDONED' "$L")
    after_line=$(grep -ac 'P304-RETIRE-IO-AFTER-FREEZE' "$L")
    notq=$(grep -ac 'P304-RETIRE-NOT-QUIESCED at=put_super.*buf_io_inflight=0 .*io_after_freeze=1 .*corrupt=0' "$L")
    quiesced=$(grep -ac 'P304-RETIRE-QUIESCED' "$L")
    released=$(grep -ac 'P304-RETIRE-PENDING-RELEASED' "$L")
    retained=$(grep -ac 'P302-PR-KEY-RETAINED-FENCE-TARGET' "$L")
    orphan=$(grep -ac 'P304-IOCNT-ORPHAN' "$L")
    untok=$(grep -ac 'P304-IOCNT-UNTOKENED' "$L")
    oops=$(grep -acE 'BUG:|Oops|KASAN|general protection|refcount_t: (underflow|use-after-free|saturated)|UBSAN' "$L")
    say "victim umount rc=$(sed -n 's/^UMOUNT_RC=//p' "$L") wall=${T_UM}s injected=$inject took=$took resubmit=$resub carry_rejected=$carry_rej carry_kept=$carry_kept drain=$drain drained=$drained abandoned=$abandoned io_after_freeze_line=$after_line not_quiesced_clean=$notq quiesced=$quiesced release_stamp=$released key_retained=$retained orphan=$orphan untokened=$untok oops_lines=$oops"
    grep -a 'P-DBG-DEPART-\|P304-TOKEN-CARRY\|P304-RETIRE-DRAIN\|P304-RETIRE-NOT-QUIESCED\|P304-IOCNT' "$L" | sed 's/^.*kernel: //' | cut -c1-260 | head -10
    [ "$inject" -eq 1 ] && [ "$took" -eq 1 ] || fail "the injector did not take exactly one token ($inject/$took)"
    [ "$resub" -eq 1 ] || fail "the carried resubmit did not fire once with tokens=1 carry=1 ($resub)"
    [ "$carry_rej" -eq 1 ] || fail "the carry take was not REJECTED after the freeze with tokens=1 inflight=1 ($carry_rej)"
    [ "$carry_kept" -eq 0 ] || fail "a carry was admitted after the freeze"
    [ "$drain" -ge 1 ] && [ "$drained" -eq 1 ] || fail "the drain did not wait for the carried token and finish once (drain=$drain drained=$drained)"
    [ "$abandoned" -eq 0 ] || fail "the drain was abandoned (account corrupt?)"
    [ "$after_line" -ge 1 ] || fail "the rejected resubmit did not log P304-RETIRE-IO-AFTER-FREEZE"
    [ "$notq" -ge 1 ] || fail "NOT-QUIESCED with buf_io_inflight=0 io_after_freeze=1 corrupt=0 not asserted"
    [ "$quiesced" -eq 0 ] && [ "$released" -eq 0 ] || fail "the departure released despite the post-freeze rejection"
    [ "$retained" -ge 1 ] || fail "the PR key was not retained as the fence target"
    [ "$orphan" -eq 0 ] && [ "$untok" -eq 0 ] || fail "the carried token was misaccounted (orphan=$orphan untokened=$untok)"
    [ "$T_UM" -ge 3 ] && [ "$T_UM" -lt 11 ] || fail "umount wall ${T_UM}s outside the 3 s resubmit window (expected 3..10 s)"
    [ "$oops" -eq 0 ] || fail "kernel fault/refcount report on the victim"
    grep -aE 'BUG:|Oops|KASAN|general protection|refcount_t|UBSAN' "$L" | head -5
    rdone=$(wait_count recov 'P163-RECOVERY-COMPLETE' 1 120 "$VICTIM")
    say "peers: RECOVERY-COMPLETE=$rdone FENCE-CERTIFIED=$(count recov 'P236-FENCE-CERTIFIED' "$VICTIM") after $(( $(date +%s) - T0 ))s"
    [ "$rdone" -ge 1 ] || fail "the DIRTY (carryfreeze) departure was never fenced and recovered by the peers"
    ;;
carrylive)
    # sess459 (review #5 condition 1, "retry carry", the REAL path):
    # buf_inject_write_eio_live=1 on the victim fails its next live metadata
    # write at submit (-EIO, no bio); xfs_buf_ioend_handle_error resubmits it
    # with the generation's token carried (P304-TOKEN-CARRY ... kept), the
    # retry completes and retires that one token; the later clean unmount
    # must be QUIESCED with carried>=1 (release stamp, key retired) and a
    # peer settles the record EMPTY exactly once, as in the plain arm.
    T0=$(date +%s)
    "$SSH" "$VICTIM" "echo 1 > /sys/module/mxfs/parameters/buf_inject_write_eio_live; mkdir -p $MNT/carrylive.\$(hostname); for i in 1 2 3 4 5 6 7 8; do echo x > $MNT/carrylive.\$(hostname)/f\$i; done; sync; sleep 2; sync; sleep 1; echo REMAIN=\$(cat /sys/module/mxfs/parameters/buf_inject_write_eio_live); echo 0 > /sys/module/mxfs/parameters/buf_inject_write_eio_live; timeout 60 umount $MNT; echo UMOUNT_RC=\$?; sleep 1; dmesg" > "$OUT/victim_umount.log" 2>&1
    T_UM=$(( $(date +%s) - T0 ))
    L="$OUT/victim_umount.log"
    remain=$(sed -n 's/^REMAIN=//p' "$L")
    hit=$(grep -ac 'P227-FR-INJECT-WRITE-EIO.*foreign=0' "$L")
    carry_kept=$(grep -ac 'P304-TOKEN-CARRY.*tokens=1 inflight=[0-9]* — kept' "$L")
    carry_rej=$(grep -ac 'P304-TOKEN-CARRY.*REJECTED' "$L")
    quiesced=$(grep -ac 'P304-RETIRE-QUIESCED at=put_super' "$L")
    carried=$(grep -ao 'P304-RETIRE-QUIESCED at=put_super.*carried=[0-9]*' "$L" | sed -n 's/.*carried=//p' | head -1)
    notq=$(grep -ac 'P304-RETIRE-NOT-QUIESCED' "$L")
    released=$(grep -ac 'P304-RETIRE-PENDING-RELEASED' "$L")
    retained=$(grep -ac 'P302-PR-KEY-RETAINED-FENCE-TARGET' "$L")
    shutdown=$(grep -ac 'SHUTDOWN_META_IO_ERROR\|Filesystem has been shut down\|I/O Error Detected. Shutting down' "$L")
    orphan=$(grep -ac 'P304-IOCNT-ORPHAN' "$L")
    untok=$(grep -ac 'P304-IOCNT-UNTOKENED' "$L")
    oops=$(grep -acE 'BUG:|Oops|KASAN|general protection|refcount_t: (underflow|use-after-free|saturated)|UBSAN' "$L")
    say "victim: injector remaining=${remain:-?} eio_hit=$hit carry_kept=$carry_kept carry_rejected=$carry_rej umount rc=$(sed -n 's/^UMOUNT_RC=//p' "$L") wall=${T_UM}s quiesced=$quiesced carried=${carried:-none} not_quiesced=$notq release_stamp=$released key_retained=$retained shutdown_lines=$shutdown orphan=$orphan untokened=$untok oops_lines=$oops"
    grep -a 'P227-FR-INJECT-WRITE-EIO\|P304-TOKEN-CARRY\|P304-RETIRE-QUIESCED\|P304-RETIRE-NOT-QUIESCED\|P304-IOCNT' "$L" | sed 's/^.*kernel: //' | cut -c1-260 | head -8
    [ "$hit" -eq 1 ] || fail "the live write-EIO injector did not fire exactly once ($hit)"
    [ "$carry_kept" -ge 1 ] || fail "the resubmit did not carry the generation's token (no P304-TOKEN-CARRY ... kept)"
    [ "$carry_rej" -eq 0 ] || fail "a carry was rejected in the live arm"
    [ "$shutdown" -eq 0 ] || fail "the transient error shut the filesystem down"
    [ "$quiesced" -eq 1 ] && [ "$notq" -eq 0 ] || fail "the departure after the carried retry was not QUIESCED (quiesced=$quiesced not=$notq)"
    [ "${carried:-0}" -ge 1 ] || fail "QUIESCED did not report carried>=1 (${carried:-none})"
    [ "$released" -ge 1 ] && [ "$retained" -eq 0 ] || fail "the clean departure did not release / retained the key (released=$released retained=$retained)"
    [ "$orphan" -eq 0 ] && [ "$untok" -eq 0 ] || fail "the carried token was misaccounted (orphan=$orphan untokened=$untok)"
    [ "$oops" -eq 0 ] || fail "kernel fault/refcount report on the victim"
    grep -aE 'BUG:|Oops|KASAN|general protection|refcount_t|UBSAN' "$L" | head -5
    done_n=$(wait_count settle 'P304-RETIRE-COMPLETED-BY-PEER' 1 60 "$VICTIM")
    say "settle: COMPLETED-BY-PEER=$done_n after $(( $(date +%s) - T0 ))s"
    [ "$done_n" -eq 1 ] || fail "the released record must be published EMPTY exactly once (got $done_n)"
    ;;
*)  echo "unknown arm $ARM"; exit 2 ;;
esac

disarm
# restore the victim
"$SSH" "$VICTIM" "mount -t mxfs | grep -q mxfs && timeout 60 umount $MNT; dmesg --clear; MXFS_DEV=$DEV timeout 120 bash /src/mxfs/tests/setup/prep_node.sh caw; echo PREP_RC=\$?; dmesg | tail -60" > "$OUT/victim_restore.log" 2>&1
grep -q NODE_PREP_OK "$OUT/victim_restore.log" || fail "victim did not remount at the end (prep_node)"
sweep final
say "fleet at end: SETTLE-UNHELD=$(count final 'P-PR-SETTLE-UNHELD') DEPARTURE-UNLOCK-NOT-OWNER=$(count final 'P-PR-DEPARTURE-UNLOCK-NOT-OWNER') CAS-NOCAW=$(count final 'P304-CAS-NOCAW') WORKER-STUCK=$(count final 'P304-RETIRE-WORKER-STUCK')"
[ "$(count final 'P-PR-DEPARTURE-UNLOCK-NOT-OWNER')" -eq 0 ] || fail "a departure-mutex unlock by a non-owner"
echo "evidence: $OUT"
if [ "$fails" = 0 ]; then echo "=== settle_token_arms $ARM PASS @ $(date -u +%FT%TZ) ==="; exit 0; fi
echo "=== settle_token_arms $ARM FAIL fails=$fails @ $(date -u +%FT%TZ) ==="; exit 1
