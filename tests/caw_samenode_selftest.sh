#!/bin/bash
# caw_samenode_selftest.sh [local] [peer] [arm]
#
#   local   node running the local arms            (default: test1)
#   peer    node holding EX on the shared key       (default: test2)
#   arm     collide | negative | all                (default: all)
#
# Driver for the in-kernel CAW same-node reconcile exerciser (0.56.0,
# dlm/v5_mount.c:mxfs_v5_dlm_caw_samenode_selftest, debugfs trigger
# /sys/kernel/debug/mxfs/<s_id>/caw_samenode_selftest, write "<mode> [ino]").
# defect-bar closure vehicle for D-SAMENODE-WAITER-CANCEL-COLLISION and its
# siblings (D-RECONCILE-SLOT-IDENTITY-UNCHECKED, D-RECONCILE-EXHAUSTION-SILENT,
# D-TRACK-PUBLISH-ORDERING): the give-up reconcile arm is never entered under
# a healthy board (sess111), so this forces it deterministically.
#
# Per arm: the PEER writes "1" (lock EX on the shared reserved key, hold 14 s,
# unlock) in the background; 2 s later the LOCAL node writes "2" (collide:
# two kernel threads acquire EX behind the peer, one is forced down the
# timeout give-up path by caw_inject_wait_expire; the survivor's holder bit
# must survive the owed pass), "3" (negative control: one attempt gives up
# alone; its bits must be CLEARED and a fresh acquire must succeed), "4"
# (collide_late, scenario B: hook B caw_inject_dow_pause_ms widens the
# give-up's plan->CAS gap and the second attempt joins inside it) or "5"
# (collide_owed, scenario C: K5 fails the give-up's own CAS so the obligation
# reaches the owed worker, hook C caw_inject_owed_pause_ms holds the worker
# while the second attempt joins after the give-up's finish).  The
# kernel side is the test; this script triggers it and checks the externally
# observable contract:
#   write(2) rc       count on PASS, -EREMOTEIO assertion, -ENOLCK no peer
#                     holder (harness sequencing fault, not an FS verdict),
#                     -ETIMEDOUT stuck attempt thread, -EBUSY concurrent
#   verdict           mxfs: P275-SAMENODE <PASS|FAIL> run= mode= ino= ...
#   peer              mxfs: P275-SAMENODE HOLDING ... then PASS mode=hold
#   knob              /sys/module/mxfs/parameters/caw_inject_wait_expire
#                     reads 0 after each local arm (consumed exactly once)
#   injection         mxfs: P272-INJECT-WAIT-EXPIRE >= 1 on the local node
#                     (the give-up really took the timeout path)
#   collide extras    guard=N or defer=N nonzero on the PASS line (the
#                     registry guard is what saved the bit); rc1/rc2 = one
#                     -110 and one 0
#   negative extras   guard=0 defer=0, hex=0 w=0 wex=0 gm=0
#   no faults         zero kernel BUG/Oops/Call Trace on either node
#
# budget: per arm = 2 s stagger + 14 s hold + <=8 s owed discharge + ssh
# ≈ 26 s; four arms + harvest ≈ 110 s.  Bound 150 s.
#
# Exit 0 PASS, 1 FAIL, 2 INFRA-FAIL (no debugfs file / no cluster / -ENOLCK).
set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd -- "$SCRIPT_DIR/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"
LOCAL=${1:-test1}
PEER=${2:-test2}
ARM=${3:-all}
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUT="$REPO/tests/evidence/${STAMP}_samenode"
mkdir -p "$OUT"
cd "$REPO" || exit 2
WANT_SV=$(modinfo "$REPO/mxfs.ko" 2>/dev/null | awk '/^srcversion/{print $2}')
FAILS=0
say() { echo "[samenode] $*"; }

# node-side trigger: marker -> write -> END marker -> marker-scoped dmesg.
NODE_TRIGGER='
set -u
MARK="$1"; MODE="$2"
DBG=$(ls /sys/kernel/debug/mxfs/*/caw_samenode_selftest 2>/dev/null | head -1)
[ -n "$DBG" ] || { echo "WRITE_RC=NO_DEBUGFS_FILE"; exit 0; }
KNOB=/sys/module/mxfs/parameters/caw_inject_wait_expire
echo "$MARK" > /dev/kmsg
e=$(mktemp)
printf "%s" "$MODE" > "$DBG" 2>"$e"; rc=$?
echo "$MARK-END" > /dev/kmsg
echo "WRITE_RC=$rc"
[ "$rc" -ne 0 ] && echo "WRITE_ERR=$(tr -d "\n" < "$e")"
echo "KNOB_AFTER=$(cat "$KNOB" 2>/dev/null)"
dmesg | awk -v m="$MARK" "index(\$0,m){f=1} f"
'

for n in "$LOCAL" "$PEER"; do
    # sess451: read the LOADED module's srcversion from sysfs.  `modinfo mxfs`
    # on a node finds nothing (mxfs.ko is insmod'ed from the NFS tree, never
    # installed), so the first precheck line was the debugfs path and chain 66
    # reported "runs srcversion /sys/kernel/debug/mxfs/dm-1/caw_samenode_selftest".
    sv=$(timeout 20 "$SSH" "$n" "cat /sys/module/mxfs/srcversion 2>/dev/null; ls /sys/kernel/debug/mxfs/*/caw_samenode_selftest 2>/dev/null | head -1" 2>/dev/null)
    echo "$sv" > "$OUT/precheck_$n.txt"
    if ! grep -q caw_samenode_selftest "$OUT/precheck_$n.txt"; then
        say "INFRA-FAIL: $n has no caw_samenode_selftest debugfs file (loaded: $(head -1 "$OUT/precheck_$n.txt"), tree: $WANT_SV)"
        exit 2
    fi
    if [ -n "$WANT_SV" ] && ! grep -q "$WANT_SV" "$OUT/precheck_$n.txt"; then
        say "INFRA-FAIL: $n runs srcversion $(head -1 "$OUT/precheck_$n.txt"), tree is $WANT_SV"
        exit 2
    fi
done

run_arm() { # <tag> <mode>
    local tag="$1" mode="$2" mark log_l log_p rc_l rc_p knob pass fail p272 faults
    mark="MXFS_SAMENODE_${tag}_${STAMP}"
    log_l="$OUT/${tag}_local.log"; log_p="$OUT/${tag}_peer.log"
    say "arm $tag: peer $PEER holds, local $LOCAL mode $mode"
    timeout 50 "$SSH" "$PEER" "bash -s -- '${mark}_PEER' 1" <<<"$NODE_TRIGGER" > "$log_p" 2>&1 &
    local pid=$!
    sleep 2
    timeout 70 "$SSH" "$LOCAL" "bash -s -- '${mark}_LOCAL' $mode" <<<"$NODE_TRIGGER" > "$log_l" 2>&1
    wait "$pid"
    rc_l=$(sed -n 's/^WRITE_RC=//p' "$log_l" | head -1)
    rc_p=$(sed -n 's/^WRITE_RC=//p' "$log_p" | head -1)
    knob=$(sed -n 's/^KNOB_AFTER=//p' "$log_l" | head -1)
    pass=$(grep -c "P275-SAMENODE PASS run=[0-9]* mode=$tag " "$log_l")
    fail=$(grep -c "P275-SAMENODE FAIL run=[0-9]* mode=$tag " "$log_l")
    p272=$(grep -c 'P272-INJECT-WAIT-EXPIRE' "$log_l")
    # sess467: one integer — `grep -c` over TWO files prints "file:count"
    # per file, which failed the -eq test below on every chain-95 arm as
    # "kernel fault lines=<file>:0" (a harness verdict, not a kernel fault).
    faults=$(cat "$log_l" "$log_p" | grep -ciE 'kernel BUG|BUG:|Oops|general protection|Call Trace')
    local peer_pass
    peer_pass=$(grep -c 'P275-SAMENODE PASS run=[0-9]* mode=hold ' "$log_p")
    echo "--- $tag: local_rc=$rc_l peer_rc=$rc_p pass=$pass fail=$fail peer_hold_pass=$peer_pass p272=$p272 knob_after=$knob faults=$faults ---"
    grep -h 'P275-SAMENODE' "$log_l" "$log_p" | sed 's/^/    /'
    if [ "$rc_l" = "NO_DEBUGFS_FILE" ] || grep -q 'WRITE_ERR=.*Interrupted\|No locks available' "$log_l"; then
        say "INFRA-FAIL at $tag: $(sed -n 's/^WRITE_ERR=//p' "$log_l")"; exit 2
    fi
    [ "$rc_l" = 0 ] || { say "FAIL $tag: local write rc=$rc_l ($(sed -n 's/^WRITE_ERR=//p' "$log_l"))"; FAILS=$((FAILS+1)); }
    [ "$pass" -ge 1 ] || { say "FAIL $tag: no P275-SAMENODE PASS mode=$tag line"; FAILS=$((FAILS+1)); }
    [ "$fail" -eq 0 ] || { say "FAIL $tag: P275-SAMENODE FAIL present"; FAILS=$((FAILS+1)); }
    [ "$peer_pass" -ge 1 ] || { say "FAIL $tag: peer hold arm did not PASS (rc=$rc_p)"; FAILS=$((FAILS+1)); }
    [ "$p272" -ge 1 ] || { say "FAIL $tag: no P272-INJECT-WAIT-EXPIRE — the give-up never took the timeout path (vacuous)"; FAILS=$((FAILS+1)); }
    [ "$knob" = 0 ] || { say "FAIL $tag: caw_inject_wait_expire=$knob after the arm (not consumed)"; FAILS=$((FAILS+1)); }
    [ "$faults" -eq 0 ] || { say "FAIL $tag: kernel fault lines=$faults"; FAILS=$((FAILS+1)); }
    if [ "$tag" != negative ]; then
        grep -q "P275-SAMENODE PASS run=[0-9]* mode=$tag .*rc1=\(-110 rc2=0\|0 rc2=-110\) hex=1 " "$log_l" || { say "FAIL $tag: PASS line lacks one -110 + one 0 with hex=1"; FAILS=$((FAILS+1)); }
        grep "P275-SAMENODE PASS run=[0-9]* mode=$tag " "$log_l" | grep -Eq 'guard=[1-9][0-9]*|defer=[1-9][0-9]*' || { say "FAIL $tag: neither guard nor defer hit — the registry did not save the bit"; FAILS=$((FAILS+1)); }
        if [ "$tag" = collide_late ]; then
            [ "$(grep -c 'P276-INJECT-DOW-PAUSE' "$log_l")" -ge 1 ] || { say "FAIL collide_late: hook B never fired (vacuous)"; FAILS=$((FAILS+1)); }
        elif [ "$tag" = collide_owed ]; then
            [ "$(grep -c 'P276-INJECT-OWED-PAUSE' "$log_l")" -ge 1 ] || { say "FAIL collide_owed: hook C never fired (vacuous)"; FAILS=$((FAILS+1)); }
        fi
    else
        # sess469: the PASS line grew a post_hex= field (sess467, the
        # post-unlock sample) between wex= and gm=; chain 99 laps 1-2 on
        # 0.64.4 printed 'hex=0 w=0 wex=0 post_hex=0 gm=0 guard=0 defer=0'
        # and this check called it a FAIL.  Accept the field, and require it
        # to be 0 too (the bit must stay clear after the give-up).
        grep -q "P275-SAMENODE PASS run=[0-9]* mode=negative .*rc1=-110 rc2=0 hex=0 w=0 wex=0 \(post_hex=0 \)\?gm=0 guard=0 defer=0 " "$log_l" || { say "FAIL negative: PASS line does not show cleared bits with zero guard/defer"; FAILS=$((FAILS+1)); }
    fi
}

case "$ARM" in
    collide)      run_arm collide 2 ;;
    negative)     run_arm negative 3 ;;
    collide_late) run_arm collide_late 4 ;;
    collide_owed) run_arm collide_owed 5 ;;
    all)          run_arm collide 2; run_arm negative 3
                  run_arm collide_late 4; run_arm collide_owed 5 ;;
    *) say "unknown arm $ARM"; exit 2 ;;
esac

if [ "$FAILS" = 0 ]; then
    echo "=== caw_samenode_selftest PASS ($ARM) — evidence $OUT ==="
    exit 0
fi
echo "=== caw_samenode_selftest FAIL fails=$FAILS ($ARM) — evidence $OUT ==="
exit 1
