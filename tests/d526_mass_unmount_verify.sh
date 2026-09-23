#!/bin/sh
# d526_mass_unmount_verify.sh — closing arm for
#   D-CLEAN-RELEASE-TREATED-AS-DEATH-PHANTOM-RECOVERY-526
#
# Trigger (sess343 measured): a 31-node PARALLEL mass unmount. Fast
# unmounters release their HB slots while slow unmounters' monitors are
# mid-count toward dead_threshold; pre-fix, released (FLAG_EMPTY) slots
# were declared dead ("no longer responding"), fenced, and latched
# P163-RECOVERY-PENDING forever on the lone survivor (phantom recovery
# livelock, sess343 evidence).
#
# The fix under test is the sess346 (#92 ruling items 3+4) clean-departure
# machinery — P163-CLEAN-DEPART-CONFIRM (dead-confirm finds the clean
# release stamp: retire tracking, no fence, no latch) and
# P163-CLEAN-DEPART-PEND (already-latched pending unlatched on FUA-confirmed
# EMPTY) — blessed by the sess413 design-consult ruling (ccmemory
# docs/rulings/d526-clean-departure-monitor-arm.md),
# plus the sess413 D-532 lease give-back (EMPTY now also implies the
# departing incarnation owned no recovery lease).
#
# PASS iff, on the lone survivor across the whole window:
#   - ZERO "no longer responding" (fire_dead) for any released slot
#   - every P163-RECOVERY-PENDING latched during the race is unlatched by a
#     P163-CLEAN-DEPART-PEND (none survive at the end)
#   - ZERO fence intents / PREEMPT issued for released slots
#   - ZERO foreign replay attempts
#   - survivor stays mounted + writable, no shutdown, no BUG/Oops
#   - the survivor then unmounts cleanly and chk_mxfs -v is clean
#     (SB lazy counters excepted, reported)
#
# the budget rule (derived): 31 parallel unmounts <=120s (post-#93 serialize fix,
# measured ~1-2s each; the bound covers a root-EX convoy) + HB expiry +
# clean-depart window 90s + sweeps 30s + survivor unmount 30s + chk 60s
# => ~330s. Caller bound 400s.
#
# Usage: tests/d526_mass_unmount_verify.sh <label> [survivor] [nodes]
# Env: D526_OUT (evidence dir, default tests/evidence/<ts>_d526)
set -u
LABEL=${1:?label}; SURV=${2:-test1}; NODES=${3:-32}
cd "$(dirname "$0")/.." || exit 2
SSH=tools/mxfs_sshpass.sh
# the device under test by identity, not by path: the LUN this rig declares
# (data/rigs.json), verified by its WWID on the node, and the node's live mxfs
# mount when it has one; MXFS_DEV names a candidate that must be that LUN.
# mxfs_dev_resolve (tests/lib/rig.sh) ABORTs on anything else, never defaults
. "$(dirname "$0")/lib/rig.sh"
mxfs_dev_resolve "$SURV"; DEV=$MXFS_DEV_RESOLVED
MNT=${MXFS_MNT:-/mnt/shared}
OUT=${D526_OUT:-tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_d526}
mkdir -p "$OUT"
t0=$(date +%s)
filt() { grep -av '^Unauthorized\|^Warning:\|^If you'; }
echo "=== d526_mass_unmount_verify label=$LABEL survivor=$SURV nodes=$NODES out=$OUT $(date -u +%FT%TZ) ==="

MARK="D526-$LABEL-$$-$(date -u +%s)"
timeout 20 $SSH "$SURV" "echo '$MARK' > /dev/kmsg" >/dev/null 2>&1

# the trigger: parallel unmount of every node except the survivor
for i in $(seq 1 "$NODES"); do
    [ "test$i" = "$SURV" ] && continue
    ( timeout 120 $SSH "test$i" "umount $MNT && echo UNMOUNT_OK || echo UNMOUNT_RC=\$?" \
        2>/dev/null | filt | tail -1 > "$OUT/um_test$i.txt"; echo $? > "$OUT/um_test$i.rc" ) &
done
wait
um_ok=$(grep -l UNMOUNT_OK "$OUT"/um_test*.txt 2>/dev/null | wc -l)
echo "mass unmount: $um_ok/$((NODES-1)) clean at +$(( $(date +%s) - t0 ))s ($(grep -L UNMOUNT_OK "$OUT"/um_test*.txt 2>/dev/null | tr '\n' ' '))"

# clean-departure window: dead_threshold 62s + confirm + unlatch margin
sleep 90

timeout 30 $SSH "$SURV" "dmesg | sed -n '/$MARK/,\$p'" 2>/dev/null | filt > "$OUT/survivor_dmesg.txt"
sv() { grep -ac -- "$1" "$OUT/survivor_dmesg.txt"; }
dead=$(sv 'no longer responding')
latched=$(sv 'P163-RECOVERY-PENDING')
unlatched=$(sv 'P163-CLEAN-DEPART-PEND')
confirm=$(sv 'P163-CLEAN-DEPART-CONFIRM')
fences=$(sv 'P236-FENCE-INTENT\|PREEMPT AND ABORT issued\|P238-FENCE-DONE')
replays=$(sv 'foreign replay of')
bug=$(sv 'BUG:\|Oops')
shut=$(sv 'Shutting down\|shut down due to log error')
echo "survivor: fire_dead=$dead pending_latched=$latched unlatched=$unlatched clean_confirm=$confirm fences=$fences replays=$replays shutdown=$shut bug=$bug"
echo "  first clean-depart: $(grep -a -m1 'P163-CLEAN-DEPART' "$OUT/survivor_dmesg.txt" | cut -c1-200)"

# survivor still healthy + writable
wr=$(timeout 30 $SSH "$SURV" "grep -c ' mxfs ' /proc/mounts; echo ok > $MNT/.d526_$$ && echo WRITE_OK; rm -f $MNT/.d526_$$" 2>/dev/null | filt | tr '\n' ' ')
echo "survivor mounted/writable: $wr"

# survivor unmounts cleanly; then the platter oracle
sum=$(timeout 90 $SSH "$SURV" "umount $MNT && echo SURV_UNMOUNT_OK || echo SURV_UNMOUNT_RC=\$?" 2>/dev/null | filt | tail -1)
echo "survivor unmount: $sum"
timeout 120 tools/chk_mxfs -v "$DEV" > "$OUT/chk.txt" 2>&1; chkrc=$?
chk_err=$(grep -c "ERROR" "$OUT/chk.txt")
chk_sb=$(grep -c "SB lazy\|icount\|ifree" "$OUT/chk.txt")
echo "chk rc=$chkrc errors=$chk_err (SB-lazy-related lines: $chk_sb)"

fail=0
[ "$um_ok" = $((NODES-1)) ] || { echo "FAIL: only $um_ok of $((NODES-1)) departers unmounted cleanly"; fail=1; }
[ "$dead" = 0 ] || { echo "FAIL: $dead 'no longer responding' declarations for cleanly released slots"; fail=1; }
[ "$latched" -le "$unlatched" ] || { echo "FAIL: $latched recovery-pending latches but only $unlatched clean-depart unlatches — phantom recovery survives"; fail=1; }
[ "$fences" = 0 ] || { echo "FAIL: $fences fence lines against cleanly departed nodes"; fail=1; }
[ "$replays" = 0 ] || { echo "FAIL: $replays foreign replay attempts on clean slices"; fail=1; }
[ "$shut" = 0 ] && [ "$bug" = 0 ] || { echo "FAIL: survivor shutdown=$shut bug=$bug"; fail=1; }
case "$wr" in *WRITE_OK*) ;; *) echo "FAIL: survivor not writable after the mass departure ($wr)"; fail=1;; esac
case "$sum" in *SURV_UNMOUNT_OK*) ;; *) echo "FAIL: survivor unmount failed ($sum)"; fail=1;; esac
[ "$chk_err" = 0 ] || { echo "FAIL: chk_mxfs errors=$chk_err after full clean departure (see $OUT/chk.txt)"; fail=1; }
if [ $fail = 0 ]; then echo "VERDICT PASS: $((NODES-1))-node mass departure produced zero false deaths, zero fences, zero phantom recoveries (clean_confirm=$confirm unlatched=$unlatched)"; else echo "VERDICT FAIL"; fi
echo "=== done label=$LABEL total=$(( $(date +%s) - t0 ))s out=$OUT ==="
exit $fail
