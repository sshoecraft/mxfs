#!/bin/bash
# tests/d0965_stalled_record_mount_thread.sh <A> <B> [laps] [label]
#
# D-0965 negative case for the held-admission fix: the mount thread used to
# withdraw a clean RETIRE_PENDING record whose PR key is still PRESENT at
# once; since 0.87.11 it holds admission for the retirement grace, because
# the key may be a same-boot successor's fresh registration.  A record that
# is genuinely stalled (the departure released its slot, the late unregister
# failed, and the node never re-stamped WITHDRAWN — modelled by the one-shot
# knobs dbg_pr_unregister_fail + dbg_retire_skip_restamp on B) must still be
# withdrawn by a LONE remounting peer's mount thread once the grace expires,
# its key fenced, the slot recovered and the mount admitted.  Nobody else is
# mounted, so no monitor can do it for the mount thread.
#
# Per lap (both nodes start mounted):
#   1. A unmounts cleanly (its own record is same-boot: A settles it itself)
#   2. B arms the two knobs and unmounts: its record stays RETIRE_PENDING,
#      key PRESENT (P301-DEPARTURE-INCOMPLETE + P-DBG-RETIRE-SKIP-RESTAMP on
#      B, else the lap is vacuous)
#   3. A mounts alone under MOUNT_BOUND; from A's ring since the mark:
#        GRACE     P304-RETIRE-PRESENT-GRACE (admission held on B's record)
#        HELD      P-ADMIT-RETIRE-PENDING-HELD
#        EXPIRED   P304-RETIRE-EXPIRED-WITHDRAWN ... immediate=1 (the mount
#                  thread withdrew it after the grace)
#        CERT      P236-FENCE-CERTIFIED (B's key fenced)
#        ABORTED   'MXFS mount ABORTED'
#   4. B's key must be ABSENT from the PR table (chk_mxfs --pr-keys on A)
#   5. B remounts (knobs off, its key was preempted: it re-registers and
#      claims fresh), a file written on A reads on B
# The last lap is the CLEAN control (no knobs): A's mount must log neither
# GRACE nor EXPIRED and both mounts must succeed.
# RESULT PASS   every stalled lap: A rc=0, GRACE>=1, EXPIRED>=1 with
#               'after N ms' >= MIN_GRACE_MS (the mount-thread grace,
#               10000) and < 30000 (the monitor's), CERT>=1, ABORTED=0,
#               B's key absent, B rc=0, cross-read ok; control lap clean.
# Measured on the first build (mount-thread grace = the monitor's 30 s):
# the withdraw landed at 30151 ms, 29.3 s into the barrier's 30 s bound,
# and the fence + replay took 12 s more; the mount succeeded only because
# the retire worker's first sight preceded the barrier's first poll.
# RESULT FAIL   otherwise.  If A's mount aborts, B is mounted first (it
#               settles its own record) and then A, so the fleet is left
#               mounted.
# budget per stalled lap: umounts ~6 s + A mount <= MOUNT_BOUND (30 s grace
# + fence + clean-slice replay + purge, measured on the restamp crash arm at
# ~30 s past the grace: bound 90 s) + B mount <= 40 s + checks ~15 s: 150 s;
# control lap ~60 s.
set -u
cd /src/mxfs || exit 1
A=${1:?node A (the lone remounter)}; B=${2:?node B (the stalled departure)}
LAPS=${3:-2}; LABEL=${4:-d0965stall}
MOUNT_BOUND=${MOUNT_BOUND:-90}; UMOUNT_BOUND=${UMOUNT_BOUND:-100}
MIN_GRACE_MS=${MIN_GRACE_MS:-10000}
SSH=tools/mxfs_sshpass.sh
MNT=${MXFS_MNT:-/mnt/shared}
PARAMS=/sys/module/mxfs/parameters
CHK=/src/mxfs/tools/chk_mxfs
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_d0965stall_$LABEL
mkdir -p "$OUT"
# rs/rsx/measure/capture_require/mxfs_dev_resolve (tests/lib/rig.sh): every
# capture a verdict is counted from crosses the boundary in the parent shell
# first; a failed acquisition is an ABORT, never a count of zero.
. "$(dirname "$0")/lib/rig.sh"
MARK="D0965STALL-$LABEL-$$"
fails=0
# ck: tests/lib/rig.sh (sourced above) provides it, and its version ABORTs on an EMPTY value instead of printing a FAIL about MXFS
echo "=== d0965_stalled_record_mount_thread A=$A B=$B laps=$LAPS (last lap = clean control) mount_bound=$MOUNT_BOUND out=$OUT $(date -u +%FT%TZ) ==="
want=$(modinfo mxfs.ko | awk '/^srcversion:/{print $2}')
for n in $A $B; do
  nsv=$(rs 15 "$n" "cat /sys/module/mxfs/srcversion" | tr -dc 'A-F0-9')
  [ "$nsv" = "$want" ] || { echo "RESULT FAIL d0965stall: $n srcversion '$nsv' != tree '$want'"; exit 2; }
  rs 15 "$n" "grep -q ' $MNT mxfs ' /proc/mounts && echo mounted" | grep -q mounted || { echo "RESULT FAIL d0965stall: $MNT not mounted on $n at start"; exit 2; }
done
rs 15 "$B" "[ -f $PARAMS/dbg_pr_unregister_fail ] && [ -f $PARAMS/dbg_retire_skip_restamp ] && echo has" | grep -q has || { echo "RESULT FAIL d0965stall: $B build lacks the departure knobs"; exit 2; }
mxfs_dev_resolve "$A"
DEV=$MXFS_DEV_RESOLVED
echo "  INFO device=$DEV (from $A's live mount)"
disarm() { rs 15 "$B" "echo 0 > $PARAMS/dbg_pr_unregister_fail; echo 0 > $PARAMS/dbg_retire_skip_restamp" >/dev/null; }
trap disarm EXIT
cnt() { rs 20 "$1" "dmesg | sed -n \"/$2/,\\\$p\" | grep -ac '$3'" | tr -dc '0-9'; }
mnt() { # <node> <bound> -> "rc=N wall_ms=M"
  rs $(( $2 + 15 )) "$1" "T0=\$(date +%s%N); timeout $2 mount -t mxfs $DEV $MNT; R=\$?; echo rc=\$R wall_ms=\$(( (\$(date +%s%N) - T0) / 1000000 ))" | grep -ao 'rc=[0-9]* wall_ms=[0-9]*'
}
for L in $(seq 1 "$LAPS"); do
  tag=lap$L; MK="$MARK-$tag"; stalled=1; [ "$L" = "$LAPS" ] && stalled=0
  echo "--- $tag $([ $stalled = 1 ] && echo STALLED || echo CONTROL) ---"
  for n in $A $B; do rs 15 "$n" "echo '$MK' > /dev/kmsg" >/dev/null; done
  o=$(rs $((UMOUNT_BOUND+10)) "$A" "timeout $UMOUNT_BOUND umount $MNT; echo UMOUNT_RC=\$?")
  echo "$o" | grep -q 'UMOUNT_RC=0' || { echo "  ABORT $tag: umount on $A failed: $o"; fails=$((fails+1)); break; }
  if [ $stalled = 1 ]; then
    rs 15 "$B" "echo 1 > $PARAMS/dbg_pr_unregister_fail; echo 1 > $PARAMS/dbg_retire_skip_restamp" >/dev/null
  fi
  o=$(rs $((UMOUNT_BOUND+10)) "$B" "timeout $UMOUNT_BOUND umount $MNT; echo UMOUNT_RC=\$?")
  echo "$o" | grep -q 'UMOUNT_RC=0' || { echo "  ABORT $tag: umount on $B failed: $o"; fails=$((fails+1)); break; }
  disarm
  window_count_into p301 "$B" 20 "$MK" 'P301-DEPARTURE-INCOMPLETE' "p301"; window_count_into skip "$B" 20 "$MK" 'P-DBG-RETIRE-SKIP-RESTAMP' "skip"
  window_into "$OUT/rv_bkey_1.txt" "$B" 20 "$MK"; bkey=$(cat "$OUT/rv_bkey_1.txt" | grep -ao 'P301-DEPARTURE-INCOMPLETE PR key 0x[0-9a-f]*' | head -1 | grep -o '0x[0-9a-f]*')
  [ -n "$bkey" ] && bkey=$(printf '0x%016x' "$bkey")
  if [ $stalled = 1 ]; then
    ck "$tag: B's unregister failed under the knob (P301 >= 1)" "$([ "${p301:-0}" -ge 1 ] && echo yes || echo no)" "yes"
    ck "$tag: B skipped the WITHDRAWN re-stamp (P-DBG-RETIRE-SKIP-RESTAMP >= 1)" "$([ "${skip:-0}" -ge 1 ] && echo yes || echo no)" "yes"
    echo "  INFO $tag: B key=${bkey:-?}"
  else
    ck "$tag: (control) B's departure was clean (P301=0)" "${p301:-na}" "0"
  fi
  am=$(mnt "$A" "$MOUNT_BOUND"); arc=${am#rc=}; arc=${arc%% *}; awall=${am##*wall_ms=}
  window_count_into grace "$A" 20 "$MK" 'P304-RETIRE-PRESENT-GRACE' "grace"; window_count_into held "$A" 20 "$MK" 'P-ADMIT-RETIRE-PENDING-HELD' "held"
  window_count_into exp "$A" 20 "$MK" 'P304-RETIRE-EXPIRED-WITHDRAWN.*immediate=1' "exp"; window_count_into expany "$A" 20 "$MK" 'P304-RETIRE-EXPIRED-WITHDRAWN' "expany"
  window_count_into cert "$A" 20 "$MK" 'P236-FENCE-CERTIFIED' "cert"; window_count_into abrt "$A" 20 "$MK" 'MXFS mount ABORTED' "abrt"
  window_into "$OUT/rv_expms_2.txt" "$A" 20 "$MK"; expms=$(cat "$OUT/rv_expms_2.txt" | grep -a 'P304-RETIRE-EXPIRED-WITHDRAWN' | grep -ao 'after [0-9]* ms' | head -1 | grep -o '[0-9]*')
  for n in $A $B; do measure "$n" 40 "$OUT/${tag}_$n.txt" '^DMESG_END$' "the kernel log on $n from the lap marker" "dmesg | sed -n \"/$MK/,\\\$p\" | grep -a 'P30[1345]-\|P-ADMIT-RETIRE\|P-DBG-\|P163-\|P236-\|P-PR-FENCE\|P-PRKEY-\|MXFS mount\|mount REFUSED\|Filesystem has been shut down\|force_shutdown\|Corruption detected\|Metadata corruption\|Ending clean mount'; echo DMESG_END"; done
  # the same two captures by name, so the lap verdict below reads from a
  # path the boundary was crossed for
  capture_require "$OUT/${tag}_$A.txt" '^DMESG_END$' "the kernel log on $A"
  capture_require "$OUT/${tag}_$B.txt" '^DMESG_END$' "the kernel log on $B"
  echo "  RESULT $tag A_mount rc=${arc:-none} wall_ms=${awall:-none} GRACE=$grace HELD=$held EXPIRED_MOUNT_THREAD=$exp EXPIRED_ANY=$expany expired_after_ms=${expms:-none} CERT=$cert ABORTED=$abrt"
  if [ $stalled = 1 ]; then
    ck "$tag: A mounted alone beside the stalled record (rc=0)" "${arc:-none}" "0"
    ck "$tag: A held admission for the grace first (GRACE >= 1)" "$([ "${grace:-0}" -ge 1 ] && echo yes || echo no)" "yes"
    ck "$tag: A's mount thread withdrew the record after the grace (EXPIRED immediate=1 >= 1)" "$([ "${exp:-0}" -ge 1 ] && echo yes || echo no)" "yes"
    ck "$tag: the withdraw waited the mount-thread grace (after >= $MIN_GRACE_MS ms)" "$([ "${expms:-0}" -ge "$MIN_GRACE_MS" ] && echo yes || echo no)" "yes"
    ck "$tag: the withdraw did not wait the monitor's full grace (after < 30000 ms)" "$([ "${expms:-99999}" -lt 30000 ] && echo yes || echo no)" "yes"
    ck "$tag: B's key was fenced (P236-FENCE-CERTIFIED >= 1)" "$([ "${cert:-0}" -ge 1 ] && echo yes || echo no)" "yes"
    ck "$tag: no mount abort on A" "${abrt:-na}" "0"
    if [ -n "$bkey" ]; then
      # the key table is only a table when chk_mxfs completed (the sentinel
      # follows its success); an empty table from a failed probe is an ABORT
      measure "$A" 40 "$OUT/${tag}_keys_after.txt" '^KEYS_END$' "the PR key table via chk_mxfs on $A" "$CHK --pr-keys $DEV && echo KEYS_END"
      ck "$tag: B's key $bkey absent from the PR table after A's mount" "$(grep -aoE '^  0x[0-9a-f]+' "$OUT/${tag}_keys_after.txt" | tr -d ' ' | sort -u | grep -cx "$bkey")" "0"
    fi
  else
    ck "$tag: (control) A mounted (rc=0)" "${arc:-none}" "0"
    ck "$tag: (control) no grace hold on A (GRACE=0)" "${grace:-na}" "0"
    ck "$tag: (control) no withdraw on A (EXPIRED=0)" "${expany:-na}" "0"
    ck "$tag: (control) no mount abort on A" "${abrt:-na}" "0"
  fi
  if [ "${arc:-1}" != 0 ]; then
    # leave the fleet mounted: B settles its own record itself, then A
    bm=$(mnt "$B" 40); echo "  INFO $tag: recovery: B mount $bm"
    am2=$(mnt "$A" 40); echo "  INFO $tag: recovery: A mount $am2"
  else
    bm=$(mnt "$B" 40); brc=${bm#rc=}; brc=${brc%% *}
    ck "$tag: B remounted (rc=0)" "${brc:-none}" "0"
    window_count_into wc9 "$B" 20 "$MK" 'mount REFUSED' "tag: B s remount was not refused"
    ck "$tag: B's remount was not refused" "$wc9" "0"
    rs 20 "$A" "echo $tag-$$ > $MNT/.d0965stall_$LABEL && sync && echo w" | grep -q w || { echo "  FAIL $tag: write on $A"; fails=$((fails+1)); }
    measure "$B" 20 "$OUT/rv_rv1_1.txt" '^READ_RC=[0-9]+$' "rv1 on $B" "cat $MNT/.d0965stall_$LABEL; printf '\nREAD_RC=%s\n' \$?"; rv1=$(grep -av '^READ_RC=' "$OUT/rv_rv1_1.txt" | tr -dc 'a-z0-9-')
    ck "$tag: $B reads $A's write" "$rv1" "$tag-$$"
  fi
  for n in $A $B; do rs 15 "$n" "grep -q ' $MNT mxfs ' /proc/mounts && echo mounted" | grep -q mounted || { echo "  FAIL $tag: $n not mounted at lap end"; fails=$((fails+1)); }; done
  ck "$tag: no shutdown/corruption lines" "$(cat "$OUT/${tag}_$A.txt" "$OUT/${tag}_$B.txt" | grep -ac 'Filesystem has been shut down\|force_shutdown\|Corruption detected\|Metadata corruption')" "0"
done
rs 20 "$A" "rm -f $MNT/.d0965stall_$LABEL" >/dev/null
echo "  INFO laps=$LAPS fails=$fails evidence=$OUT"
[ "$fails" = 0 ] || { echo "RESULT FAIL d0965stall: fails=$fails out=$OUT"; exit 1; }
echo "RESULT PASS d0965stall: $((LAPS-1)) stalled lap(s) withdrawn by the mount thread after the grace and 1 clean control out=$OUT"
exit 0
