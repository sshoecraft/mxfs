#!/bin/bash
# tests/d0965_remount_bracket_race.sh <A> <B> [laps] [label]
#
# D-TCP-REMOUNT-REFUSED-WHEN-A-PEERS-PROUT-LANDS-INSIDE-THE-OWN-KEY-PROOF-
# BRACKET-0965: a node remounting after a clean unmount in the same boot
# settles its own RETIRE_PENDING record by proving its registration in ONE
# PR bracket (READ KEYS A, READ RESERVATION, READ KEYS B).  A peer's REGISTER
# landing inside that bracket moves the PR generation, the bracket is
# INCOHERENT (no proof either way) and the settle path answered that with a
# mount refusal (P305-RETIRE-OWN-UNPROVEN rc=-71, 'TCP mount REFUSED (-16)').
#
# Deterministic shape of the chk_clean row's same-second remount of both
# nodes: both unmount (B first, then A, so both carry a same-boot record),
# A's READ KEYS is slowed by dbg_pr_read_keys_delay_ms=DELAY_MS so its own
# proof bracket spans >= 2 x DELAY_MS, A mounts in the background and B
# mounts BSTAGGER_S later, so B's REGISTER PROUT lands inside A's bracket.
# The module is not reloaded (the knob would reset), so the mounts are the
# plain remounts the row performs.
#
# Per lap, from A's kernel ring inside a kmsg mark:
#   INCOHERENT   P-PR-BRACKET-INCOHERENT count (the injected condition;
#                >= 1 required or the lap is INCONCLUSIVE)
#   UNPROVEN     P305-RETIRE-OWN-UNPROVEN count
#   REFUSED      'TCP mount REFUSED' count
#   SETTLED      P305-RETIRE-SETTLED count
#   REBRACKET    P-PR-OWN-PROOF-REBRACKET count (the fix's re-bracket)
# and from B's ring (variant 2: B's mount thread meets A's predecessor
# record while A's re-registered key is PRESENT):
#   B_GRACE      P304-RETIRE-PRESENT-GRACE (the fix: admission held)
#   B_HELD       P-ADMIT-RETIRE-PENDING-HELD
#   B_WITHDRAWN  P304-RETIRE-EXPIRED-WITHDRAWN (the defect: B withdrew and
#                fenced A's live registration)
#   A_SELFABSENT P303-FENCECAP-SELFABSENT on A (A's key was fenced away)
# and A's mount rc / wall, B's mount rc / wall.
# A lap is REACHED when INCOHERENT >= 1 (variant 1) or B_GRACE+B_WITHDRAWN
# >= 1 (variant 2); BSTAGGER_S=1 tends to produce variant 2, 2 variant 1.
# RESULT PASS   every reached lap: A's mount rc=0 inside MOUNT_BOUND,
#               B's mount rc=0, UNPROVEN=0, REFUSED=0, SETTLED >= 1,
#               B_WITHDRAWN=0, A_SELFABSENT=0, both nodes mounted, a file
#               written on one reads on the other, no shutdown / corruption
#               line.
# RESULT FAIL   any lap where A's mount was refused (the defect) or any
#               other check failed; A is remounted before the next lap so
#               the fleet is left mounted.
# RESULT INCONCLUSIVE  no lap produced an incoherent bracket on A.
# EXPECT=refuse (the control on a build without the fix): PASS when every
# lap with INCOHERENT >= 1 has UNPROVEN >= 1 and A's mount rc != 0.
# budget per lap: B umount (35-80 s measured on TCP while A stays mounted,
# D-A-CLEAN-UNMOUNT) + A umount ~5 s + A mount (2 x DELAY_MS + ~5 s) +
# B mount ~5 s + checks ~5 s; bound 150 s per lap at DELAY_MS=1500.
set -u
cd /src/mxfs || exit 1
A=${1:?node A (the one whose bracket is disturbed)}; B=${2:?node B}
LAPS=${3:-3}; LABEL=${4:-d0965}
DELAY_MS=${DELAY_MS:-1500}; BSTAGGER_S=${BSTAGGER_S:-1}
MOUNT_BOUND=${MOUNT_BOUND:-40}; UMOUNT_BOUND=${UMOUNT_BOUND:-100}
EXPECT=${EXPECT:-fix}
SSH=tools/mxfs_sshpass.sh
MNT=${MXFS_MNT:-/mnt/shared}
PARAMS=/sys/module/mxfs/parameters
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_d0965race_$LABEL
mkdir -p "$OUT"
# rs/rsx/measure/window_count_into/mxfs_dev_resolve (tests/lib/rig.sh):
# every count a verdict is taken from is acquired into its own file and
# validated in the parent shell first; a failed ssh is an ABORT, never a
# count of zero.
. "$(dirname "$0")/lib/rig.sh"
MARK="D0965RACE-$LABEL-$$"
fails=0; reached=0
# ck: tests/lib/rig.sh (sourced above) provides it, and its version ABORTs on an EMPTY value instead of printing a FAIL about MXFS
echo "=== d0965_remount_bracket_race A=$A B=$B laps=$LAPS delay_ms=$DELAY_MS bstagger_s=$BSTAGGER_S expect=$EXPECT out=$OUT $(date -u +%FT%TZ) ==="
want=$(modinfo mxfs.ko | awk '/^srcversion:/{print $2}')
for n in $A $B; do
  nsv=$(rs 15 "$n" "cat /sys/module/mxfs/srcversion" | tr -dc 'A-F0-9')
  [ "$nsv" = "$want" ] || { echo "RESULT FAIL d0965race: $n srcversion '$nsv' != tree '$want'"; exit 2; }
  rs 15 "$n" "grep -q ' $MNT mxfs ' /proc/mounts && echo mounted" | grep -q mounted || { echo "RESULT FAIL d0965race: $MNT not mounted on $n at start"; exit 2; }
  rs 15 "$n" "[ -f $PARAMS/dbg_pr_read_keys_delay_ms ] && echo has" | grep -q has || { echo "RESULT FAIL d0965race: $n build has no dbg_pr_read_keys_delay_ms"; exit 2; }
done
mxfs_dev_resolve "$A"
DEV=$MXFS_DEV_RESOLVED
echo "  INFO device=$DEV (from $A's live mount)"
# BRACKETS=1 is the F1 control (a single own-proof bracket, the pre-0.87.11
# behaviour); the default 4 is the fix.  Restored to 4 at exit.
BRACKETS=${BRACKETS:-4}
rs 15 "$A" "[ -f $PARAMS/dbg_pr_own_proof_brackets ] && echo $BRACKETS > $PARAMS/dbg_pr_own_proof_brackets && echo set" | grep -q set || { echo "RESULT FAIL d0965race: $A build has no dbg_pr_own_proof_brackets"; exit 2; }
disarm() { rs 15 "$A" "echo 0 > $PARAMS/dbg_pr_read_keys_delay_ms" >/dev/null; }
restore() { rs 15 "$A" "echo 0 > $PARAMS/dbg_pr_read_keys_delay_ms; echo 4 > $PARAMS/dbg_pr_own_proof_brackets" >/dev/null; }
trap restore EXIT
for L in $(seq 1 "$LAPS"); do
  tag=lap$L; MK="$MARK-$tag"
  for n in $A $B; do rs 15 "$n" "echo '$MK' > /dev/kmsg" >/dev/null; done
  # both leave, B first so A is the last member and both carry a same-boot record
  for n in $B $A; do
    o=$(rs $((UMOUNT_BOUND+10)) "$n" "T0=\$(date +%s); timeout $UMOUNT_BOUND umount $MNT; echo UMOUNT_RC=\$? WALL=\$(( \$(date +%s) - T0 ))")
    echo "  INFO $tag: $n $o"
    echo "$o" | grep -q 'UMOUNT_RC=0' || { echo "  ABORT $tag: umount on $n failed: $o"; fails=$((fails+1)); break 2; }
  done
  rs 15 "$A" "echo $DELAY_MS > $PARAMS/dbg_pr_read_keys_delay_ms" >/dev/null
  # A mounts in the background (its bracket is slow); B mounts BSTAGGER_S later
  ( rsx $((MOUNT_BOUND+15)) "$A" "T0=\$(date +%s%N); timeout $MOUNT_BOUND mount -t mxfs $DEV $MNT; R=\$?; echo AMOUNT rc=\$R wall_ms=\$(( (\$(date +%s%N) - T0) / 1000000 ))" > "$OUT/${tag}_amount.txt" ) &
  apid=$!
  sleep "$BSTAGGER_S"
  rsx $((MOUNT_BOUND+15)) "$B" "T0=\$(date +%s%N); timeout $MOUNT_BOUND mount -t mxfs $DEV $MNT; R=\$?; echo BMOUNT rc=\$R wall_ms=\$(( (\$(date +%s%N) - T0) / 1000000 ))" > "$OUT/${tag}_bmount.txt"
  wait $apid
  disarm
  # the mount commands carry their own bound and always print their result
  # line; its absence is a failed acquisition (a hung ssh), never a mount rc
  capture_require "$OUT/${tag}_amount.txt" '^AMOUNT rc=[0-9]+ wall_ms=[0-9]+$' "the mount of $A"
  capture_require "$OUT/${tag}_bmount.txt" '^BMOUNT rc=[0-9]+ wall_ms=[0-9]+$' "the mount of $B"
  arc=$(grep -ao 'rc=[0-9]*' "$OUT/${tag}_amount.txt" | cut -d= -f2); awall=$(grep -ao 'wall_ms=[0-9]*' "$OUT/${tag}_amount.txt" | cut -d= -f2)
  brc=$(grep -ao 'rc=[0-9]*' "$OUT/${tag}_bmount.txt" | cut -d= -f2); bwall=$(grep -ao 'wall_ms=[0-9]*' "$OUT/${tag}_bmount.txt" | cut -d= -f2)
  window_count_into inc "$A" 20 "$MK" 'P-PR-BRACKET-INCOHERENT' "inc"; window_count_into unp "$A" 20 "$MK" 'P305-RETIRE-OWN-UNPROVEN' "unp"
  window_count_into ref "$A" 20 "$MK" 'TCP mount REFUSED' "ref"; window_count_into set "$A" 20 "$MK" 'P305-RETIRE-SETTLED' "set"; window_count_into reb "$A" 20 "$MK" 'P-PR-OWN-PROOF-REBRACKET' "reb"
  # variant 2 (found in the control, s49ctl): B's mount thread reads A's
  # predecessor record while A's re-registered key is PRESENT and, before
  # the fix, withdrew and fenced it (A: P303-FENCECAP-SELFABSENT); with the
  # fix B holds admission for the grace (P304-RETIRE-PRESENT-GRACE) and A
  # settles the record itself.
  window_count_into grace "$B" 20 "$MK" 'P304-RETIRE-PRESENT-GRACE' "grace"; window_count_into held "$B" 20 "$MK" 'P-ADMIT-RETIRE-PENDING-HELD' "held"
  window_count_into wdr "$B" 20 "$MK" 'P304-RETIRE-EXPIRED-WITHDRAWN' "wdr"; window_count_into selfabs "$A" 20 "$MK" 'P303-FENCECAP-SELFABSENT' "selfabs"
  for n in $A $B; do measure "$n" 40 "$OUT/${tag}_$n.txt" '^DMESG_END$' "the kernel log on $n from the lap marker" "dmesg | sed -n \"/$MK/,\\\$p\" | grep -a 'P-PR-BRACKET\|P-PR-OWN-PROOF\|P305-\|P304-\|P303-\|P-ADMIT-RETIRE\|P-PR-FENCE\|mount REFUSED\|P-PRKEY-\|Filesystem has been shut down\|force_shutdown\|Corruption detected\|Metadata corruption\|Ending clean mount'; echo DMESG_END"; done
  capture_require "$OUT/${tag}_$A.txt" '^DMESG_END$' "the kernel log on $A"
  capture_require "$OUT/${tag}_$B.txt" '^DMESG_END$' "the kernel log on $B"
  echo "  RESULT $tag A_mount rc=${arc:-none} wall_ms=${awall:-none} B_mount rc=${brc:-none} wall_ms=${bwall:-none} INCOHERENT=$inc UNPROVEN=$unp REFUSED=$ref SETTLED=$set REBRACKET=$reb B_GRACE=$grace B_HELD=$held B_WITHDRAWN=$wdr A_SELFABSENT=$selfabs"
  v1=$([ "${inc:-0}" -ge 1 ] && echo 1 || echo 0)
  v2=$([ "$(( ${grace:-0} + ${wdr:-0} ))" -ge 1 ] && echo 1 || echo 0)
  if [ "$v1" = 1 ] || [ "$v2" = 1 ]; then
    reached=$((reached+1))
    if [ "$EXPECT" = refuse ]; then
      # variant 1's control is BRACKETS=1 on the fixed build (B still holds,
      # so the v2 expectation applies only when v1 was not reached, i.e. on
      # a build without the held-admission fix)
      if [ "$v1" = 1 ]; then
        ck "$tag: (control) the disturbed bracket was answered with a refusal (UNPROVEN >= 1)" "$([ "${unp:-0}" -ge 1 ] && echo yes || echo no)" "yes"
      else
        ck "$tag: (control) B withdrew and fenced A's live re-registration (WITHDRAWN >= 1, SELFABSENT >= 1)" "$([ "${wdr:-0}" -ge 1 ] && [ "${selfabs:-0}" -ge 1 ] && echo yes || echo no)" "yes"
      fi
      ck "$tag: (control) A's mount was refused" "$([ "${arc:-0}" != 0 ] && echo yes || echo no)" "yes"
    else
      ck "$tag: A mounted despite the disturbed bracket / the peer's concurrent mount (rc=0)" "${arc:-none}" "0"
      ck "$tag: no P305-RETIRE-OWN-UNPROVEN on A" "${unp:-na}" "0"
      ck "$tag: no mount refusal on A" "${ref:-na}" "0"
      ck "$tag: A settled its own record (P305-RETIRE-SETTLED >= 1)" "$([ "${set:-0}" -ge 1 ] && echo yes || echo no)" "yes"
      ck "$tag: B did not withdraw A's live record (P304-RETIRE-EXPIRED-WITHDRAWN=0)" "${wdr:-na}" "0"
      ck "$tag: A's key was not fenced (P303-FENCECAP-SELFABSENT=0)" "${selfabs:-na}" "0"
      ck "$tag: A's mount inside the bound (wall <= ${MOUNT_BOUND}000 ms)" "$([ "${awall:-999999}" -le $((MOUNT_BOUND*1000)) ] && echo yes || echo no)" "yes"
    fi
  else
    echo "  NOTE $tag: neither variant reached on this lap (no incoherent bracket on $A, no PRESENT-key sighting on $B) — not counted"
  fi
  ck "$tag: B mounted (rc=0)" "${brc:-none}" "0"
  # leave the fleet mounted: remount A if it was refused
  if [ "${arc:-1}" != 0 ]; then
    o=$(rs $((MOUNT_BOUND+15)) "$A" "timeout $MOUNT_BOUND mount -t mxfs $DEV $MNT; echo RETRY_RC=\$?")
    echo "  INFO $tag: A remount after the refusal: $o"
  fi
  for n in $A $B; do rs 15 "$n" "grep -q ' $MNT mxfs ' /proc/mounts && echo mounted" | grep -q mounted || { echo "  FAIL $tag: $n not mounted at lap end"; fails=$((fails+1)); }; done
  rs 20 "$A" "echo $tag-$$ > $MNT/.d0965race_$LABEL && sync && echo w" | grep -q w || { echo "  FAIL $tag: write on $A"; fails=$((fails+1)); }
  measure "$B" 20 "$OUT/rv_rv1_1.txt" '^READ_RC=[0-9]+$' "rv1 on $B" "cat $MNT/.d0965race_$LABEL; printf '\nREAD_RC=%s\n' \$?"; rv1=$(grep -av '^READ_RC=' "$OUT/rv_rv1_1.txt" | tr -dc 'a-z0-9-')
  ck "$tag: $B reads $A's write" "$rv1" "$tag-$$"
  ck "$tag: no shutdown/corruption lines" "$(cat "$OUT/${tag}_$A.txt" "$OUT/${tag}_$B.txt" | grep -ac 'Filesystem has been shut down\|force_shutdown\|Corruption detected\|Metadata corruption')" "0"
done
rs 20 "$A" "rm -f $MNT/.d0965race_$LABEL" >/dev/null
echo "  INFO laps=$LAPS reached=$reached fails=$fails evidence=$OUT"
[ "$fails" = 0 ] || { echo "RESULT FAIL d0965race: fails=$fails reached=$reached out=$OUT"; exit 1; }
[ "$reached" -ge 1 ] || { echo "RESULT INCONCLUSIVE d0965race: no lap produced an incoherent bracket on $A out=$OUT"; exit 3; }
echo "RESULT PASS d0965race: $reached of $LAPS laps disturbed A's own-proof bracket; expect=$EXPECT held on every one out=$OUT"
exit 0
