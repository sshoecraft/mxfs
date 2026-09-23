#!/bin/bash
# tests/d488_unlock_exit_arms.sh <X> <Y> <arm> [label]
#
# D-AGLOCK-ORPHAN-EX-TRACKING-LOSS-LIVELOCK-488, sess470 design-consult disposition
# ruling: the ag_strand_repair criterion manufactures the stranded
# POSTCONDITION; this harness executes the formerly-silent EXITS of the real
# post-COMMIT AG unlock body (dlm/dlm_caw.c caw_unlock_gen_body) through the
# 0.64.13 knobs and reads the tri-state machinery's answer:
#   noslot        find_slot -> -ENOENT   : P274-AGUNLK-NOSLOT, RELEASED with
#                 the bit STILL SET = an own-bit strand born on X; X's next
#                 own-AG allocation must recover it (self-BAST -> orphan_nak
#                 -> readopt) — doubling as D-0528's out-of-window measure.
#   findslot_eio  find_slot -> -EIO      : P274-UNLK-FINDSLOT-ERR, UNKNOWN ->
#                 re-verify (held=1) -> STILL_HELD -> P275-AGUNLK-REARM.
#   cas_eio1      clear CAS skipped, -EIO: P274-UNLK-CAS-ERR may_have_written=0
#                 -> UNKNOWN -> re-verify -> STILL_HELD -> REARM.
#   cas_eio2      clear CAS committed, -EIO reported: P274-UNLK-CAS-ERR ->
#                 UNKNOWN -> re-verify (held=0) -> RELEASED.
# Shape: X makes a directory and holds its AG (cached EX); the knob is armed
# on X; Y REMOVES files X created (their inodes live in X's affine AG, so Y's
# ifree needs EX on X's AG -> BAST -> X's release runs the injected exit);
# then X allocates in the same AG itself, then Y removes more.
#   sess472: the first cut had Y CREATE in X's directory, which never fires —
#   MXFS pins a node's inode allocation (xfs_dialloc_pick_ag) AND a shared
#   directory's block growth (xfs_bmap_btalloc, sess6) to the CREATING node's
#   own affine AG, so Y's creates never touch X's AG (chain 111 s470c: all
#   arms INCONCLUSIVE, Y wall 0 s).  Freeing X's inodes is what needs X's AG.
# RESULT PASS   the arm fired, the expected exit + outcome lines are present,
#               no QUARANTINE / REARM-FAIL / splat, and every create on X and
#               Y completed inside its bound.
# RESULT FAIL   an expected line missing, a forbidden line present, or a
#               create timed out (the livelock).
# RESULT INCONCLUSIVE  the arm never fired (P470-UNLK-INJECT absent) — the
#               release went through a path the knob does not cover.
# budget: Y's creates 60 s (healthy ~1 s; the REARM cadence is bounded
# seconds); X's own creates 60 s; the strand arm's recovery wall is the
# D-0528 measure and is printed.  Whole arm < 3 min.
set -u
cd /src/mxfs || exit 1
X=${1:?X (holder node)}; Y=${2:?Y (contender node)}; ARM=${3:?arm}; LABEL=${4:-d488}
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
TS=$(date -u +%Y%m%dT%H%M%SZ)
OUT=tests/evidence/${TS}_d488_${ARM}_${LABEL}
# the device under test by identity, not by path: the LUN this rig declares
# (data/rigs.json), verified by its WWID on the node, and the node's live mxfs
# mount when it has one; MXFS_DEV names a candidate that must be that LUN.
# mxfs_dev_resolve (tests/lib/rig.sh) ABORTs on anything else, never defaults
. "$(dirname "$0")/lib/rig.sh"
mxfs_dev_resolve "$X"; DEV=$MXFS_DEV_RESOLVED
mkdir -p "$OUT"
r() { timeout "$1" $SSH "$2" "$3" 2>/dev/null | grep -av '^Unauthorized\|^If you\|^$'; }
say() { echo "[d488 $ARM] $*"; }
case "$ARM" in
  noslot)       KNOB=caw_inject_unlk_noslot; KVAL=1; EXIT_LINE='P274-AGUNLK-NOSLOT' ;;
  findslot_eio) KNOB=caw_inject_unlk_findslot_eio; KVAL=1; EXIT_LINE='P274-UNLK-FINDSLOT-ERR' ;;
  cas_eio1)     KNOB=caw_inject_unlk_cas_eio; KVAL=1; EXIT_LINE='P274-UNLK-CAS-ERR' ;;
  cas_eio2)     KNOB=caw_inject_unlk_cas_eio; KVAL=2; EXIT_LINE='P274-UNLK-CAS-ERR' ;;
  *) echo "RESULT FAIL d488: unknown arm $ARM"; exit 2 ;;
esac
P=/sys/module/mxfs/parameters/$KNOB
for n in $X $Y; do
  m=$(r 20 $n "grep -c ' $MNT mxfs ' /proc/mounts; cat /sys/module/mxfs/srcversion; ls $P 2>&1 | tail -1" | tr '\n' ' ')
  echo "$n: $m" | tee "$OUT/pre_$n.txt"
  case "$m" in 1\ *) ;; *) echo "RESULT FAIL d488 $ARM: $n not mounted ($m)"; exit 2;; esac
done
r 10 $X "ls $P" | grep -q "$P" || { echo "RESULT FAIL d488 $ARM: $X lacks $KNOB (build without the sess470 knobs?)"; exit 2; }
MARK="D488-$ARM-$LABEL-$$"
r 10 $X "echo '$MARK' > /dev/kmsg"; r 10 $Y "echo '$MARK' > /dev/kmsg"
D=$MNT/d488_${ARM}_$TS

# 1. X owns the directory's AG (the files' inodes and the dir's blocks are in it)
r 30 $X "mkdir -p $D && for i in 1 2 3 4 5 6 7 8; do echo x > $D/x\$i; done; sync; echo ok" | grep -q ok || { echo "RESULT FAIL d488 $ARM: X setup failed"; exit 2; }
# 2. arm
r 10 $X "echo $KVAL > $P && cat $P" | grep -qx "$KVAL" || { echo "RESULT FAIL d488 $ARM: could not arm $KNOB on $X"; exit 2; }
say "armed $KNOB=$KVAL on $X"
# 3. Y contends: frees X's inodes -> needs X's AG -> BAST -> X's release runs
#    the injected exit (creates alone would stay in Y's own AG, see header)
T0=$(date +%s)
YO=$(r 70 $Y "cd $D && for i in 1 2 3 4; do rm x\$i || echo RM_FAIL x\$i; echo y > y\$i || echo CREATE_FAIL y\$i; done; echo ydone")
YW=$(( $(date +%s) - T0 )); echo "$YO" > "$OUT/y_creates.txt"
say "Y creates wall=${YW}s: $(echo "$YO" | tr '\n' ' ' | cut -c1-80)"
# wait (bounded) for the arm to fire and the worker to settle
fired=0
for i in $(seq 1 15); do
  if r 10 $X "dmesg | sed -n '/$MARK/,\$p' | grep -ac 'P470-UNLK-INJECT'" | grep -qv '^0$'; then fired=1; break; fi
  sleep 2
done
sleep 12   # the UNKNOWN re-verify polls once per second, bounded 10
r 25 $X "dmesg | sed -n '/$MARK/,\$p'" > "$OUT/x_dmesg.txt"
KAFTER=$(r 10 $X "cat $P")
AG=$(grep -a 'P470-UNLK-INJECT' "$OUT/x_dmesg.txt" | head -1 | grep -o 'ag=[0-9]*' | head -1 | cut -d= -f2)
say "fired=$fired knob_after=$KAFTER ag=${AG:-?}"
grep -a 'P470-UNLK-INJECT\|P274-\|P275-\|P5N-AG-ORPHAN\|P294\|P12-HANDOFF\|P5G\|P12-READOPT' "$OUT/x_dmesg.txt" | head -30 | cut -c1-200 | sed 's/^/  X: /'
# slot table truth for the AG (holder bits), from X's view of the LUN
if [ -n "${AG:-}" ]; then
  r 30 $X "/src/mxfs/tools/caw_slotdump $DEV --type ag 2>/dev/null | grep -a -m3 'ag=$AG\b\|agno=$AG\b\| $AG '" > "$OUT/slot_ag_after_release.txt"
  say "slot after release: $(head -c 300 "$OUT/slot_ag_after_release.txt" | tr '\n' ' ')"
fi
# 4. X allocates in its own AG (the strand arm's recovery measure)
T0=$(date +%s)
XO=$(r 70 $X "cd $D && for i in \$(seq 1 16); do echo h > h\$i || echo CREATE_FAIL h\$i; done; echo xdone")
XW=$(( $(date +%s) - T0 )); echo "$XO" > "$OUT/x_creates.txt"
say "X own-AG creates wall=${XW}s: $(echo "$XO" | tr '\n' ' ' | cut -c1-80)"
# 5. Y again: frees two more of X's inodes (X's AG changes hands again)
T0=$(date +%s)
YO2=$(r 70 $Y "cd $D && for i in 5 6; do rm x\$i || echo RM_FAIL x\$i; echo y > y\$i || echo CREATE_FAIL y\$i; done; ls | wc -l; echo ydone2")
YW2=$(( $(date +%s) - T0 )); echo "$YO2" > "$OUT/y_creates2.txt"
say "Y creates2 wall=${YW2}s: $(echo "$YO2" | tr '\n' ' ' | cut -c1-80)"
r 25 $X "dmesg | sed -n '/$MARK/,\$p'" > "$OUT/x_dmesg_final.txt"
r 25 $Y "dmesg | sed -n '/$MARK/,\$p'" > "$OUT/y_dmesg_final.txt"
if [ -n "${AG:-}" ]; then
  r 30 $X "/src/mxfs/tools/caw_slotdump $DEV --type ag 2>/dev/null | grep -a -m3 'ag=$AG\b\|agno=$AG\b\| $AG '" > "$OUT/slot_ag_final.txt"
fi
r 10 $X "echo 0 > $P" >/dev/null
r 30 $X "rm -rf $D" >/dev/null

# verdict
F="$OUT/x_dmesg_final.txt"
c() { grep -ac -- "$1" "$F"; }
fails=0; why=""
[ "$fired" = 1 ] || { echo "RESULT INCONCLUSIVE d488 $ARM: P470-UNLK-INJECT never fired on $X (knob_after=$KAFTER; Y wall=${YW}s) out=$OUT"; exit 3; }
[ "$(c "$EXIT_LINE")" -ge 1 ] || { fails=$((fails+1)); why="$why no-$EXIT_LINE"; }
case "$ARM" in
  findslot_eio|cas_eio1)
    [ "$(c 'P275-AGUNLK-REVERIFY')" -ge 1 ] || { fails=$((fails+1)); why="$why no-REVERIFY"; }
    [ "$(c 'P275-AGUNLK-REARM ')" -ge 1 ] || { fails=$((fails+1)); why="$why no-REARM"; } ;;
  cas_eio2)
    [ "$(c 'P275-AGUNLK-REVERIFY')" -ge 1 ] || { fails=$((fails+1)); why="$why no-REVERIFY"; } ;;
  noslot)
    [ "$(c 'P5N-AG-ORPHAN-NAK.*disk_held=1')" -ge 1 ] || [ "$(c 'P294-READOPT')" -ge 1 ] || [ "$(c 'P12-READOPT')" -ge 1 ] || { fails=$((fails+1)); why="$why no-readopt/orphan-nak"; } ;;
esac
[ "$(c 'P275-AGUNLK-QUARANTINE')" = 0 ] || { fails=$((fails+1)); why="$why QUARANTINE"; }
[ "$(c 'P275-AGUNLK-REARM-FAIL')" = 0 ] || { fails=$((fails+1)); why="$why REARM-FAIL"; }
[ "$(grep -aEc 'BUG:|Oops|WARNING: CPU' "$F" "$OUT/y_dmesg_final.txt" | awk -F: '{s+=$2} END{print s+0}')" = 0 ] || { fails=$((fails+1)); why="$why splat"; }
echo "$YO" | grep -q 'ydone' && ! echo "$YO" | grep -q 'CREATE_FAIL\|RM_FAIL' || { fails=$((fails+1)); why="$why Y-rm+creates(${YW}s)"; }
echo "$XO" | grep -q 'xdone' && ! echo "$XO" | grep -q CREATE_FAIL || { fails=$((fails+1)); why="$why X-creates(${XW}s)"; }
echo "$YO2" | grep -q 'ydone2' && ! echo "$YO2" | grep -q 'CREATE_FAIL\|RM_FAIL' || { fails=$((fails+1)); why="$why Y-rm+creates2(${YW2}s)"; }
p5g=$(c 'P5G-AGLOCK-BOUNDED-BUSY')
if [ "$fails" = 0 ]; then
  echo "RESULT PASS d488 $ARM: X=$X Y=$Y ag=${AG:-?} exit=$EXIT_LINE reverify=$(c 'P275-AGUNLK-REVERIFY') rearm=$(c 'P275-AGUNLK-REARM ') readopt=$(c 'P294-READOPT')/$(c 'P5N-AG-ORPHAN-NAK') p5g=$p5g walls y=${YW}s x=${XW}s y2=${YW2}s out=$OUT"
  exit 0
fi
echo "RESULT FAIL d488 $ARM: X=$X Y=$Y ag=${AG:-?} fails=$fails [$why] p5g=$p5g walls y=${YW}s x=${XW}s y2=${YW2}s out=$OUT"
exit 1
