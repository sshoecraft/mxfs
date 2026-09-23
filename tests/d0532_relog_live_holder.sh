#!/bin/bash
# tests/d0532_relog_live_holder.sh <H> <P> [laps] [label]
#
# D-RECYCLE-DEFERRED-FREE-CORPSE-ILOCK-END-UNPAIRED-EX-HOLDER-UNDERFLOW-0532,
# item (b): the internal nowait-ILOCK site in the release drain (the P146V
# clean-but-unlanded re-log, xfs_ilock_nowait + commit + xfs_iunlock_nodlm)
# run while another task on the same node is a counted DLM holder.  The
# holder count must be identical on both sides of the raw unlock, the drain
# must defer its unlock under the live holder (P15H-LIVE-SKIP), and the peer
# must be served only at the holder's genuine end.
#
# Ordering (the 32-node chain 117 arm was vacuous five times because it
# admitted the holder FIRST: the BAST was then deferred behind the holder
# and by the time the drain ran the inode had gone clean, so the release
# took the already-durable early-out before either injection point):
#   1. H creates F (1 MiB), syncs; P reads F (publishes; H's EX demoted).
#   2. H arms three one-shot knobs for F's inode: dbg_bast_pause_ino (the
#      drain parks PAUSE_MS before its reg-durable loop), dbg_relog_force_ino
#      (the loop treats the dinode as clean-but-unlanded once), and
#      dbg_iolock_hold_ino (the next IOLOCK_EXCL admission parks HOLD_MS).
#      NOTE the hold knob is armed only AFTER P's write is launched, so the
#      rewrite in step 3 does not consume it.
#   3. H rewrites 4 KiB at offset 8192 UNSYNCED (the inode stays pinned in
#      the CIL; a clean inode takes the early-out) and, through an ssh
#      session on P already waiting on its stdin, P's write of 'P' bytes at
#      offset 0 is triggered inside the same second — H's EX is released by
#      the quiet-age dwork ~0.9 s after an idle write, so P must request
#      before that.  P's request BASTs H with no local holder: the drain runs
#      at once, passes the early-out (dirty), parks (P-BAST-PAUSE).
#   4. Once P-BAST-PAUSE is on H's ring, H's task A writes 4 KiB of 'A' at
#      offset 4096, parked at its IOLOCK_EXCL admission with
#      i_dlm_ex_holders=1 (P-IOLOCK-HOLD).  MEASURED s49c (0.87.9 +
#      instruments): A is NOT admitted mid-drain.  A user task with nothing
#      pinned asking for a file in state BAST/DEMOTING parks in the
#      demote-wait until the hand-off (file_yield_on_demote, 0.75.40), so
#      P-IOLOCK-HOLD lands ~60 ms after P146V-RELOG-HOLDERS, after the
#      release: order=serialized, 2/2 laps.  The only admissions during a
#      drain are writeback submitters holding a folio lock and this inode's
#      own direct-I/O completions (mxfs_ilock_admit_ioend), and the drain
#      waits those out before its durable loop (0.87.7).  What this arm does
#      establish: the forced re-log (P146V-FORCE, P146V-UNLANDED) runs its
#      nowait ILOCK + commit + raw unlock with ex/pr counts 0 -> 0 and
#      p71_underflows=0, the peer's write lands after the drain, both nodes
#      read P then A.  Note the regular-file early-out ahead of the durable
#      loop skips the loop once the drain's AIL flush has landed the inode;
#      the build honours dbg_relog_force_ino at that early-out so the loop
#      (and the pause) is reached at all (s49a/s49b: 0/4 laps without it).
#   5. The drain resumes, takes the forced re-log (P146V-FORCE,
#      P146V-RELOG-HOLDERS ex_before/ex_after), reaches its unlock and finds
#      the live tenure (P15H-LIVE-SKIP); A's hold ends, its write completes,
#      its end is the final-holder transition and the BAST drains; P's write
#      completes (wall >= HOLD_MS - 1 s).
# Verdict per lap, from H's ring inside a kmsg mark, the exact
# p71_underflows counter (reset before, read after) and P's write wall:
#   REACHED   P-BAST-PAUSE, P146V-FORCE and P146V-RELOG-HOLDERS present and
#             P-IOLOCK-HOLD printed before P-BAST-PAUSE-END (the concurrent
#             case); then ex_before == ex_after == 1, P15H-LIVE-SKIP >= 1,
#             P's wall >= HOLD_MS - 1000 ms.
#   SERIAL    the lines are present but the holder was admitted after the
#             pause ended: ex_before == ex_after == 0 is still required, the
#             concurrent case was not reached.  This is the measured shape
#             for a user holder (see step 4); the lap is INCONCLUSIVE for
#             the concurrent case, never a PASS.
#   UNREACHED P-BAST-PAUSE absent (the peer's write came after the quiet-age
#             release, or the inode was clean): not a PASS.
# Always: p71_underflows == 0 on H, P's write rc=0, F[0..4095]=='P' and
# F[4096..8191]=='A' on BOTH nodes, no shutdown / corruption line.
# RESULT PASS   every lap REACHED with all checks.
# RESULT FAIL   any check failed (holder count changed, P71, torn bytes,
#               shutdown).
# RESULT INCONCLUSIVE  no lap reached the concurrent case, no check failed.
# budget: per lap ~ PAUSE_MS + HOLD_MS + 8 s of ssh; bound 60 s per lap.
set -u
cd /src/mxfs || exit 1
H=${1:?holder node}; P=${2:?peer node}; LAPS=${3:-2}; LABEL=${4:-relog}
PAUSE_MS=${PAUSE_MS:-6000}; HOLD_MS=${HOLD_MS:-6000}
SSH=tools/mxfs_sshpass.sh
MNT=${MXFS_MNT:-/mnt/shared}
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_d0532relog_$LABEL
mkdir -p "$OUT"
# rs/rsx/measure/capture_require (tests/lib/rig.sh): every capture a verdict
# is counted from crosses the boundary in the parent shell first; a failed
# acquisition is an ABORT, never a count of zero.
. "$(dirname "$0")/lib/rig.sh"
PARAMS=/sys/module/mxfs/parameters
MARK="D0532RELOG-$LABEL-$$"
D=$MNT/.d0532relog_$LABEL
echo "=== d0532_relog_live_holder H=$H P=$P laps=$LAPS pause_ms=$PAUSE_MS hold_ms=$HOLD_MS out=$OUT $(date -u +%FT%TZ) ==="
want=$(modinfo mxfs.ko | awk '/^srcversion:/{print $2}')
for n in $H $P; do
  nsv=$(rs 15 "$n" "cat /sys/module/mxfs/srcversion" | tr -dc 'A-F0-9')
  [ "$nsv" = "$want" ] || { echo "RESULT FAIL d0532relog: $n srcversion '$nsv' != tree '$want'"; exit 2; }
  rs 15 "$n" "grep -q ' $MNT mxfs ' /proc/mounts && echo mounted" | grep -q mounted || { echo "RESULT FAIL d0532relog: $MNT not mounted on $n"; exit 2; }
done
for k in dbg_bast_pause_ino dbg_relog_force_ino dbg_iolock_hold_ino p71_underflows; do
  rs 15 "$H" "[ -f $PARAMS/$k ] && echo has" | grep -q has || { echo "RESULT FAIL d0532relog: $H build has no $k"; exit 2; }
done
disarm() { rs 15 "$H" "for k in dbg_bast_pause_ino dbg_relog_force_ino dbg_iolock_hold_ino; do echo 0 > $PARAMS/\$k; done" >/dev/null; }
trap disarm EXIT
fails=0; reached=0
# ck: tests/lib/rig.sh (sourced above) provides it, and its version ABORTs on an EMPTY value instead of printing a FAIL about MXFS
rs 20 "$H" "mkdir -p $D" >/dev/null
for L in $(seq 1 "$LAPS"); do
  tag=lap$L; MK="$MARK-$tag"; F=$D/F$L
  for n in $H $P; do rs 15 "$n" "echo '$MK' > /dev/kmsg" >/dev/null; done
  rs 30 "$H" "dd if=/dev/urandom of=$F bs=1M count=1 status=none && sync && echo made" | grep -q made || { echo "  ABORT $tag: create F on $H"; fails=$((fails+1)); continue; }
  value_now_into ino "$H" 15 "$OUT/rv_ino_1.txt" '^[0-9]+$' "ino on $H" "stat -c %i $F"
  rs 30 "$P" "cat $F > /dev/null && echo pubok" | grep -q pubok || { echo "  ABORT $tag: publish via $P"; fails=$((fails+1)); continue; }
  rs 15 "$H" "echo $PAUSE_MS > $PARAMS/dbg_bast_pause_ms; echo $HOLD_MS > $PARAMS/dbg_iolock_hold_ms; echo 0 > $PARAMS/p71_underflows; echo $ino > $PARAMS/dbg_bast_pause_ino; echo $ino > $PARAMS/dbg_relog_force_ino" >/dev/null
  # P's writer waits on its stdin so the trigger costs no ssh setup.
  fifo=$OUT/${tag}_fifo; rm -f "$fifo"; mkfifo "$fifo"
  # The session announces READY before it blocks in read: a fixed sleep let
  # the trigger sit in the fifo until the login finished, so P's write landed
  # ~1.2 s after H's rewrite, past the quiet-age release of H's EX (s49a:
  # P70-BP qsrc=5 held_ms=1002 on H, then P's write in 98 ms, no BAST at all).
  ( timeout $(( (PAUSE_MS + HOLD_MS) / 1000 + 40 )) $SSH "$P" "echo READY; read x; s=\$(date +%s%N); python3 -c \"import os; fd=os.open('$F', os.O_WRONLY); os.pwrite(fd, b'P'*4096, 0); os.fsync(fd); os.close(fd)\"; rc=\$?; e=\$(date +%s%N); echo PWRITE rc=\$rc wall_ms=\$(( (e - s) / 1000000 ))" < "$fifo" 2>/dev/null | grep -a --line-buffered -v '^Unauthorized\|^Warning:\|^If you' | grep -a --line-buffered 'PWRITE\|READY' > "$OUT/${tag}_pwrite.txt" ) &
  pw_pid=$!
  exec 7>"$fifo"      # hold the fifo open so P's read blocks until the trigger
  t=0
  while [ $t -lt 100 ] && ! grep -aq READY "$OUT/${tag}_pwrite.txt"; do sleep 0.1; t=$((t+1)); done
  grep -aq READY "$OUT/${tag}_pwrite.txt" || { echo "  ABORT $tag: $P's writer session not READY in 10 s"; fails=$((fails+1)); echo go >&7; exec 7>&-; wait $pw_pid; continue; }
  t0ms=$(( $(date +%s%N) / 1000000 ))
  # step 3: dirty F on H (unsynced) and trigger P inside the same second
  rs 20 "$H" "dd if=/dev/zero of=$F bs=4k count=1 seek=2 conv=notrunc status=none && echo rew" | grep -q rew || { echo "  ABORT $tag: rewrite on $H"; fails=$((fails+1)); echo go >&7; exec 7>&-; wait $pw_pid; continue; }
  echo go >&7; exec 7>&-
  ttrig=$(( $(date +%s%N) / 1000000 - t0ms ))
  # wait for the drain to park, then admit the holder
  t=0; parked=0
  while [ $t -lt 20 ]; do
    c=$(rs 10 "$H" "dmesg | sed -n \"/$MK/,\\\$p\" | grep -ac 'P-BAST-PAUSE ino=$ino '" | tr -dc '0-9')
    case "$c" in ''|*[!0-9]*) : ;; *) [ "$c" -ge 1 ] && { parked=1; break; };; esac
    sleep 0.3; t=$((t+1))
  done
  tpark=$(( $(date +%s%N) / 1000000 - t0ms ))
  if [ "$parked" = 1 ]; then
    rs 15 "$H" "echo $ino > $PARAMS/dbg_iolock_hold_ino" >/dev/null
    rs $(( HOLD_MS / 1000 + 30 )) "$H" "s=\$(date +%s%N); python3 -c \"import os; fd=os.open('$F', os.O_WRONLY); os.pwrite(fd, b'A'*4096, 4096); os.fsync(fd); os.close(fd)\"; rc=\$?; e=\$(date +%s%N); echo AWRITE rc=\$rc wall_ms=\$(( (e - s) / 1000000 ))" | grep -a AWRITE > "$OUT/${tag}_awrite.txt"
  else
    echo "  NOTE $tag: the drain never parked (P-BAST-PAUSE absent after $t polls; trigger at +${ttrig}ms) — holder not launched"
    : > "$OUT/${tag}_awrite.txt"
  fi
  wait $pw_pid
  disarm
  sleep 2
  for n in $H $P; do measure "$n" 40 "$OUT/${tag}_$n.txt" '^DMESG_END$' "the kernel log on $n from the lap marker" "dmesg | sed -n \"/$MK/,\\\$p\" | grep -a 'P-BAST-PAUSE\|P146V\|P-IOLOCK-HOLD\|P15H-LIVE-SKIP\|P71-UNDERFLOW\|P70-BP ino=$ino\|shutdown\|Corruption\|corruption'; echo DMESG_END"; done
  capture_require "$OUT/${tag}_$H.txt" '^DMESG_END$' "the kernel log on $H"
  capture_require "$OUT/${tag}_$P.txt" '^DMESG_END$' "the kernel log on $P"
  value_now_into p71 "$H" 15 "$OUT/rv_p71_2.txt" '^-?[0-9]+$' "p71 on $H" "cat $PARAMS/p71_underflows"
  hf="$OUT/${tag}_$H.txt"
  pw=$(grep -ao 'wall_ms=[0-9]*' "$OUT/${tag}_pwrite.txt" | cut -d= -f2); prc=$(grep -ao 'rc=[0-9]*' "$OUT/${tag}_pwrite.txt" | cut -d= -f2)
  holders=$(grep -a "P146V-RELOG-HOLDERS ino=$ino " "$hf" | tail -1 | grep -ao 'ex_before=[0-9]* ex_after=[0-9]*')
  order=$(awk '/P-IOLOCK-HOLD ino='"$ino"' /{h=NR} /P-BAST-PAUSE-END ino='"$ino"' /{e=NR} END{ if (h && e) print (h < e) ? "concurrent" : "serialized"; else print "unknown" }' "$hf")
  echo "  RESULT $tag ino=$ino order=$order relog_holders=[$holders] live_skip=$(grep -ac 'P15H-LIVE-SKIP' "$hf") p71_underflows=${p71:-na} pwrite_rc=${prc:-none} pwrite_wall_ms=${pw:-none} t_trigger=+${ttrig}ms t_park=+${tpark}ms"
  cat "$OUT/${tag}_pwrite.txt" "$OUT/${tag}_awrite.txt" | sed 's/^/  /'
  ck "$tag: p71_underflows == 0 on $H" "${p71:-na}" "0"
  ck "$tag: peer's write succeeded (rc=0)" "${prc:-none}" "0"
  for n in $H $P; do
    measure "$n" 20 "$OUT/rv_got_$n.txt" '^READ_RC=[0-9]+$' "the content class of $F on $n" "python3 -c \"d=open('$F','rb').read(8192); print(('P' if d[:4096]==b'P'*4096 else 'x')+('A' if d[4096:8192]==b'A'*4096 else 'x'))\"; printf '\nREAD_RC=%s\n' \$?"; got=$(grep -av '^READ_RC=' "$OUT/rv_got_$n.txt" | tr -dc 'PAx')
    ck "$tag: $n sees P's bytes at 0 and A's bytes at 4096" "$got" "PA"
  done
  ck "$tag: no shutdown/corruption lines on $H/$P" "$(cat "$hf" "$OUT/${tag}_$P.txt" | grep -ac 'shutdown\|Corruption\|corruption')" "0"
  if [ "$order" = concurrent ]; then
    reached=$((reached+1))
    ck "$tag: re-log forced and taken under the live holder (P146V-FORCE + RELOG-HOLDERS)" "$(grep -ac "P146V-FORCE ino=$ino \|P146V-RELOG-HOLDERS ino=$ino " "$hf")" "2"
    ck "$tag: holder count 1 on both sides of the raw unlock" "$holders" "ex_before=1 ex_after=1"
    ck "$tag: unlock deferred under the live holder (P15H-LIVE-SKIP >= 1)" "$([ "$(grep -ac 'P15H-LIVE-SKIP' "$hf")" -ge 1 ] && echo yes || echo no)" "yes"
    ck "$tag: peer waited for the holder's genuine end (wall >= HOLD_MS - 1000)" "$([ "${pw:-0}" -ge $(( HOLD_MS - 1000 )) ] && echo yes || echo no)" "yes"
  else
    [ -n "$holders" ] && ck "$tag: (order=$order) holder count unchanged across the raw unlock" "$(echo "$holders" | awk -F'[= ]' '{print ($2==$4)?"same":"changed"}')" "same"
    echo "  NOTE $tag: order=$order — the concurrent case was not reached this lap"
  fi
  grep -a "P-BAST-PAUSE\|P146V\|P-IOLOCK-HOLD\|P15H-LIVE-SKIP\|P71" "$hf" | cut -c1-200 | sed 's/^/  /'
done
rs 30 "$H" "rm -rf $D" >/dev/null
echo "  INFO laps=$LAPS reached=$reached fails=$fails evidence=$OUT"
[ "$fails" = 0 ] || { echo "RESULT FAIL d0532relog: fails=$fails reached=$reached out=$OUT"; exit 1; }
[ "$reached" -ge 1 ] || { echo "RESULT INCONCLUSIVE d0532relog: the concurrent case was not reached in $LAPS laps out=$OUT"; exit 3; }
[ "$reached" = "$LAPS" ] || { echo "RESULT INCONCLUSIVE d0532relog: reached=$reached of $LAPS laps (no check failed) out=$OUT"; exit 3; }
echo "RESULT PASS d0532relog: $LAPS laps reached the concurrent case; holder count unchanged, unlock deferred under the live holder, p71=0, both nodes coherent out=$OUT"
exit 0
