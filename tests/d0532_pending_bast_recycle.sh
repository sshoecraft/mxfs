#!/bin/bash
# tests/d0532_pending_bast_recycle.sh <H> <P> [laps] [label]
#
# D-RECYCLE-DEFERRED-FREE-CORPSE-ILOCK-END-UNPAIRED-EX-HOLDER-UNDERFLOW-0532,
# item (c), the directed schedule the design consult asked for (Astra,
# 2026-09-18): a real peer BAST recorded on the old in-core inode, its cached
# grant still live, its drain not yet run, then a normal free and recycle of
# the number.
#
#   1. H creates F (EX cached, grant live); P's ssh session and H's ssh
#      session are staged, each blocked on stdin after printing READY.
#   2. H arms dbg_bast_defer_ino=F (one-shot; the BAST work item parks
#      DEFER_MS before it touches the in-core state) and ifree_drain_ms=0
#      (the free is deferred: dinode undestaged, grant kept cached).
#   3. P is triggered: stat F -> PR request -> BAST delivered to H's in-core
#      inode (i_dlm_bast_pending set, state BAST) -> work parked
#      (P-BAST-DEFER).
#   4. H is triggered 150 ms later: rm F; create G.  G reuses F's number
#      (checked by inode number; otherwise the lap is INCONCLUSIVE) and
#      xfs_iget recycles the corpse WITH the pending flag set.
#   5. fix arm (recycle_bast_keep=1): the recycle keeps the flag and the
#      BAST state (P-RECYCLE-BAST-KEEP); the parked work resumes, drains
#      and releases; P is served by that one BAST (no P36-RETRY on P, one
#      P7B-BASTNOTIFY for the number on H) and H's create is admitted after
#      the hand-off.
#      control arm (recycle_bast_keep=0): the recycle clears the flag
#      (P-RECYCLE-BAST-DROP); the parked work bails; P is served only by
#      its own 1 s deadline retry (P36-RETRY >= 1 on P, a second BAST on H).
# Read from the kernel: recycle_bast_kept / recycle_bast_dropped /
# p71_underflows (exact, reset before each lap), the probe lines inside the
# lap's kmsg mark on both nodes, P's stat rc and wall, H's create rc, the
# inode numbers of F and G, and G's content read on both nodes.
# OUTCOME (s49b/s49c, 6/6 laps): step 4 cannot reach the recycle — see the
# verdict block below.  The lap now asserts the invariant that makes the
# schedule unreachable; the arm knob is kept so the keep path can be A/B'd
# if a build ever meets the shape (recycle_bast_kept > 0 anywhere is the
# tripwire that the invariant broke).
# RESULT PASS         every counted lap: the BAST work parked, F was not
#                     inactivated until the park ended, G got a fresh
#                     number, no recycle met a live BAST, P was served by
#                     the one BAST without a retry, p71 == 0, no shutdown
# RESULT FAIL         a check failed
# RESULT INCONCLUSIVE no lap parked a BAST work item
# budget per lap: staging ~3 s + DEFER_MS + P's stat (<= DEFER_MS + 2 s)
# + captures ~4 s => ~10 s at DEFER_MS=700; bound 30 s per lap.
set -u
cd /src/mxfs || exit 1
H=${1:?holder/creator node}; P=${2:?peer node}; LAPS=${3:-3}; LABEL=${4:-pbr}
DEFER_MS=${DEFER_MS:-700}; ARM=${ARM:-fix}
SSH=tools/mxfs_sshpass.sh
MNT=${MXFS_MNT:-/mnt/shared}
PARAMS=/sys/module/mxfs/parameters
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_d0532pbr_${LABEL}_$ARM
mkdir -p "$OUT"
# rs/rsx/measure/capture_require (tests/lib/rig.sh): every capture a verdict
# is counted from crosses the boundary in the parent shell first; a failed
# acquisition is an ABORT, never a count of zero.
. "$(dirname "$0")/lib/rig.sh"
MARK="D0532PBR-$LABEL-$ARM-$$"
D=$MNT/.d0532pbr_$LABEL
CNTS="recycle_bast_kept recycle_bast_dropped recycle_bast_stale recycle_grant_cached p71_underflows"
fails=0; reached=0
# ck: tests/lib/rig.sh (sourced above) provides it, and its version ABORTs on an EMPTY value instead of printing a FAIL about MXFS
echo "=== d0532_pending_bast_recycle H=$H P=$P laps=$LAPS defer_ms=$DEFER_MS arm=$ARM out=$OUT $(date -u +%FT%TZ) ==="
want=$(modinfo mxfs.ko | awk '/^srcversion:/{print $2}')
for n in $H $P; do
  nsv=$(rs 15 "$n" "cat /sys/module/mxfs/srcversion" | tr -dc 'A-F0-9')
  [ "$nsv" = "$want" ] || { echo "RESULT FAIL d0532pbr: $n srcversion '$nsv' != tree '$want'"; exit 2; }
  rs 15 "$n" "grep -q ' $MNT mxfs ' /proc/mounts && echo mounted" | grep -q mounted || { echo "RESULT FAIL d0532pbr: $MNT not mounted on $n"; exit 2; }
done
for k in dbg_bast_defer_ino dbg_bast_defer_ms recycle_bast_keep $CNTS; do
  rs 15 "$H" "[ -f $PARAMS/$k ] && echo has" | grep -q has || { echo "RESULT FAIL d0532pbr: $H build has no $k"; exit 2; }
done
pre_drain=$(rs 12 "$H" "cat $PARAMS/ifree_drain_ms" | tr -dc '0-9')
case "$ARM" in fix) keep=1 ;; control) keep=0 ;; *) echo "RESULT FAIL d0532pbr: ARM must be fix or control"; exit 2 ;; esac
restore() { rs 15 "$H" "echo 0 > $PARAMS/dbg_bast_defer_ino; echo 1 > $PARAMS/recycle_bast_keep; echo ${pre_drain:-2000} > $PARAMS/ifree_drain_ms" >/dev/null; }
trap restore EXIT
rs 15 "$H" "echo $keep > $PARAMS/recycle_bast_keep; echo $DEFER_MS > $PARAMS/dbg_bast_defer_ms; echo 0 > $PARAMS/ifree_drain_ms; mkdir -p $D" >/dev/null
stage() { # stage <node> <fifo> <outfile> <remote command after READY+read>; pid in STAGE_PID
  # Not a command substitution: $(...) would wait for the background
  # subshell's inherited stdout while the session blocks opening the fifo.
  rm -f "$2"; mkfifo "$2"
  ( timeout 40 $SSH "$1" "echo READY; read x; $4" < "$2" 2>/dev/null | grep -a --line-buffered -v '^Unauthorized\|^Warning:\|^If you' > "$3" ) &
  STAGE_PID=$!
}
wait_ready() { local t=0; while [ $t -lt 100 ] && ! grep -aq READY "$1"; do sleep 0.1; t=$((t+1)); done; grep -aq READY "$1"; }
for L in $(seq 1 "$LAPS"); do
  tag=lap$L; MK="$MARK-$tag"; F=$D/F$L; G=$D/G$L
  rs 20 "$H" "rm -f $F $G; echo data > $F && stat -c %i $F" > "$OUT/${tag}_fino.txt"
  fino=$(tr -dc '0-9' < "$OUT/${tag}_fino.txt")
  [ -n "$fino" ] || { echo "  ABORT $tag: could not create F on $H"; fails=$((fails+1)); continue; }
  rs 15 "$H" "for c in $CNTS; do echo 0 > $PARAMS/\$c; done; true" >/dev/null
  for n in $H $P; do rs 15 "$n" "echo '$MK' > /dev/kmsg" >/dev/null; done
  pf=$OUT/${tag}_pfifo; hf=$OUT/${tag}_hfifo
  stage "$P" "$pf" "$OUT/${tag}_p.txt" "s=\$(date +%s%N); stat -c %s $F >/dev/null 2>&1; rc=\$?; e=\$(date +%s%N); echo PSTAT rc=\$rc wall_ms=\$(( (e - s) / 1000000 ))"; ppid=$STAGE_PID
  # rm then sync: the deferred free (inodegc) must have committed the ifree
  # before the create, or the allocator hands G a fresh number (s49b: F=134,
  # G=135 on 3/3 laps with no sync, the park still running).
  stage "$H" "$hf" "$OUT/${tag}_h.txt" "s=\$(date +%s%N); rm -f $F; sync; m=\$(date +%s%N); echo new > $G; rc=\$?; e=\$(date +%s%N); echo HCREATE rc=\$rc wall_ms=\$(( (e - s) / 1000000 )) sync_ms=\$(( (m - s) / 1000000 )) gino=\$(stat -c %i $G 2>/dev/null)"; hpid=$STAGE_PID
  exec 7>"$pf"; exec 8>"$hf"
  if ! wait_ready "$OUT/${tag}_p.txt" || ! wait_ready "$OUT/${tag}_h.txt"; then
    echo "  ABORT $tag: a staged session was not READY in 10 s"; fails=$((fails+1))
    echo go >&7; echo go >&8; exec 7>&- 8>&-; wait $ppid $hpid; continue
  fi
  rs 15 "$H" "echo $fino > $PARAMS/dbg_bast_defer_ino" >/dev/null
  echo go >&7; exec 7>&-
  sleep 0.15
  echo go >&8; exec 8>&-
  wait $ppid; wait $hpid
  sleep 1.5
  cnts=$(rs 15 "$H" "for c in $CNTS; do printf ' %s=%s' \$c \$(cat $PARAMS/\$c); done; echo")
  for n in $H $P; do measure "$n" 40 "$OUT/${tag}_$n.txt" '^DMESG_END$' "the kernel log on $n from the lap marker" "dmesg | sed -n \"/$MK/,\\\$p\" | grep -a 'P-BAST-DEFER\|P-RECYCLE-BAST\|P-RECYCLE-PHANTOM\|P7B-BASTNOTIFY ino=$fino \|P70-BP ino=$fino ENTRY\|P36-RETRY\|P-LKTIMEOUT\|P71-UNDERFLOW\|P-FILE-YIELD ino=$fino \|shutdown\|Corruption\|corruption'; echo DMESG_END"; done
  capture_require "$OUT/${tag}_$H.txt" '^DMESG_END$' "the kernel log on $H"
  capture_require "$OUT/${tag}_$P.txt" '^DMESG_END$' "the kernel log on $P"
  prc=$(grep -ao 'rc=[0-9]*' "$OUT/${tag}_p.txt" | cut -d= -f2); pwall=$(grep -ao 'wall_ms=[0-9]*' "$OUT/${tag}_p.txt" | cut -d= -f2)
  hrc=$(grep -ao 'rc=[0-9]*' "$OUT/${tag}_h.txt" | cut -d= -f2); hwall=$(grep -ao 'wall_ms=[0-9]*' "$OUT/${tag}_h.txt" | cut -d= -f2); gino=$(grep -ao 'gino=[0-9]*' "$OUT/${tag}_h.txt" | cut -d= -f2)
  kept=$(echo "$cnts" | grep -ao 'recycle_bast_kept=[0-9]*' | cut -d= -f2); dropped=$(echo "$cnts" | grep -ao 'recycle_bast_dropped=[0-9]*' | cut -d= -f2)
  p71=$(echo "$cnts" | grep -ao 'p71_underflows=[0-9]*' | cut -d= -f2)
  defer=$(grep -ac 'P-BAST-DEFER ino=' "$OUT/${tag}_$H.txt"); notify=$(grep -ac "P7B-BASTNOTIFY ino=$fino " "$OUT/${tag}_$H.txt")
  pretry=$(grep -ac 'P36-RETRY' "$OUT/${tag}_$P.txt")
  stale=$(echo "$cnts" | grep -ao 'recycle_bast_stale=[0-9]*' | cut -d= -f2); syncms=$(grep -ao 'sync_ms=[0-9]*' "$OUT/${tag}_h.txt" | cut -d= -f2)
  echo "  RESULT $tag F=$fino G=${gino:-none} defer=$defer kept=${kept:-na} dropped=${dropped:-na} stale=${stale:-na} notify=$notify P_stat rc=${prc:-none} wall_ms=${pwall:-none} P36-RETRY(P)=$pretry H_create rc=${hrc:-none} wall_ms=${hwall:-none} sync_ms=${syncms:-none} p71=${p71:-na}"
  grep -a 'P-BAST-DEFER\|P-RECYCLE-BAST' "$OUT/${tag}_$H.txt" | cut -c1-200 | sed 's/^/  /'
  ck "$tag: P's stat was served (rc=0)" "${prc:-none}" "0"
  ck "$tag: H's create succeeded (rc=0)" "${hrc:-none}" "0"
  ck "$tag: p71_underflows == 0 on $H" "${p71:-na}" "0"
  ck "$tag: no shutdown/corruption lines" "$(cat "$OUT/${tag}_$H.txt" "$OUT/${tag}_$P.txt" | grep -ac 'shutdown\|Corruption\|corruption')" "0"
  measure "$P" 20 "$OUT/rv_rv1_1.txt" '^READ_RC=[0-9]+$' "rv1 on $P" "cat $G; printf '\nREAD_RC=%s\n' \$?"; rv1=$(grep -av '^READ_RC=' "$OUT/rv_rv1_1.txt" | tr -dc 'a-z')
  ck "$tag: $P reads G" "$rv1" "new"
  # MEASURED s49b/s49c (0.87.9 + instruments, 6/6 laps): the shape the
  # consult asked for is UNREACHABLE, and the reason is the invariant it
  # asked to be named.  The BAST work item holds an inode reference for its
  # whole life (arm ref, released after mxfs_dlm_bast_process), so while a
  # delivered BAST is outstanding the inode's last iput cannot happen, it
  # is never inactivated, never freed, never reclaimable, never recycled.
  # In the trace: rm+sync completed ~50 ms into a 700 ms park, the corpse
  # read nlink=0 imode=0100644 at P-BAST-DEFER-END, the drain released
  # 4 ms later, P-INACT-CERT / P128-INACT-DEFER followed 10 ms after that,
  # and G was handed a fresh number every lap.  The lap therefore asserts
  # the invariant: the free waits for the BAST work, the peer is served by
  # the one parked BAST, and the number is not reused inside the park.
  tdefend=$(grep -ao '^\[ *[0-9.]*\] mxfs: P-BAST-DEFER-END' "$OUT/${tag}_$H.txt" | grep -ao '[0-9.]*' | head -1)
  # double quotes: the inode number must expand.  Single-quoted, the pattern
  # was the literal text "ino=$fino", matched nothing, and every lap FAILed
  # "not inactivated" while the window it read held the P128-INACT-DEFER
  # line for F (s59h, s61c: 6 of 6 laps)
  window_into "$OUT/rv_tinact_1.txt" "$H" 20 "$MK"; tinact=$(grep -a "P128-INACT-DEFER ino=$fino \|P-INACT-EX ino=$fino " "$OUT/rv_tinact_1.txt" | head -1 | grep -ao '^\[ *[0-9.]*' | grep -ao '[0-9.]*')
  echo "  INFO $tag: t(P-BAST-DEFER-END)=${tdefend:-none} t(first inactivation line for F)=${tinact:-none}"
  if [ "$defer" -ge 1 ]; then
    reached=$((reached+1))
    ck "$tag: F was not inactivated while its BAST work was parked (inactivation after P-BAST-DEFER-END)" "$(python3 -c "import sys; a='${tdefend:-}'; b='${tinact:-}'; print('yes' if a and b and float(b) > float(a) else 'no')")" "yes"
    ck "$tag: the number was not reused inside the park (G != F)" "$([ "${gino:-x}" != "$fino" ] && echo yes || echo no)" "yes"
    ck "$tag: no live BAST met by a recycle (kept=0 dropped=0)" "${kept:-na}/${dropped:-na}" "0/0"
    ck "$tag: P served by the one parked BAST (P36-RETRY on $P == 0)" "$pretry" "0"
    ck "$tag: one BAST delivery for the number on $H" "$notify" "1"
    ck "$tag: P's wall inside DEFER_MS + 1000 ms" "$([ "${pwall:-99999}" -le $((DEFER_MS + 1000)) ] && echo yes || echo no)" "yes"
  else
    echo "  NOTE $tag: the BAST work was not parked (defer=$defer) — not counted"
  fi
  rs 20 "$H" "rm -f $F $G" >/dev/null
done
rs 20 "$H" "rm -rf $D" >/dev/null
echo "  INFO laps=$LAPS reached=$reached fails=$fails arm=$ARM evidence=$OUT"
[ "$fails" = 0 ] || { echo "RESULT FAIL d0532pbr: fails=$fails reached=$reached arm=$ARM out=$OUT"; exit 1; }
[ "$reached" -ge 1 ] || { echo "RESULT INCONCLUSIVE d0532pbr: no lap reached the pending-BAST recycle shape out=$OUT"; exit 3; }
echo "RESULT PASS d0532pbr: $reached of $LAPS laps reached the shape; arm=$ARM expectation held on every one out=$OUT"
exit 0
