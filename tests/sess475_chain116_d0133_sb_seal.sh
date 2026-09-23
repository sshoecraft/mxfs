#!/bin/bash
# sess475 chain 116 v2: D-0133 verification of the 0.64.30 fix placement
# (design-consult ruling ccmemory ccloop-c7ee71c6-sess475-GPT-ruling-d0133-lock-inert-
# put-super-teardown-shape9-hardened): the SB summary critical section now runs
# in put_super while the DLM is alive (P-SB-SUMMARY-LOCK rc=0 epoch=E
# at=put_super), the mount is SEALED after its unlock (P-SB-SEALED, then
# P-SB-SEAL-OK from the guarded late quiesce), and every SB-sector write is
# witnessed at the submission chokepoint (P-SB-WRITE-SUBMIT seq= epoch= locked=
# sealed=).
#
# Arms (env ARMS, default all):
#   normal     LAPS x (prep, dirshard reuse laps on a rotating worker pair, SB
#              sector snapshot, timestamped fleet unmount, snapshot, probe
#              capture, byte-compare, chk).  Verdict per lap: 32/32 lock rc=0,
#              32 DISTINCT epochs (grant ordering witness), 32/32 P-SB-SEAL-OK,
#              0 late-dirty / seal violations / POST mismatch / lock-fail, the
#              HIGHEST-epoch node's P-SB-SYNC-WRITE == chk totals, every node's
#              last P-SB-WRITE-SUBMIT locked=1 and none sealed=1, 0 bytes
#              changed outside icount/ifree/fdblocks/crc/lsn, chk errors=0.
#   adversarial 2 sub-laps: X parks inside its critical section
#              (dbg_sb_pause_point=P, dbg_sb_pause_ms=PAUSE_MS) while Y unmounts
#              1 s later.  Y must wait: Y's LOCK epoch == X's + 1 and Y's umount
#              wall >= 0.8 x PAUSE_MS; no fence/death line names X during the
#              hold; X's PAUSE-END precedes its UNLOCK; both SEAL-OK.  Sub-lap 1
#              P=2 (after recount, before cover), X=W1; sub-lap 2 P=4 (after
#              POST, before unlock), X=W2.  The 30 other nodes stay mounted and
#              one of them (BURSTER) runs a create/rm burst with a 1 s
#              xfssyncd period, so a runtime cover lands during the hold: its
#              P-SB-WRITE-SUBMIT locked=0 lines and any P-SB-SYNC-POST-MISMATCH
#              on X are the D-0536 MEASUREMENT (recorded, not a verdict here).
#   latedirty  X arms dbg_sb_late_dirty=1 and unmounts alone: expect
#              P-DBG-SB-LATE-DIRTY, P-SB-SEAL-TRANS>=1, P-SB-LATE-DIRTY-COVER,
#              'will fix summary counters at next mount', P-SB-SEAL-DIRTY-
#              DEPARTURE, NO P304-RETIRE-QUIESCED-driven clean release (slot
#              retained), and a peer's P163-RECOVERY-COMPLETE for X's slot
#              within RECOVER_S; then the rest unmounts and chk is 0.
#   holderfail X parks (P=2, HOLD_MS) and is virsh-destroyed 3 s into the hold
#              while Y is waiting on the lock: Y must get the lock only after
#              X's recovery (a peer's P163 for X's slot precedes Y's LOCK in Y's
#              wall: umount wall >= the recovery latency), Y's epoch > X's, Y
#              recounts fresh (P-SB-RECOUNT-DONE err=0) and SEAL-OK; the rest
#              unmounts; chk 0.
# derived time budgets: prep 300 (95-118 s measured); reuse 10 laps 150 (87 s);
# umount 120 (1-2 s; adversarial = PAUSE_MS + 10 s); capture 60; chk 60;
# latedirty recovery wait RECOVER_S=150 (stale window 62 s + fence/replay);
# holderfail Y umount 240 s.
set -u
cd /src/mxfs || exit 1
LABEL=${1:-s475a}
GATE=${GATE:-tests/evidence/sess468_chain105_intentsA_s475a.log}
LOG=tests/evidence/sess475_chain116_d0133_$LABEL.log
PROD_KO=${PROD_KO:?PROD_KO required}
PROD_SV=${PROD_SV:?PROD_SV required}
LAPS=${LAPS:-3}
REUSE_LAPS=${REUSE_LAPS:-10}
ARMS=${ARMS:-"normal adversarial latedirty holderfail"}
WORKERS=${WORKERS:-"test1:test2 test5:test6 test30:test31"}
PAUSE_MS=${PAUSE_MS:-20000}
HOLD_MS=${HOLD_MS:-60000}
RECOVER_S=${RECOVER_S:-150}
BURSTER=${BURSTER:-test9}
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
IMG=$(tools/mxfs_host_image.sh) || { echo "$IMG"; exit 2; }
XFS_DATA_OFFSET=${XFS_DATA_OFFSET:-793497600}
DM=tests/evidence/sess475_chain116_dmesg_$LABEL
mkdir -p "$DM"
OUT=$DM
while ! grep -q "^DONE" "$GATE" 2>/dev/null; do sleep 30; done
fails=0
ck() { if [ "$2" = "$3" ]; then echo "  PASS $1 ($2)"; else echo "  FAIL $1 got=$2 want=$3"; fails=$((fails+1)); fi; }
# sess479: prep the fleet, and STOP the whole run if it fails.  s479a ran every
# arm after ./run.sh returned rc=3 (the clyde host-safety preflight refused to
# start a fleet run: the shared LUN was over its used-space ceiling), and the
# arms then scored an unmounted, unprepped fleet as twelve FAILs -- a build
# whose fix was already proven would have read as a regression.  A failed prep
# is not a filesystem result: record no verdict, abort, and let the gate open
# so downstream chains reach the same clean stop instead of hanging forever.
prep_arm() { # <tag>
  local t=$1 T0=$(date +%s) rc
  timeout 300 ./run.sh 32 caw prep_cluster; rc=$?
  echo "STAGE prep $t rc=$rc wall=$(( $(date +%s) - T0 ))s"
  [ "$rc" = 0 ] && return 0
  echo "ABORT $t: prep_cluster rc=$rc — the fleet is not in a known state, so no arm can yield a verdict; scoring one would be fabricating evidence."
  echo "RESULTS: fails=$fails ABORTED_ON_PREP tag=$t rc=$rc"
  echo "DONE $(date -u +%FT%TZ)"
  exit 2
}
lap() { local b="$1" l="$2"; shift 2; local T0=$(date +%s); timeout "$b" "$@"; echo "STAGE $l rc=$? wall=$(( $(date +%s) - T0 ))s"; }
# rs/rsx/measure/capture_require/value_now_into/window_into (tests/lib/rig.sh):
# every capture a verdict is taken from crosses the boundary in the parent
# shell first; a failed acquisition is an ABORT, never a count of zero or an
# empty value.
. "$(dirname "$0")/lib/rig.sh"
install_ko() {
  [ -f "$1" ] || { echo "install_ko: missing $1"; return 1; }
  cp "$1" mxfs.ko || return 1
  for t in mkfs_mxfs chk_mxfs resize_mxfs fua_verify; do [ -f "$(dirname "$1")/tools/$t" ] && cp "$(dirname "$1")/tools/$t" tools/$t; done
  local sv; sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  echo "STAGE install_prod sv=$sv want=$2"; [ "$sv" = "$2" ]
}
SBPAT='P-SB-SYNC\|P-SB-RECOUNT\|P-SB-SUMMARY\|P-SB-SEAL\|P-SB-WRITE-SUBMIT\|P-SB-LATE\|P-SB-SEALED\|P-DBG-SB\|P30-QUIESCE-RECOUNT\|will fix summary\|P304-RETIRE\|slot retained\|DIRTY\|P163-RECOVERY-COMPLETE\|lease expired/died\|fenc\|P-UNMOUNT-ORDER'
mark_fleet() { # <mark> — kmsg marker on every node (bounds the captures)
  for i in $(seq 1 32); do ( timeout 15 $SSH "test$i" "echo '$1' > /dev/kmsg" >/dev/null 2>&1 ) & done; wait
}
capture() { # <tag> <mark> [nodes...] — dmesg from mark, SB-related lines only
  local tag=$1 mk=$2; shift 2; local nodes=${*:-$(seq -f 'test%g' 1 32)}
  for n in $nodes; do ( timeout 40 $SSH "$n" "dmesg | sed -n \"/$mk/,\\\$p\" | grep -a '$SBPAT'" 2>/dev/null | grep -av '^Unauthorized\|^If you\|^$' > "$DM/${tag}_$n.txt" ) & done; wait
}
umount_node() { # <node> <bound_s> <outfile> — timestamped umount, own clock
  timeout "$2" $SSH "$1" "s=\$(date +%s%N); if grep -q ' $MNT mxfs ' /proc/mounts; then timeout $(( $2 - 10 )) umount $MNT; rc=\$?; else rc=0; fi; e=\$(date +%s%N); echo P-UNMOUNT-ORDER node=$1 start_ns=\$s end_ns=\$e rc=\$rc wall_ms=\$(( (e - s) / 1000000 ))" 2>/dev/null | grep -a '^P-UNMOUNT-ORDER' | tail -1 > "$3"
}
fleet_umount() { # <tag> [skip nodes csv]
  local UM=$DM/umount_$1; mkdir -p "$UM"; local T1=$(date +%s) skip=",${2:-},"
  for i in $(seq 1 32); do case "$skip" in *",test$i,"*) continue;; esac; umount_node "test$i" 120 "$UM/um_test$i.txt" & done; wait
  echo "STAGE fleet_umount $1 wall=$(( $(date +%s) - T1 ))s rc0=$(grep -l 'rc=0' "$UM"/um_test*.txt | wc -l)/$(ls "$UM" | wc -l)"
}
epoch_of() { grep -a 'P-SB-SUMMARY-LOCK slot=[0-9]* rc=0' "$1" | grep -ao 'epoch=[0-9]*' | tail -1 | cut -d= -f2; }
slot_of() { grep -a 'P-SB-SUMMARY-LOCK slot=' "$1" | head -1 | grep -ao 'slot=[0-9]*' | cut -d= -f2; }
verdict_lap() { # <tag> — the per-lap verdict over $DM/<tag>_test*.txt (+ chk file)
  local tag=$1 f n e best=-1 bestn= lock_ok=0 seal_ok=0 late=0 viol=0 mism=0 lfail=0 ffail=0 lastlocked=0 sealedw=0 recerr=0
  : > "$DM/${tag}_epochs.txt"
  for i in $(seq 1 32); do
    n=test$i; f="$DM/${tag}_$n.txt"; [ -s "$f" ] || continue
    grep -aq 'P-SB-SUMMARY-LOCK slot=[0-9]* rc=0 epoch=[0-9]* at=put_super' "$f" && lock_ok=$((lock_ok+1))
    grep -aq 'P-SB-SEAL-OK' "$f" && seal_ok=$((seal_ok+1))
    late=$((late + $(grep -ac 'P-SB-LATE-DIRTY-COVER' "$f")))
    viol=$((viol + $(grep -ac 'P-SB-SEAL-TRANS\|P-SB-SEAL-SYNCSB\|P-SB-WRITE-SUBMIT.*sealed=1' "$f")))
    mism=$((mism + $(grep -ac 'P-SB-SYNC-POST-MISMATCH' "$f")))
    lfail=$((lfail + $(grep -ac 'P-SB-SUMMARY-LOCK-FAIL\|P-SB-SUMMARY-LOCK slot=[0-9]* rc=-' "$f")))
    ffail=$((ffail + $(grep -ac 'P-SB-SUMMARY-FINAL-FAIL\|P-SB-RECOUNT-FAIL' "$f")))
    recerr=$((recerr + $(grep -ac 'P-SB-RECOUNT-DONE slot=[0-9]* err=-' "$f")))
    grep -a 'P-SB-WRITE-SUBMIT' "$f" | tail -1 | grep -aq 'locked=1' && lastlocked=$((lastlocked+1))
    e=$(epoch_of "$f"); [ -n "$e" ] && { echo "$e $n" >> "$DM/${tag}_epochs.txt"; [ "$e" -gt "$best" ] && { best=$e; bestn=$n; }; }
  done
  local nep=$(wc -l < "$DM/${tag}_epochs.txt") ndist=$(cut -d' ' -f1 "$DM/${tag}_epochs.txt" | sort -un | wc -l)
  local emin=$(cut -d' ' -f1 "$DM/${tag}_epochs.txt" | sort -n | head -1) emax=$(cut -d' ' -f1 "$DM/${tag}_epochs.txt" | sort -n | tail -1)
  local nn=$(ls "$DM"/${tag}_test*.txt 2>/dev/null | wc -l)
  echo "  VERDICT $tag nodes=$nn lock_ok=$lock_ok seal_ok=$seal_ok epochs=$nep distinct=$ndist range=$emin..$emax highest=$bestn late_dirty=$late seal_viol=$viol post_mismatch=$mism lock_fail=$lfail final_fail=$ffail recount_err=$recerr last_write_locked=$lastlocked"
  ck "$tag: all captured nodes took the lock at put_super" "$lock_ok" "$nn"
  ck "$tag: all captured nodes sealed clean (P-SB-SEAL-OK)" "$seal_ok" "$nn"
  ck "$tag: grant epochs distinct (ordering witness)" "$ndist" "$nep"
  ck "$tag: zero late-dirty/seal-violation/post-mismatch/lock-fail/final-fail/recount-err" "$((late+viol+mism+lfail+ffail+recerr))" "0"
  ck "$tag: every node's last SB write was under its lock" "$lastlocked" "$nn"
  if [ -n "$bestn" ] && [ -s "$DM/chk_$tag.txt" ]; then
    local w=$(grep -a 'P-SB-SYNC-WRITE' "$DM/${tag}_$bestn.txt" | tail -1 | grep -ao 'icount=[0-9]* ifree=[0-9]*')
    local c=$(grep -ao 'icount=[0-9]*, ifree=[0-9]*' "$DM/chk_$tag.txt" | head -1 | tr -d ',')
    echo "  TERMINAL $tag highest_epoch_node=$bestn epoch=$best write=[$w] chk=[$c]"
    ck "$tag: highest-epoch writer's counters == chk totals" "$w" "$c"
  fi
}
chk_stage() { # <tag>
  local T0=$(date +%s); timeout 60 tools/chk_mxfs -v "$IMG" > "$DM/chk_$1.txt" 2>&1; local rc=$?
  echo "STAGE chk $1 rc=$rc wall=$(( $(date +%s) - T0 ))s errors=$(grep -ac 'ERROR' "$DM/chk_$1.txt") $(grep -a 'ERROR\|icount=' "$DM/chk_$1.txt" | head -3 | tr '\n' ';' | cut -c1-300)"
  ck "$1: chk errors=0" "$(grep -ac 'ERROR' "$DM/chk_$1.txt")" "0"
}
{
  echo "=== sess475 chain116v2 START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) LAPS=$LAPS ARMS='$ARMS' PAUSE_MS=$PAUSE_MS HOLD_MS=$HOLD_MS ==="
  install_ko "$PROD_KO" "$PROD_SV" || { echo "ABORT: prod install"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  set -- $WORKERS
  case " $ARMS " in *" normal "*)
  for L in $(seq 1 $LAPS); do
    pair=${1:-test1:test2}; [ $# -gt 0 ] && shift; W1=${pair%%:*}; W2=${pair##*:}; tag=lap$L
    prep_arm "$tag"
    lap 150 "dirshard_reuse_peer_list $W1 $W2 $REUSE_LAPS $tag" tests/dirshard_reuse_peer_list.sh $W1 $W2 "$REUSE_LAPS"
    MK="SBSEAL-$LABEL-$tag"; mark_fleet "$MK"; sleep 3
    tests/mxfs_sb_bytecmp.sh snap "$IMG" "$DM/sb_pre_$tag.bin" "$XFS_DATA_OFFSET"
    fleet_umount "$tag"
    tests/mxfs_sb_bytecmp.sh snap "$IMG" "$DM/sb_post_$tag.bin" "$XFS_DATA_OFFSET"
    capture "$tag" "$MK"
    tests/mxfs_sb_bytecmp.sh cmp "$tag" "$DM/sb_pre_$tag.bin" "$DM/sb_post_$tag.bin"; ck "$tag: 0 bytes changed outside counters/crc/lsn" "$?" "0"
    chk_stage "$tag"
    verdict_lap "$tag"
    sort -n "$DM/${tag}_epochs.txt" | awk '{printf "%s:%s ", $2, $1}' | sed 's/^/  EPOCHS '"$tag"': /'; echo
  done;; esac
  case " $ARMS " in *" adversarial "*)
  sub=0
  for spec in "2:test1:test2" "4:test2:test1"; do
    sub=$((sub+1)); P=${spec%%:*}; r=${spec#*:}; X=${r%%:*}; Y=${r##*:}; tag=adv$sub
    prep_arm "$tag"
    MK="SBSEAL-$LABEL-$tag"; mark_fleet "$MK"
    rs 15 "$X" "echo $PAUSE_MS > /sys/module/mxfs/parameters/dbg_sb_pause_ms; echo $P > /sys/module/mxfs/parameters/dbg_sb_pause_point; cat /sys/module/mxfs/parameters/dbg_sb_pause_point" | grep -qx "$P" || { echo "ABORT: pause knob on $X"; fails=$((fails+1)); }
    # D-0536 measurement: a mounted peer covers during X's hold
    rs 15 "$BURSTER" "sysctl -w fs.xfs.xfssyncd_centisecs=100 2>&1 | tail -1; ls /proc/sys/fs/ | tr '\n' ' '" | sed 's/^/  INFO burster sysctl: /' | cut -c1-200
    mkdir -p "$DM/umount_$tag"
    umount_node "$X" $(( PAUSE_MS / 1000 + 60 )) "$DM/umount_$tag/um_$X.txt" &
    sleep 1
    umount_node "$Y" $(( PAUSE_MS / 1000 + 60 )) "$DM/umount_$tag/um_$Y.txt" &
    ( rs 60 "$BURSTER" "mkdir -p $MNT/.sbburst_$tag; for i in \$(seq 1 200); do echo x > $MNT/.sbburst_$tag/f\$i; done; rm -f $MNT/.sbburst_$tag/f*; sleep $(( PAUSE_MS / 1000 - 3 )); echo burst_done" | tail -1 | sed "s/^/  INFO burster: /" ) &
    wait
    cat "$DM/umount_$tag/um_$X.txt" "$DM/umount_$tag/um_$Y.txt" | sed 's/^/  /'
    capture "$tag" "$MK"
    ex=$(epoch_of "$DM/${tag}_$X.txt"); ey=$(epoch_of "$DM/${tag}_$Y.txt"); xs=$(slot_of "$DM/${tag}_$X.txt")
    wy=$(grep -ao 'wall_ms=[0-9]*' "$DM/umount_$tag/um_$Y.txt" | cut -d= -f2)
    echo "  ADV $tag point=$P X=$X(epoch=$ex slot=$xs) Y=$Y(epoch=$ey wall_ms=$wy) pause_lines=$(grep -ac 'P-SB-SUMMARY-PAUSE' "$DM/${tag}_$X.txt")"
    ck "$tag: X parked at point $P" "$(grep -ac "P-SB-SUMMARY-PAUSE slot=[0-9]* point=$P " "$DM/${tag}_$X.txt")" "1"
    ck "$tag: Y's grant epoch == X's + 1 (Y waited for X's unlock)" "$ey" "$(( ${ex:-0} + 1 ))"
    ck "$tag: Y's umount wall >= 0.8 x pause" "$([ "${wy:-0}" -ge $(( PAUSE_MS * 8 / 10 )) ] && echo yes || echo no)" "yes"
    ck "$tag: X's PAUSE-END precedes its UNLOCK" "$(awk '/P-SB-SUMMARY-PAUSE-END/{e=NR} /P-SB-SUMMARY-UNLOCK/{u=NR} END{print (e && u && e<u) ? "yes" : "no"}' "$DM/${tag}_$X.txt")" "yes"
    ck "$tag: no fence/death line names X's slot during the hold" "$(cat "$DM"/${tag}_test*.txt | grep -a 'lease expired/died\|fenc' | grep -ac "slot ${xs:-NONE})\|slot=${xs:-NONE} ")" "0"
    ck "$tag: X and Y both SEAL-OK" "$(grep -al 'P-SB-SEAL-OK' "$DM/${tag}_$X.txt" "$DM/${tag}_$Y.txt" | wc -l)" "2"
    echo "  D0536-MEASURE $tag burster_unlocked_writes=$(grep -ac 'P-SB-WRITE-SUBMIT.*locked=0' "$DM/${tag}_$BURSTER.txt") peers_unlocked_writes=$(cat "$DM"/${tag}_test*.txt | grep -a 'P-SB-WRITE-SUBMIT' | grep -ac 'locked=0 sealed=0') x_post_mismatch=$(grep -ac 'P-SB-SYNC-POST-MISMATCH' "$DM/${tag}_$X.txt") y_post_mismatch=$(grep -ac 'P-SB-SYNC-POST-MISMATCH' "$DM/${tag}_$Y.txt")"
    fleet_umount "$tag" "$X,$Y"
    chk_stage "$tag"
  done;; esac
  case " $ARMS " in *" latedirty "*)
    X=test3; tag=latedirty
    prep_arm "$tag"
    MK="SBSEAL-$LABEL-$tag"; mark_fleet "$MK"
    rs 15 "$X" "echo 1 > /sys/module/mxfs/parameters/dbg_sb_late_dirty; cat /sys/module/mxfs/parameters/dbg_sb_late_dirty" | grep -qx 1 || { echo "ABORT: late-dirty knob on $X"; fails=$((fails+1)); }
    mkdir -p "$DM/umount_$tag"; umount_node "$X" 90 "$DM/umount_$tag/um_$X.txt"; cat "$DM/umount_$tag/um_$X.txt" | sed 's/^/  /'
    capture "$tag" "$MK" "$X"
    xs=$(slot_of "$DM/${tag}_$X.txt")
    for pat in 'P-DBG-SB-LATE-DIRTY' 'P-SB-SEAL-TRANS' 'P-SB-LATE-DIRTY-COVER' 'will fix summary counters' 'P-SB-SEAL-DIRTY-DEPARTURE'; do
      ck "$tag: $X printed $pat" "$([ "$(grep -ac "$pat" "$DM/${tag}_$X.txt")" -ge 1 ] && echo yes || echo no)" "yes"; done
    ck "$tag: $X wrote NO SB sector after the seal" "$(grep -ac 'P-SB-WRITE-SUBMIT.*sealed=1' "$DM/${tag}_$X.txt")" "0"
    # sess476: the QUIESCED line ("release stamp may proceed") prints BEFORE the
    # seal-dirty decision on every departure, clean or not (chain 116 v2: it
    # mis-scored a correctly RETAINED slot as released).  The release stamp
    # itself is P304-RETIRE-PENDING-RELEASED; the retained departure prints
    # P277-SLOT-RETAINED-UNMOUNT-DIRTY + P302-PR-KEY-RETAINED.
    ck "$tag: $X's departure was not released clean" "$(grep -ac 'P304-RETIRE-PENDING-RELEASED\|P277-SLOT-RELEASED\|released clean' "$DM/${tag}_$X.txt" | awk '{print ($1>0)?"released":"retained"}')" "retained"
    ck "$tag: $X retained its slot and PR key (dirty departure)" "$(grep -ac 'P277-SLOT-RETAINED-UNMOUNT-DIRTY\|P302-PR-KEY-RETAINED' "$DM/${tag}_$X.txt")" "2"
    # peers must fence/recover the retained slot
    T0=$(date +%s); got=no
    while [ $(( $(date +%s) - T0 )) -lt "$RECOVER_S" ]; do
      for n in test1 test2 test4 test5; do rs 15 "$n" "dmesg | sed -n \"/$MK/,\\\$p\" | grep -ac 'P163-RECOVERY-COMPLETE.*slot=${xs:-NONE}\b\|P163-RECOVERY-COMPLETE.*slot ${xs:-NONE}\b'" | grep -qv '^0$' && { got=yes; break 2; }; done; sleep 5; done
    echo "  LATEDIRTY $tag X=$X slot=$xs recovered_by_peer=$got after=$(( $(date +%s) - T0 ))s"
    ck "$tag: a peer recovered $X's retained slot within ${RECOVER_S}s" "$got" "yes"
    capture "${tag}peers" "$MK" test1 test2 test4 test5
    fleet_umount "$tag" "$X"
    chk_stage "$tag"
  ;; esac
  case " $ARMS " in *" holderfail "*)
  # sess476 (D-0537): chain 116 v2's holderfail lap granted Y epoch=2 in 255 ms
  # while X was parked at epoch=1 inside a 60 s hold — the SB summary key has
  # no in-core inode, so Y's BAST took the no-inode ORPHAN release on X.
  # 0.64.33 names every BAST for the key (P-SB-SUMMARY-BAST held= action=)
  # and refuses the release under a live holder (sb_summary_bast_refuse=1).
  # HF_KNOBS (default "0 1") runs the arm once per knob value: 0 = the instrumented
  # proof lap (X must print held=1 action=RELEASE-under-live-holder and Y's
  # early grant reproduces), 1 = the fix lap (held=1 action=REFUSED, Y waits
  # for X's recovery).  X's ring is captured (mark-bounded) right BEFORE the
  # destroy so the holder's own lines survive its death.
  for hfk in ${HF_KNOBS:-0 1}; do
    X=test4; Y=test5; tag=holderfail$hfk
    prep_arm "$tag"
    MK="SBSEAL-$LABEL-$tag"; mark_fleet "$MK"
    rs 15 "$X" "echo $HOLD_MS > /sys/module/mxfs/parameters/dbg_sb_pause_ms; echo 2 > /sys/module/mxfs/parameters/dbg_sb_pause_point; echo $hfk > /sys/module/mxfs/parameters/sb_summary_bast_refuse; cat /sys/module/mxfs/parameters/dbg_sb_pause_point /sys/module/mxfs/parameters/sb_summary_bast_refuse | tr '\n' ' '" | grep -q "^2 $hfk " || { echo "ABORT: pause/refuse knobs on $X"; fails=$((fails+1)); }
    mkdir -p "$DM/umount_$tag"
    umount_node "$X" $(( HOLD_MS / 1000 + 30 )) "$DM/umount_$tag/um_$X.txt" &
    t=0; while [ $t -lt 20 ]; do rs 10 "$X" "dmesg | sed -n \"/$MK/,\\\$p\" | grep -ac 'P-SB-SUMMARY-PAUSE slot='" | grep -qv '^0$' && break; sleep 1; t=$((t+1)); done
    window_into "$OUT/rv_ex_1.txt" "$X" 10 "$MK"; ex=$(cat "$OUT/rv_ex_1.txt" | grep -a 'P-SB-SUMMARY-LOCK slot=' | tail -1 | grep -ao 'epoch=[0-9]*' | cut -d= -f2); window_into "$OUT/rv_xs_2.txt" "$X" 10 "$MK"; xs=$(cat "$OUT/rv_xs_2.txt" | grep -a 'P-SB-SUMMARY-LOCK slot=' | tail -1 | grep -ao 'slot=[0-9]*' | cut -d= -f2)
    echo "  HOLDERFAIL $tag knob=$hfk X=$X parked after ${t}s epoch=$ex slot=$xs"
    umount_node "$Y" 240 "$DM/umount_$tag/um_$Y.txt" &
    sleep 3
    rs 10 "$X" "dmesg | sed -n \"/$MK/,\\\$p\"" > "$DM/${tag}_${X}_predestroy.txt" 2>/dev/null
    T0=$(date +%s); sudo virsh -c qemu:///system destroy "$X" >/dev/null 2>&1; echo "  INFO virsh destroy $X rc=$? at +$(( $(date +%s) - T0 ))s (X ring lines captured pre-destroy: $(wc -l < "$DM/${tag}_${X}_predestroy.txt"))"
    wait
    cat "$DM/umount_$tag/um_$Y.txt" | sed 's/^/  /'
    capture "$tag" "$MK" test1 test2 test3 "$Y" test6 test7 test8
    ey=$(epoch_of "$DM/${tag}_$Y.txt"); wy=$(grep -ao 'wall_ms=[0-9]*' "$DM/umount_$tag/um_$Y.txt" | cut -d= -f2)
    rec=$(cat "$DM"/${tag}_test*.txt | grep -ac "P163-RECOVERY-COMPLETE.*slot[= ]${xs:-NONE}\b")
    xb=$(grep -a 'P-SB-SUMMARY-BAST' "$DM/${tag}_${X}_predestroy.txt" | tail -1 | cut -c1-200)
    echo "  HOLDERFAIL $tag knob=$hfk Y=$Y epoch=$ey wall_ms=$wy x_epoch=$ex peers_recovered_x=$rec x_unlock_before_destroy=$(grep -ac 'P-SB-SUMMARY-UNLOCK' "$DM/${tag}_${X}_predestroy.txt") x_bast='$xb'"
    ck "$tag: X was parked with the lock held when destroyed (no UNLOCK before the destroy)" "$(grep -ac 'P-SB-SUMMARY-UNLOCK' "$DM/${tag}_${X}_predestroy.txt")" "0"
    ck "$tag: X saw Y's BAST for the SB summary key while holding it (P-SB-SUMMARY-BAST held=1)" "$([ "$(grep -ac 'P-SB-SUMMARY-BAST .*held=1' "$DM/${tag}_${X}_predestroy.txt")" -ge 1 ] && echo yes || echo no)" "yes"
    if [ "$hfk" = 0 ]; then
      ck "$tag: PROOF lap — X released the key under its live holder (action=RELEASE-under-live-holder)" "$([ "$(grep -ac 'P-SB-SUMMARY-BAST .*action=RELEASE-under-live-holder' "$DM/${tag}_${X}_predestroy.txt")" -ge 1 ] && echo yes || echo no)" "yes"
      ck "$tag: PROOF lap — Y was granted epoch X+1 without waiting (wall < 5 s)" "$([ -n "$ey" ] && [ "${ey:-0}" -eq $(( ${ex:-0} + 1 )) ] && [ "${wy:-99999}" -lt 5000 ] && echo yes || echo no)" "yes"
    else
      ck "$tag: X REFUSED the orphan release under its live holder" "$([ "$(grep -ac 'P-SB-SUMMARY-BAST .*action=REFUSED-live-holder' "$DM/${tag}_${X}_predestroy.txt")" -ge 1 ] && echo yes || echo no)" "yes"
      ck "$tag: Y took the lock (rc=0) after the holder died" "$([ -n "$ey" ] && echo yes || echo no)" "yes"
      ck "$tag: Y's epoch > X's" "$([ "${ey:-0}" -gt "${ex:-0}" ] && echo yes || echo no)" "yes"
      ck "$tag: Y recounted fresh and sealed clean" "$(grep -ac 'P-SB-RECOUNT-DONE slot=[0-9]* err=0\|P-SB-SEAL-OK' "$DM/${tag}_$Y.txt")" "2"
      ck "$tag: peers recovered X's slot" "$([ "$rec" -ge 1 ] && echo yes || echo no)" "yes"
      ck "$tag: Y waited for X's recovery (umount wall >= 20 s)" "$([ "${wy:-0}" -ge 20000 ] && echo yes || echo no)" "yes"
    fi
    sudo virsh -c qemu:///system start "$X" >/dev/null 2>&1; echo "  INFO virsh start $X rc=$?"
    fleet_umount "$tag" "$X,$Y"
    chk_stage "$tag"
  done
  ;; esac
  echo "RESULTS: fails=$fails $(grep -a '^  VERDICT\|^  TERMINAL\|^  ADV \|^  D0536-MEASURE\|^  LATEDIRTY\|^  HOLDERFAIL\|^STAGE chk' "$LOG" | tr '\n' ';')"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
