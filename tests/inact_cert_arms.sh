#!/bin/bash
# inact_cert_arms.sh — fix shape A (D-FOREIGN-SLICE-INTENTS-ABANDONED)
# verification arms the sess469 design-consult ruling made MANDATORY, driven by the
# TEST ONLY module parameter mxfs.inact_cert_inject (docs/authority-
# certificate.md) on ONE node of a mounted multi-node cluster.
#
#   refuse    knob=1: every inactivation certificate is refused -> the free
#             must DEFER (P-INACT-CERT-REFUSED, no truncate, reap entry);
#             knob=0 afterwards -> the deferred reap frees the zombies
#             (P89-REAP-DONE) with a certificate (P-INACT-CERT installed=1).
#   edeadlk   knob=3: the first acquire is turned into the -EDEADLK contract
#             with a POISONED grant result -> the retry re-acquires and
#             installs from ITS result (P-INACT-CERT-INJECT3, P2I-INACT-UPG
#             rc=0, installed=1), no MISS.
#   advance   knob=4: the installed epoch is advanced past the grant
#             result's -> P-INACT-CERT cid_epoch == gres_epoch+1 and the exact
#             revoke still hits (no P-INACT-CERT-REVOKE-MISS).
#   defer     mxfs.ifree_drain_ms=0: the ifree-end drain is skipped ->
#             P128-INACT-DEFER keeps the grant + certificate; drop_caches
#             evicts -> the evict assertion runs clean (no P-INACT-CERT-EVICT
#             cls!=0, no LOST, P-INACT-CERT-TOTAL evict_ok grows).
#   foreign   knob=2: the saved identity is corrupted -> the revoke misses
#             FOREIGN and the node fails CLOSED (P-INACT-CERT-FOREIGN +
#             shutdown).                                     [shuts fs down]
#   gone      knob=5: a release-side actor moves the certificate before
#             INACT-EXREL -> P-INACT-CERT-LOST + P-INACT-CERT-GONE +
#             shutdown.                                       [shuts fs down]
#             sess474: both inject at the SYNC INACT-EXREL revoke, which
#             only runs when the freed dinode is destaged inside the
#             inactivation.  With mxfs.ifree_eager_durable=0 (default)
#             EVERY free on this rig P128-INACT-DEFERs instead (chain 108
#             s473c: pin=1 on the arm's ino; the evict retired the
#             certificate through mxfs_dlm_evict's assertion and neither
#             injection ran).  These arms set ifree_eager_durable=1 for
#             their rm so the sync path is the one retiring, and fail if
#             the arm's ino DEFERred anyway.
#   evictforeign knob=6: the DEFERRED certificate is made to look like
#             another incarnation's at evict -> P-INACT-CERT-EVICT cls=2 +
#             P-INACT-CERT-EVICT-CORRUPT + shutdown.          [shuts fs down]
#   evictactive knob=7: the inactivation leaves the certificate ACTIVE
#             (no defer) -> evict cls=3 + EVICT-CORRUPT + shutdown.
#                                                             [shuts fs down]
#   reuse     no knob: two create->publish->rm cycles in the same directory so
#             the second cycle's creates REUSE the first cycle's just-freed
#             numbers with re-randomised generations (D-0529 item 3: a reused
#             number's new incarnation must not fall into the gen+1 window);
#             both cycles' DEFERRED certificates are retired by evict with
#             cls=0 (no P-INACT-CERT-EVICT, no CORRUPT, no shutdown) and
#             P-INACT-CERT-TOTAL evict_ok grows by both cycles' inodes.
#             Reports how many numbers were actually reused; a lap that
#             reused none is FAILED as vacuous, never passed.
#   escalate  knob=1 held across the deferred-reap cadence: the 9th refusal
#             of one zombie -> P-INACT-CERT-REFUSED-ESCALATE + shutdown
#             (~5 s + 8 x 30 s).                              [shuts fs down]
#
# Usage: tests/inact_cert_arms.sh <arm> <node> [label] [peer]
#   arms needing a build >= 0.64.24: evictforeign, evictactive (knobs 6/7).
#   sess472: <peer> (default test2, or $INACT_PEER) walks the directory and
#   reads every file BEFORE the rm.  Chain 108 s472b on 0.64.14 failed all
#   seven arms with 'P-INACT-CERT installed=1 got=0': the files were created
#   and removed on one node, so they were still on the UNPUBLISHED list
#   (local-only EX grant, no slot) and every install was refused with
#   try=7 UNPUB — the by-design classless case the ruling exempts — so no
#   arm ever reached the certified path.  The peer walk BASTs the creator
#   into publishing (mxfs_dlm_publish_unpublished); the rm's inactivation
#   then acquires a real EX and installs.  finish() fails the arm if any
#   try=7 refusal is still seen.
# Prints "RESULT <arm> PASS|FAIL fails=N" and leaves the node's dmesg for the
# arm in tests/evidence/<stamp>_inactcert_<arm>/dmesg_<node>.txt.
# derived time budgets: refuse 120 s (reap cadence 5 s + 30 s), escalate 330 s
# (8 x 30 s + margin), every other arm 60 s.
set -u
cd /src/mxfs || exit 1
ARM=${1:?arm}; V=${2:?node}; LABEL=${3:-a}; PEER=${4:-${INACT_PEER:-test2}}
SSH=tools/mxfs_sshpass.sh
MNT=${MXFS_MNT:-/mnt/shared}
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_inactcert_$ARM
mkdir -p "$OUT"
fails=0
ck() { if [ "$2" = "$3" ]; then echo "  PASS $1 ($2)"; else echo "  FAIL $1 got=$2 want=$3"; fails=$((fails+1)); fi; }
ckge() { if [ "${2:-0}" -ge "$3" ] 2>/dev/null; then echo "  PASS $1 ($2 >= $3)"; else echo "  FAIL $1 got=$2 want>=$3"; fails=$((fails+1)); fi; }
# rs/rsx/measure/window_count_into/value_now_into (tests/lib/rig.sh): every
# count and every knob value a verdict is taken from is acquired into its own
# file and validated in the parent shell first; a failed ssh is an ABORT,
# never a count of zero (the old cnt-over-ssh read exactly that way).
. "$(dirname "$0")/lib/rig.sh"
# THE INSTALL PROBE IS BUDGETED.  xfs_inode.c prints 'P-INACT-CERT ino=...
# installed=' for the first 96 inactivations per module load and then never
# again; the defer arm's 1100-file filler alone exhausts it, so every arm run
# after that on the same load read installed=1 as 0 (s582d: reuse and
# evictforeign both "FAIL installed=1 got=0" while the injection arm classed a
# certificate that was demonstrably there).  An assertion on a silenced probe
# is neither a pass nor a fail: it is unreadable, and is reported as such.
# The counter is per module LOAD; the dmesg ring is per BOOT and survives a
# reload (s582f read a census of 1115 from the previous load as this load's
# "pre" and failed on -1107).  Nothing the module prints marks a load, so the
# reads are anchored on the mount's first membership line, which every mount
# prints and which no probe here can precede: everything after the last
# 'MXFS-MEMBERSHIP ... active_count=1' is this mount, hence this load.  A
# same-load remount would move the anchor without resetting the counter, which
# can only under-count -- toward FAIL, never toward a false PASS.
SINCE_LOAD="dmesg | tac | sed '/MXFS-MEMBERSHIP local=[0-9]* active_count=1/q' | tac"
CERT_PRINT_BUDGET=96
ck_installed() { # <label> <count> <want>
  local ring ringf
  ringf="$OUT/ring_$(echo "$1" | tr -c 'A-Za-z0-9' '_' | cut -c1-40).txt"
  measure "$V" 20 "$ringf" '^RING_END$' "the since-load kernel ring on $V" "$SINCE_LOAD; echo RING_END"
  count_file_into ring "$ringf" 'P-INACT-CERT ino='
  if [ "${2:-0}" -ge "$3" ] 2>/dev/null; then
    echo "  PASS $1 ($2 >= $3)"
  elif [ "$ring" -ge "$CERT_PRINT_BUDGET" ]; then
    echo "  UNREADABLE $1: the install probe's print budget ($CERT_PRINT_BUDGET per module load) is exhausted ($ring in the ring); reload the module before this arm to read it"
    unreadable=$((unreadable+1))
  else
    echo "  FAIL $1 got=$2 want>=$3 (probe budget not exhausted: $ring of $CERT_PRINT_BUDGET)"; fails=$((fails+1))
  fi
}
unreadable=0
MARK="INACTCERT-$ARM-$LABEL-$$"
FMARK="$MARK-FILL"   # sess474: the defer arm's filler boundary (see finish)
# cnt: POLLING ONLY (the escalate arm's wait loop); never feeds a verdict —
# those go through window_count_into
cnt() { rs 20 "$V" "dmesg | sed -n \"/$MARK/,\\\$p\" | grep -ac '$1'" | tr -dc '0-9'; }
knob() { rs 12 "$V" "echo $1 > /sys/module/mxfs/parameters/inact_cert_inject; cat /sys/module/mxfs/parameters/inact_cert_inject" | tr -dc '0-9'; }
drain_ms() { rs 12 "$V" "echo $1 > /sys/module/mxfs/parameters/ifree_drain_ms; cat /sys/module/mxfs/parameters/ifree_drain_ms" | tr -dc '0-9'; }
eager() { rs 12 "$V" "echo $1 > /sys/module/mxfs/parameters/ifree_eager_durable; cat /sys/module/mxfs/parameters/ifree_eager_durable" | tr -dc '0-9'; }
EVICT_N=0
evict() { EVICT_N=$((EVICT_N + 1)); measure "$V" 60 "$OUT/evict_$EVICT_N.txt" '^evict_ok$' "the cache eviction on $V" "sync; echo 2 > /proc/sys/vm/drop_caches; sleep 3; echo evict_ok"; }
DIR=$MNT/.inactcert_${ARM}_$LABEL
# create N 1 MiB files (real extents: the truncate dirties bmbt/agf images
# under the certificate) and rm them; inactivation follows the last iput.
mkrm() { # <n>   (stdout line 1 = the inos; the walk / rm status goes to the log on stderr and to $OUT/mkrm.txt)
  local inos walk rmo
  # the inode list is the arm's identity: acquired across the boundary
  # (the creates and the listing must complete), then required non-empty
  measure "$V" 60 "$OUT/inos_raw.txt" '^INOS_END$' "the creation and listing of the arm's files on $V" "mkdir -p $DIR && for i in \$(seq 1 $1); do dd if=/dev/zero of=$DIR/f\$i bs=64k count=16 status=none; done; sync; ls -i $DIR | awk '{print \$1}'; echo INOS_END"
  grep -a '^[0-9]' "$OUT/inos_raw.txt" > "$OUT/inos.txt"
  capture_require "$OUT/inos.txt" '^[0-9]+$' "the arm's inode list on $V"
  inos=$(tr '\n' ' ' < "$OUT/inos.txt")
  echo "$inos"
  # sess472: publish before the rm (see the header) — the peer lists the
  # directory and reads every file, then the creator waits for its
  # releases to settle before the unlink.
  # sess473: chain 108 s472u's refuse arm showed the creates and then 46 s of
  # NOTHING on the creator (no unlink trail, no inactivation) — the walk and
  # the rm must leave their own status in the log, with the creator's
  # ring-line count around the rm, so "rm never ran" and "inactivation never
  # ran" are told apart on the next lap.
  walk=$(rs 60 "$PEER" "ls -l $DIR > /dev/null && for f in $DIR/f*; do cat \$f > /dev/null; done && echo peer_walk_ok" | grep -a 'peer_walk_ok\|No such\|denied\|cannot' | head -2 | tr '\n' ' ')
  rmo=$(rs 60 "$V" "l0=\$(dmesg | wc -l); sleep 2; rm -f $DIR/f*; rc=\$?; sync; sleep 3; echo rm_rc=\$rc left=\$(ls $DIR 2>/dev/null | wc -l) ring_lines_added=\$(( \$(dmesg | wc -l) - l0 )) unlink_trail=\$(dmesg | sed -n \"/$MARK/,\\\$p\" | grep -ac 'P82-ADD\|P-IUNLINK\|P128-INACT\|P-INACT-CERT')")
  echo "  INFO mkrm n=$1 inos=[$(tr '\n' ' ' < "$OUT/inos.txt")] walk=[${walk:-no_output}] rm=[${rmo:-no_output}]" >&2
  echo "walk=$walk rm=$rmo" > "$OUT/mkrm.txt"
}
finish() {
  measure "$V" 30 "$OUT/dmesg_$V.txt" '^DMESG_END$' "the kernel log on $V from the arm's mark" "dmesg | sed -n \"/$MARK/,\\\$p\"; echo DMESG_END"
  # sess473: scoped to the arm's own inos — the defer arm's 1100-file filler
  # is created and removed unpublished on purpose (by-design try=7), and
  # chain 108 s472u counted those 84 as the arm's failure.
  measure "$V" 20 "$OUT/unpub_window.txt" '^UNPUB_END$' "the pre-filler kernel log window on $V" "dmesg | sed -n \"/$MARK\\\$/,/$FMARK/p\" | grep -a 'P-INACT-CERT ino=[0-9]* installed=0 try=7' | grep -ao 'ino=[0-9]*' | cut -d= -f2; echo UNPUB_END"
  ck "no UNPUB refusals on the arm's inos before the filler (P-INACT-CERT installed=0 try=7: the peer walk published the files)" "$(grep -av '^UNPUB_END$' "$OUT/unpub_window.txt" | grep -acxFf "$OUT/inos.txt")" 0
  echo "  INFO evidence $OUT/dmesg_$V.txt ($(wc -l < "$OUT/dmesg_$V.txt") lines)"
  # An arm with an unreadable assertion did not decide it; say so in the
  # verdict line rather than folding it into PASS.
  if [ "$fails" = 0 ] && [ "$unreadable" = 0 ]; then echo "RESULT $ARM PASS fails=0"
  elif [ "$fails" = 0 ]; then echo "RESULT $ARM PASS-WITH-UNREADABLE fails=0 unreadable=$unreadable"
  else echo "RESULT $ARM FAIL fails=$fails unreadable=$unreadable"; fi
  exit $(( fails > 0 ))
}

echo "=== inact_cert_arms arm=$ARM node=$V label=$LABEL out=$OUT $(date -u +%FT%TZ) ==="
want=$(modinfo mxfs.ko | awk '/^srcversion:/{print $2}')
nsv=$(rs 15 "$V" "cat /sys/module/mxfs/srcversion" | tr -dc 'A-F0-9')
[ "$nsv" = "$want" ] || { echo "ABORT: $V srcversion '$nsv' != tree '$want'"; exit 2; }
rs 15 "$V" "grep -q ' $MNT mxfs ' /proc/mounts && echo mounted" | grep -q mounted || { echo "ABORT: $MNT not mounted on $V"; exit 2; }
rs 15 "$PEER" "grep -q ' $MNT mxfs ' /proc/mounts && echo mounted" | grep -q mounted || { echo "ABORT: $MNT not mounted on peer $PEER"; exit 2; }
rs 15 "$V" "test -w /sys/module/mxfs/parameters/inact_cert_inject && echo knob_ok" | grep -q knob_ok || { echo "ABORT: no inact_cert_inject knob on $V (build < 0.64.8)"; exit 2; }
rs 12 "$V" "echo '$MARK' > /dev/kmsg" >/dev/null

case "$ARM" in
refuse)
  value_now_into knobv1 "$V" 12 "$OUT/knob_1.txt" '^[0-9]+$' "the inact_cert_inject knob on $V" "echo 1 > /sys/module/mxfs/parameters/inact_cert_inject; cat /sys/module/mxfs/parameters/inact_cert_inject"
  ck "knob=1" "$knobv1" 1
  inos=$(mkrm 4 | head -1)
  echo "  INFO inos: $inos"
  window_count_into wc1 "$V" 20 "$MARK" 'P-INACT-CERT-REFUSED ino=' "P-INACT-CERT-REFUSED lines"
  ckge "P-INACT-CERT-REFUSED lines" "$wc1" 4
  window_into "$OUT/rv_rv1_1.txt" "$V" 20 "$MARK"; rv1=$(cat "$OUT/rv_rv1_1.txt" | grep -a 'P137-INACT-TIME' | grep -ac 'trunc_us=[1-9]' | tr -dc '0-9')
  ck   "no truncate after a refusal (P137-INACT-TIME trunc>0 for these inos)" "$rv1" 0
  window_count_into wc2 "$V" 20 "$MARK" 'P-INACT-CERT-REFUSED-ESCALATE' "no escalation yet"
  ck   "no escalation yet" "$wc2" 0
  window_count_into shutv1 "$V" 20 "$MARK" 'Filesystem has been shut down\|P-SESSION-POISON\|force-shutdown' "shut"
  ck   "no shutdown" "$shutv1" 0
  value_now_into knobv2 "$V" 12 "$OUT/knob_2.txt" '^[0-9]+$' "the inact_cert_inject knob on $V" "echo 0 > /sys/module/mxfs/parameters/inact_cert_inject; cat /sys/module/mxfs/parameters/inact_cert_inject"
  ck "knob=0" "$knobv2" 0
  # the deferred reap retries at 5 s then 30 s; the second retry installs
  # a certificate and frees the zombie
  sleep 40
  window_count_into wc3 "$V" 20 "$MARK" 'P89-REAP-DONE' "P89-REAP-DONE (zombies freed once certified)"
  ckge "P89-REAP-DONE (zombies freed once certified)" "$wc3" 4
  window_count_into wc4 "$V" 20 "$MARK" 'P-INACT-CERT ino=[0-9]* installed=1' "P-INACT-CERT installed=1 after the knob cleared"
  ck_installed "P-INACT-CERT installed=1 after the knob cleared" "$wc4" 4
  window_count_into wc5 "$V" 20 "$MARK" 'P-INACT-CERT-REVOKE-MISS' "no REVOKE-MISS"
  ck   "no REVOKE-MISS" "$wc5" 0
  window_count_into wc6 "$V" 20 "$MARK" 'P-INACT-CERT-LOST' "no LOST"
  ck   "no LOST" "$wc6" 0
  window_count_into shutv2 "$V" 20 "$MARK" 'Filesystem has been shut down\|P-SESSION-POISON\|force-shutdown' "shut"
  ck   "no shutdown" "$shutv2" 0
  ;;
edeadlk)
  value_now_into knobv3 "$V" 12 "$OUT/knob_3.txt" '^[0-9]+$' "the inact_cert_inject knob on $V" "echo 3 > /sys/module/mxfs/parameters/inact_cert_inject; cat /sys/module/mxfs/parameters/inact_cert_inject"
  ck "knob=3" "$knobv3" 3
  mkrm 4 > /dev/null
  window_count_into wc7 "$V" 20 "$MARK" 'P-INACT-CERT-INJECT3' "P-INACT-CERT-INJECT3"
  ckge "P-INACT-CERT-INJECT3" "$wc7" 4
  window_count_into wc8 "$V" 20 "$MARK" 'P2I-INACT-UPG ino=[0-9]* demote+reacquire rc=0' "P2I-INACT-UPG rc=0 (retry re-acquired)"
  ckge "P2I-INACT-UPG rc=0 (retry re-acquired)" "$wc8" 4
  window_count_into wc9 "$V" 20 "$MARK" 'P-INACT-CERT ino=[0-9]* installed=1' "P-INACT-CERT installed=1 from the RETRY result"
  ck_installed "P-INACT-CERT installed=1 from the RETRY result" "$wc9" 4
  window_count_into wc10 "$V" 20 "$MARK" 'P-INACT-CERT-REFUSED' "no refusal from the poisoned result"
  ck   "no refusal from the poisoned result" "$wc10" 0
  window_count_into wc11 "$V" 20 "$MARK" 'P-INACT-CERT-REVOKE-MISS' "no REVOKE-MISS"
  ck   "no REVOKE-MISS" "$wc11" 0
  window_count_into shutv3 "$V" 20 "$MARK" 'Filesystem has been shut down\|P-SESSION-POISON\|force-shutdown' "shut"
  ck   "no shutdown" "$shutv3" 0
  value_now_into knobv4 "$V" 12 "$OUT/knob_4.txt" '^[0-9]+$' "the inact_cert_inject knob on $V" "echo 0 > /sys/module/mxfs/parameters/inact_cert_inject; cat /sys/module/mxfs/parameters/inact_cert_inject"
  ck "knob=0" "$knobv4" 0
  ;;
advance)
  value_now_into knobv5 "$V" 12 "$OUT/knob_5.txt" '^[0-9]+$' "the inact_cert_inject knob on $V" "echo 4 > /sys/module/mxfs/parameters/inact_cert_inject; cat /sys/module/mxfs/parameters/inact_cert_inject"
  ck "knob=4" "$knobv5" 4
  mkrm 4 > /dev/null
  window_count_into wc12 "$V" 20 "$MARK" 'P-INACT-CERT ino=[0-9]* installed=1' "P-INACT-CERT installed=1"
  ck_installed "P-INACT-CERT installed=1" "$wc12" 4
  window_into "$OUT/rv_rv2_2.txt" "$V" 20 "$MARK"; rv2=$(cat "$OUT/rv_rv2_2.txt" | grep -a 'P-INACT-CERT ino=[0-9]* installed=1' | awk '{g=0;c=0; for(i=1;i<=NF;i++){ if($i ~ /^gres_epoch=/){split($i,a,"=");g=a[2]} if($i ~ /^cid_epoch=/){split($i,b,"=");c=b[2]} } if (c==g+1) ok++; else bad++} END{print ok+0 "/" bad+0}')
  ck   "cid_epoch == gres_epoch+1 on every install" "$rv2" "4/0"
  window_count_into wc13 "$V" 20 "$MARK" 'P-INACT-CERT-REVOKE-MISS' "no REVOKE-MISS (exact revoke matched the advanced epoch)"
  ck   "no REVOKE-MISS (exact revoke matched the advanced epoch)" "$wc13" 0
  window_count_into shutv4 "$V" 20 "$MARK" 'Filesystem has been shut down\|P-SESSION-POISON\|force-shutdown' "shut"
  ck   "no shutdown" "$shutv4" 0
  value_now_into knobv6 "$V" 12 "$OUT/knob_6.txt" '^[0-9]+$' "the inact_cert_inject knob on $V" "echo 0 > /sys/module/mxfs/parameters/inact_cert_inject; cat /sys/module/mxfs/parameters/inact_cert_inject"
  ck "knob=0" "$knobv6" 0
  ;;
defer)
  value_now_into drain_msv1 "$V" 12 "$OUT/drain_ms_1.txt" '^[0-9]+$' "the ifree_drain_ms knob on $V" "echo 0 > /sys/module/mxfs/parameters/ifree_drain_ms; cat /sys/module/mxfs/parameters/ifree_drain_ms"
  ck "ifree_drain_ms=0" "$drain_msv1" 0
  pre=$(rs 20 "$V" "$SINCE_LOAD | grep -a 'P-INACT-CERT-TOTAL' | tail -1 | grep -ao 'evict_ok=[0-9]*' | tr -dc '0-9'"); pre=${pre:-0}
  mkrm 4 > /dev/null
  window_count_into wc14 "$V" 20 "$MARK" 'P128-INACT-DEFER' "P128-INACT-DEFER (grant   certificate kept cached)"
  ckge "P128-INACT-DEFER (grant + certificate kept cached)" "$wc14" 4
  window_count_into wc15 "$V" 20 "$MARK" 'P-INACT-CERT ino=[0-9]* installed=1' "P-INACT-CERT installed=1"
  ck_installed "P-INACT-CERT installed=1" "$wc15" 4
  value_now_into drain_msv2 "$V" 12 "$OUT/drain_ms_2.txt" '^[0-9]+$' "the ifree_drain_ms knob on $V" "echo 2000 > /sys/module/mxfs/parameters/ifree_drain_ms; cat /sys/module/mxfs/parameters/ifree_drain_ms"
  ck "ifree_drain_ms restored" "$drain_msv2" 2000
  # evict the shells: the certificate is retired by mxfs_dlm_evict's
  # begin-release after the evict assertion; then a filler workload of
  # 1100 creates drives the periodic census past a 1024 boundary so
  # P-INACT-CERT-TOTAL prints evict_ok.
  # sess474 (chain 108 s473c): the filler REUSES the arm's just-freed inode
  # numbers (P2G-LOGWHO comm=bash xfs_icreate on the arm's inos 7 s after
  # their DEFER) and its own unpublished try=7 refusals then carried the
  # arm's numbers — finish()'s scoped check reads only up to $FMARK.
  rs 12 "$V" "echo '$FMARK' > /dev/kmsg" >/dev/null
  rs 60 "$V" "sync; echo 2 > /proc/sys/vm/drop_caches; sleep 2; mkdir -p $DIR/fill && for i in \$(seq 1 1100); do : > $DIR/fill/x\$i; done; sync; rm -rf $DIR/fill; sync; sleep 2; echo fill_ok" | grep -q fill_ok || { echo "  FAIL filler workload"; fails=$((fails+1)); }
  # sess473: both reads are whole-ring (the s472u lap compared a whole-ring pre
  # with a post-mark post and got -3294)
  post=$(rs 20 "$V" "$SINCE_LOAD | grep -a 'P-INACT-CERT-TOTAL' | tail -1 | grep -ao 'evict_ok=[0-9]*' | tr -dc '0-9'"); post=${post:-0}
  echo "  INFO evict_ok pre=$pre post=$post"
  ckge "evict_ok grew by the deferred certificates" "$(( post - pre ))" 4
  window_count_into wc16 "$V" 20 "$MARK" 'P-INACT-CERT-EVICT ino=' "no P-INACT-CERT-EVICT anomaly (cls =0)"
  ck   "no P-INACT-CERT-EVICT anomaly (cls!=0)" "$wc16" 0
  window_count_into wc17 "$V" 20 "$MARK" 'P-INACT-CERT-LOST' "no LOST"
  ck   "no LOST" "$wc17" 0
  window_count_into shutv5 "$V" 20 "$MARK" 'Filesystem has been shut down\|P-SESSION-POISON\|force-shutdown' "shut"
  ck   "no shutdown" "$shutv5" 0
  ;;
reuse)
  value_now_into knobv7 "$V" 12 "$OUT/knob_7.txt" '^[0-9]+$' "the inact_cert_inject knob on $V" "echo 0 > /sys/module/mxfs/parameters/inact_cert_inject; cat /sys/module/mxfs/parameters/inact_cert_inject"
  ck "knob=0" "$knobv7" 0
  pre=$(rs 20 "$V" "$SINCE_LOAD | grep -a 'P-INACT-CERT-TOTAL' | tail -1 | grep -ao 'evict_ok=[0-9]*' | tr -dc '0-9'"); pre=${pre:-0}
  mkrm 4 > /dev/null
  cp "$OUT/inos.txt" "$OUT/inos_cycle1.txt"
  window_count_into wc18 "$V" 20 "$MARK" 'P128-INACT-DEFER' "cycle 1: P128-INACT-DEFER"
  ckge "cycle 1: P128-INACT-DEFER" "$wc18" 4
  window_count_into wc19 "$V" 20 "$MARK" 'P-INACT-CERT ino=[0-9]* installed=1' "cycle 1: P-INACT-CERT installed=1"
  ck_installed "cycle 1: P-INACT-CERT installed=1" "$wc19" 4
  # Retire cycle 1's deferred certificates BEFORE the numbers are reissued,
  # so the second incarnation of each number starts from a clean shell.
  evict
  mkrm 4 > /dev/null
  cp "$OUT/inos.txt" "$OUT/inos_cycle2.txt"
  reused=$(grep -acxFf "$OUT/inos_cycle1.txt" "$OUT/inos_cycle2.txt")
  echo "  INFO cycle1=[$(tr '\n' ' ' < "$OUT/inos_cycle1.txt")] cycle2=[$(tr '\n' ' ' < "$OUT/inos_cycle2.txt")] reused=$reused"
  ckge "cycle 2 reused numbers from cycle 1 (non-vacuous)" "$reused" 1
  window_count_into wc20 "$V" 20 "$MARK" 'P128-INACT-DEFER' "cycle 2: P128-INACT-DEFER"
  ckge "cycle 2: P128-INACT-DEFER" "$wc20" 8
  window_count_into wc21 "$V" 20 "$MARK" 'P-INACT-CERT ino=[0-9]* installed=1' "cycle 2: P-INACT-CERT installed=1"
  ck_installed "cycle 2: P-INACT-CERT installed=1" "$wc21" 8
  evict
  # Force the periodic census print (1024-create boundary), as the defer arm
  # does; the filler's own unpublished refusals are outside the arm's inos.
  rs 12 "$V" "echo '$FMARK' > /dev/kmsg" >/dev/null
  rs 60 "$V" "mkdir -p $DIR/fill && for i in \$(seq 1 1100); do : > $DIR/fill/x\$i; done; sync; rm -rf $DIR/fill; sync; sleep 2; echo fill_ok" | grep -q fill_ok || { echo "  FAIL filler workload"; fails=$((fails+1)); }
  post=$(rs 20 "$V" "$SINCE_LOAD | grep -a 'P-INACT-CERT-TOTAL' | tail -1 | grep -ao 'evict_ok=[0-9]*' | tr -dc '0-9'"); post=${post:-0}
  echo "  INFO evict_ok pre=$pre post=$post"
  ckge "evict_ok grew by both cycles' deferred certificates" "$(( post - pre ))" 8
  window_count_into wc22 "$V" 20 "$MARK" 'P-INACT-CERT-EVICT ino=' "no P-INACT-CERT-EVICT anomaly (cls =0) on either incarnation"
  ck   "no P-INACT-CERT-EVICT anomaly (cls!=0) on either incarnation" "$wc22" 0
  window_count_into wc23 "$V" 20 "$MARK" 'P-INACT-CERT-EVICT-CORRUPT' "no P-INACT-CERT-EVICT-CORRUPT"
  ck   "no P-INACT-CERT-EVICT-CORRUPT" "$wc23" 0
  window_count_into wc24 "$V" 20 "$MARK" 'P-INACT-CERT-LOST' "no LOST"
  ck   "no LOST" "$wc24" 0
  window_count_into shutv6 "$V" 20 "$MARK" 'Filesystem has been shut down\|P-SESSION-POISON\|force-shutdown' "shut"
  ck   "no shutdown" "$shutv6" 0
  ;;
foreign)
  value_now_into knobv8 "$V" 12 "$OUT/knob_8.txt" '^[0-9]+$' "the inact_cert_inject knob on $V" "echo 2 > /sys/module/mxfs/parameters/inact_cert_inject; cat /sys/module/mxfs/parameters/inact_cert_inject"
  ck "knob=2" "$knobv8" 2
  # sess474: the injection lives at the SYNC INACT-EXREL revoke (see the
  # header) — the eager durable chain destages the freed dinode inside the
  # inactivation so the grant is retired THERE, not by a later evict.
  value_now_into eagerv1 "$V" 12 "$OUT/eager_1.txt" '^[0-9]+$' "the ifree_eager_durable knob on $V" "echo 1 > /sys/module/mxfs/parameters/ifree_eager_durable; cat /sys/module/mxfs/parameters/ifree_eager_durable"
  ck "ifree_eager_durable=1" "$eagerv1" 1
  mkrm 1 > /dev/null
  window_count_into wc25 "$V" 20 "$MARK" "P128-INACT-DEFER ino=$(head -1 "$OUT/inos.txt") pin=" "sync retirement reached (no P128-INACT-DEFER for the arm s ino)"
  ck   "sync retirement reached (no P128-INACT-DEFER for the arm's ino)" "$wc25" 0
  window_count_into wc26 "$V" 20 "$MARK" 'P-INACT-CERT-REVOKE-MISS ino=[0-9]* rv=2' "P-INACT-CERT-REVOKE-MISS rv=2"
  ckge "P-INACT-CERT-REVOKE-MISS rv=2" "$wc26" 1
  window_count_into wc27 "$V" 20 "$MARK" 'P-INACT-CERT-FOREIGN' "P-INACT-CERT-FOREIGN"
  ckge "P-INACT-CERT-FOREIGN" "$wc27" 1
  window_count_into shutv7 "$V" 20 "$MARK" 'Filesystem has been shut down\|P-SESSION-POISON\|force-shutdown' "shut"
  ckge "shutdown (fail closed)" "$shutv7" 1
  value_now_into eagerv2 "$V" 12 "$OUT/eager_2.txt" '^[0-9]+$' "the ifree_eager_durable knob on $V" "echo 0 > /sys/module/mxfs/parameters/ifree_eager_durable; cat /sys/module/mxfs/parameters/ifree_eager_durable"
  ck "ifree_eager_durable=0" "$eagerv2" 0
  knob 0 > /dev/null
  ;;
gone)
  value_now_into knobv9 "$V" 12 "$OUT/knob_9.txt" '^[0-9]+$' "the inact_cert_inject knob on $V" "echo 5 > /sys/module/mxfs/parameters/inact_cert_inject; cat /sys/module/mxfs/parameters/inact_cert_inject"
  ck "knob=5" "$knobv9" 5
  value_now_into eagerv3 "$V" 12 "$OUT/eager_3.txt" '^[0-9]+$' "the ifree_eager_durable knob on $V" "echo 1 > /sys/module/mxfs/parameters/ifree_eager_durable; cat /sys/module/mxfs/parameters/ifree_eager_durable"
  ck "ifree_eager_durable=1" "$eagerv3" 1   # sess474: sync retirement (see foreign)
  mkrm 1 > /dev/null
  window_count_into wc28 "$V" 20 "$MARK" "P128-INACT-DEFER ino=$(head -1 "$OUT/inos.txt") pin=" "sync retirement reached (no P128-INACT-DEFER for the arm s ino)"
  ck   "sync retirement reached (no P128-INACT-DEFER for the arm's ino)" "$wc28" 0
  window_count_into wc29 "$V" 20 "$MARK" 'P-INACT-CERT-LOST ino=[0-9]* by=begin_release' "P-INACT-CERT-LOST by=begin_release"
  ckge "P-INACT-CERT-LOST by=begin_release" "$wc29" 1
  window_count_into wc30 "$V" 20 "$MARK" 'P-INACT-CERT-GONE' "P-INACT-CERT-GONE"
  ckge "P-INACT-CERT-GONE" "$wc30" 1
  window_count_into shutv8 "$V" 20 "$MARK" 'Filesystem has been shut down\|P-SESSION-POISON\|force-shutdown' "shut"
  ckge "shutdown (fail closed)" "$shutv8" 1
  value_now_into eagerv4 "$V" 12 "$OUT/eager_4.txt" '^[0-9]+$' "the ifree_eager_durable knob on $V" "echo 0 > /sys/module/mxfs/parameters/ifree_eager_durable; cat /sys/module/mxfs/parameters/ifree_eager_durable"
  ck "ifree_eager_durable=0" "$eagerv4" 0
  knob 0 > /dev/null
  ;;
evictforeign)
  value_now_into knobv10 "$V" 12 "$OUT/knob_10.txt" '^[0-9]+$' "the inact_cert_inject knob on $V" "echo 6 > /sys/module/mxfs/parameters/inact_cert_inject; cat /sys/module/mxfs/parameters/inact_cert_inject"
  ck "knob=6" "$knobv10" 6
  mkrm 1 > /dev/null
  window_count_into wc31 "$V" 20 "$MARK" "P128-INACT-DEFER ino=$(head -1 "$OUT/inos.txt") pin=" "P128-INACT-DEFER (deferred retirement on the arm s ino)"
  ckge "P128-INACT-DEFER (deferred retirement on the arm's ino)" "$wc31" 1
  window_count_into wc32 "$V" 20 "$MARK" 'P-INACT-CERT ino=[0-9]* installed=1' "P-INACT-CERT installed=1"
  ck_installed "P-INACT-CERT installed=1" "$wc32" 1
  evict
  window_count_into wc33 "$V" 20 "$MARK" 'P-INACT-CERT-EVICT ino=[0-9]* cls=2' "P-INACT-CERT-EVICT cls=2"
  ckge "P-INACT-CERT-EVICT cls=2" "$wc33" 1
  window_count_into wc34 "$V" 20 "$MARK" 'P-INACT-CERT-EVICT-CORRUPT' "P-INACT-CERT-EVICT-CORRUPT"
  ckge "P-INACT-CERT-EVICT-CORRUPT" "$wc34" 1
  window_count_into shutv9 "$V" 20 "$MARK" 'Filesystem has been shut down\|P-SESSION-POISON\|force-shutdown' "shut"
  ckge "shutdown (fail closed)" "$shutv9" 1
  knob 0 > /dev/null
  ;;
evictactive)
  value_now_into knobv11 "$V" 12 "$OUT/knob_11.txt" '^[0-9]+$' "the inact_cert_inject knob on $V" "echo 7 > /sys/module/mxfs/parameters/inact_cert_inject; cat /sys/module/mxfs/parameters/inact_cert_inject"
  ck "knob=7" "$knobv11" 7
  mkrm 1 > /dev/null
  window_count_into wc35 "$V" 20 "$MARK" "P128-INACT-DEFER ino=$(head -1 "$OUT/inos.txt") pin=" "P128-INACT-DEFER (deferred retirement on the arm s ino)"
  ckge "P128-INACT-DEFER (deferred retirement on the arm's ino)" "$wc35" 1
  window_count_into wc36 "$V" 20 "$MARK" 'P-INACT-CERT ino=[0-9]* installed=1' "P-INACT-CERT installed=1"
  ck_installed "P-INACT-CERT installed=1" "$wc36" 1
  evict
  window_count_into wc37 "$V" 20 "$MARK" 'P-INACT-CERT-EVICT ino=[0-9]* cls=3' "P-INACT-CERT-EVICT cls=3"
  ckge "P-INACT-CERT-EVICT cls=3" "$wc37" 1
  window_count_into wc38 "$V" 20 "$MARK" 'P-INACT-CERT-EVICT-CORRUPT' "P-INACT-CERT-EVICT-CORRUPT"
  ckge "P-INACT-CERT-EVICT-CORRUPT" "$wc38" 1
  window_count_into shutv10 "$V" 20 "$MARK" 'Filesystem has been shut down\|P-SESSION-POISON\|force-shutdown' "shut"
  ckge "shutdown (fail closed)" "$shutv10" 1
  knob 0 > /dev/null
  ;;
escalate)
  value_now_into knobv12 "$V" 12 "$OUT/knob_12.txt" '^[0-9]+$' "the inact_cert_inject knob on $V" "echo 1 > /sys/module/mxfs/parameters/inact_cert_inject; cat /sys/module/mxfs/parameters/inact_cert_inject"
  ck "knob=1" "$knobv12" 1
  mkrm 1 > /dev/null
  window_count_into wc39 "$V" 20 "$MARK" 'P-INACT-CERT-REFUSED ino=' "first refusal"
  ckge "first refusal" "$wc39" 1
  # 5 s first retry + 7 more at 30 s = 8 refusals by ~215 s; the 9th at ~245 s escalates
  T0=$(date +%s); esc=0
  while [ $(( $(date +%s) - T0 )) -lt 300 ]; do sleep 15; window_count_into esc "$V" 20 "$MARK" 'P-INACT-CERT-REFUSED-ESCALATE' "esc"; [ "${esc:-0}" -ge 1 ] && break; done
  echo "  INFO window_count_into refusals "$V" 20 "$MARK" 'P-INACT-CERT-REFUSED ino=' "refusals" escalate=$esc after $(( $(date +%s) - T0 )) s"
  ckge "P-INACT-CERT-REFUSED-ESCALATE" "${esc:-0}" 1
  window_count_into wc40 "$V" 20 "$MARK" 'P-INACT-CERT-REFUSED ino=' "refusals before escalation"
  ckge "refusals before escalation" "$wc40" 9
  window_count_into shutv11 "$V" 20 "$MARK" 'Filesystem has been shut down\|P-SESSION-POISON\|force-shutdown' "shut"
  ckge "shutdown (fail closed)" "$shutv11" 1
  window_count_into wc41 "$V" 20 "$MARK" 'P89-REAP-DONE' "the free never happened (no P89-REAP-DONE)"
  ck   "the free never happened (no P89-REAP-DONE)" "$wc41" 0
  knob 0 > /dev/null
  ;;
*) echo "unknown arm $ARM"; exit 2 ;;
esac
finish
