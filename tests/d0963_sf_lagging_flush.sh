#!/bin/bash
# d0963_sf_lagging_flush.sh — the deleter's own lagging flush, read back by
# its next removal's refresh as if it were a peer's image.
#
# D-PEER-STATS-A-NAME-THE-DELETER-UNLINKED-AND-SYNCED-WHILE-ITS-DIRECTORY-
# PUBLICATION-IS-IN-FLIGHT-0963.  The board capture (tests/evidence/
# run_cache_coherency_20260912T161757Z, dir ino 2246 on test2) showed the chain:
# the deleter's shortform fork was refreshed against the platter before every
# removal; xfsaild's write of the directory inode (all nine P56-DIRWRITEs by
# xfsaild/sda, EX held) landed one removal behind; the refresh read that own,
# older image; the 3-way merge, whose base predated every entry the deleter had
# created (the directory had been block-format since the creates, so no
# shortform base was ever captured), classified the just-removed entry as a
# peer's fresh add and put it back (P-SFM-READD, P-SFMERGE 146->166); the
# resurrected name was published as a dangling dirent naming a freed inode.
#
# The race between the asynchronous write and the coherent read is what a
# quiet rig loses (0/20 laps of the board criterion, s605b; 0/20 of the
# synthetic churn, s604a).  This harness makes the in-flight window
# deterministic with two test knobs on the deleter B and otherwise takes the
# real path:
#   dbg_ail_pin_ino     keeps xfsaild off the directory inode during the churn,
#                       so the platter still holds the creator's small image
#                       (the base) when the directory shrinks back to shortform;
#   sf_fastpath_adopt   makes every cached-EX shortform removal take the platter
#                       refresh (the P174 stale-gen gate's own path, entered on
#                       the board only after a peer tenure and a skipped rebuild);
#   dbg_iflush_pause_*  then holds xfsaild's write of the directory inode for a
#                       few seconds after the copy-in, and debugfs ail_push
#                       starts that write on demand.
# Shape, per lap (A = creator, B = deleter):
#   A: mkdir D, three seed files (A holds EX; D is shortform).
#   B: lists D (reload: the merge base = the 3-entry image), pins xfsaild off
#      D's inode, creates N files (D goes block format), removes them in order
#      until D is shortform again (stat size < 4096).
#   B: unpins, arms the pause, kicks xfsaild: the k-entry image is copied into
#      the cluster buffer and its write is held.  B removes the next file V:
#      the refresh reads the platter (still the 3-entry image, so the base
#      stays what it was) and V leaves the in-core fork.  The held write lands.
#      B removes the next file W: the refresh now reads B's OWN k-entry image,
#      which still names V.
#   With sf_own_image=0 (MODE=control, the pre-0.84.18 behaviour on the same
#   build) the merge re-adds V (P-SFM-READD) and V is published: after B's
#   sync it lists on B and, cold, on A, while it resolves on neither.  With
#   sf_own_image=1 (MODE=fix) the refresh recognises its own image
#   (P963-SF-OWN-IMAGE), keeps the fork, and V is gone from both nodes.
# Both modes assert the instrument fired (pause seen, kick seen) so a clean
# lap is never vacuous.  Knobs are restored at the end and on abort.  The
# control arm leaves its directory in place (a dangling dirent cannot be
# removed by rm -rf; its rc is reported).
#
# Usage: tests/d0963_sf_lagging_flush.sh <label> [LAPS=3] [N=64]   (MODE=fix|control)
# Exit 0 = the mode's expectation met on every lap, 1 = not met, 2 = ABORT.
#
# derived time budget per lap: setup ~3 s + N creates ~1 s + removals to
# shortform ~2 s (a platter read per removal under sf_fastpath_adopt) + pause
# PAUSE_MS (3000) + landing wait 1 s + two removals + sync ~1 s + verify on
# both nodes ~3 s + ssh dispatch ~4 s => ~18 s at N=64; 3 laps = 54 s,
# bounded at 180 s.
set -u
LABEL=${1:?label}
LAPS=${2:-3}
N=${3:-64}
MODE=${MODE:-fix}
PAUSE_MS=${PAUSE_MS:-3000}
case "$MODE" in fix|control) ;; *) echo "ABORT: MODE must be fix or control"; exit 2;; esac
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
A=${MXFS_NODE_LIST%%,*}
B=${MXFS_NODE_LIST##*,}
SSH=tools/mxfs_sshpass.sh
MNT=${MXFS_MNT:-/mnt/shared}
P=/sys/module/mxfs/parameters
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_d0963lag_${MODE}_$LABEL
mkdir -p "$OUT"
# rs/rsx/measure/capture_require/value_now_into/window_into (tests/lib/rig.sh):
# every capture a verdict is taken from crosses the boundary in the parent
# shell first; a failed acquisition is an ABORT, never a count of zero or an
# empty value.
. "$(dirname "$0")/lib/rig.sh"
fld() { echo "$1" | grep -ao "$2=[0-9-]*" | head -1 | cut -d= -f2; }
restore() { rs 20 "$B" "echo 0 > $P/sfm_dbg; echo 0 > $P/sf_fastpath_adopt; echo 1 > $P/sf_own_image; echo 0 > $P/dbg_ail_pin_ino; echo 0 > $P/dbg_iflush_pause_ino" >/dev/null; }
t0=$(date +%s)
el() { echo $(( $(date +%s) - t0 )); }
fails=0
ck() { if [ "$2" = "$3" ]; then echo "  ok   $1 ($2)"; else echo "  FAIL $1 (got [$2] want [$3])"; fails=$((fails+1)); fi; }
SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
echo "=== d0963_sf_lagging_flush label=$LABEL mode=$MODE laps=$LAPS n=$N pause_ms=$PAUSE_MS sv=$SV out=$OUT $(date -u +%FT%TZ) ==="

KNOB=$([ "$MODE" = control ] && echo 0 || echo 1)
for n in $A $B; do
    st=$(rs 25 "$n" "echo sv=\$(cat /sys/module/mxfs/srcversion) mnt=\$(grep -c ' $MNT mxfs ' /proc/mounts) knobs=\$(for k in sfm_dbg sf_own_image sf_fastpath_adopt dbg_ail_pin_ino dbg_iflush_pause_ino dbg_iflush_pause_ms dbg_iflush_pause_n sf_own_image_hits; do test -w $P/\$k && printf 1 || printf 0; done) push=\$(ls /sys/kernel/debug/mxfs/*/ail_push 2>/dev/null | wc -l)" | tr -d '\n')
    echo "  INFO $n $st"
    [[ "$st" == *"sv=$SV"* ]] || { echo "ABORT: $n srcversion != tree $SV ($st)"; exit 2; }
    [[ "$st" == *"mnt=1"* ]]  || { echo "ABORT: $n not mounted ($st)"; exit 2; }
    [[ "$st" == *"knobs=11111111"* ]] || { echo "ABORT: $n lacks a knob this harness needs (build older than 0.84.18): $st"; exit 2; }
    [[ "$st" == *"push=1"* ]] || { echo "ABORT: $n has no debugfs ail_push"; exit 2; }
done
rs 20 "$B" "echo 1 > $P/sfm_dbg; echo 1 > $P/sf_fastpath_adopt; echo $KNOB > $P/sf_own_image; echo 0 > $P/dbg_iflush_pause_ino; echo $PAUSE_MS > $P/dbg_iflush_pause_ms; echo 0 > $P/sf_own_image_hits; echo 0 > $P/sf_own_image_recorded; echo 0 > $P/sf_release_base; echo knobs=\$(cat $P/sfm_dbg),\$(cat $P/sf_fastpath_adopt),\$(cat $P/sf_own_image),\$(cat $P/dbg_iflush_pause_ms)" | sed "s/^/  INFO $B /"
wprobe=$(rs 40 "$A" "mkdir -p $MNT/.d0963probe.$$ 2>&1 && rmdir $MNT/.d0963probe.$$ 2>&1 && echo WRITABLE || echo NOTWRITABLE")
[[ "$wprobe" == *WRITABLE* ]] && [[ "$wprobe" != *NOTWRITABLE* ]] || { echo "ABORT: $A mounted but not writable: $wprobe"; restore; exit 2; }

BASEDIR=$MNT/d0963lag_$LABEL
for r in $(seq 1 "$LAPS"); do
    D=$BASEDIR/lap$r
    MK="D0963LAG-$LABEL-$$-r$r"
    for n in $A $B; do rs 15 "$n" "echo '$MK' > /dev/kmsg" >/dev/null; done
    # The counters are per lap: P963-SF-OWN-IMAGE prints only its first 32
    # hits and then one in 500, so the printed line proves nothing after the
    # first lap (s605e laps 2 and 3 printed none while the counter advanced
    # 19 -> 57 -> 95); the verdict reads the counter, reset here.
    rs 20 "$B" "echo 0 > $P/sf_own_image_hits; echo 0 > $P/sf_own_image_recorded; echo 0 > $P/sf_release_base" >/dev/null
    echo "--- lap $r at +$(el)s ---"
    # A creates the directory and its seeds and keeps EX cached.
    ca=$(rs 40 "$A" "mkdir -p $D && : > $D/seedA_1 && : > $D/seedA_2 && : > $D/seedA_3 && echo CA ok=1 ino=\$(stat -c %i $D) size=\$(stat -c %s $D)")
    echo "  $ca"
    [ "$(fld "$ca" ok)" = 1 ] || { echo "ABORT: A could not create the directory ($ca)"; restore; exit 2; }
    INO=$(fld "$ca" ino)
    # B lists it (its reload captures the 3-entry image as the merge base),
    # then pins xfsaild off the directory inode for the churn.
    lb=$(rs 40 "$B" "n=\$(ls -A $D | wc -l); echo $INO > $P/dbg_ail_pin_ino; echo LB listed=\$n ino=\$(stat -c %i $D) pin=\$(cat $P/dbg_ail_pin_ino)")
    echo "  $lb"
    [ "$(fld "$lb" listed)" = 3 ] && [ "$(fld "$lb" ino)" = "$INO" ] && [ "$(fld "$lb" pin)" = "$INO" ] || { echo "ABORT: B's view of the directory or the pin is wrong ($lb)"; restore; exit 2; }
    # B creates N (block format), then removes in order until shortform again.
    cb=$(rs 90 "$B" "e=0; for i in \$(seq 1 $N); do : > $D/nodeB_file\$i 2>/dev/null || e=\$((e+1)); done; echo CB cerr=\$e size=\$(stat -c %s $D)")
    echo "  $cb"
    [ "$(fld "$cb" cerr)" = 0 ] && [ "$(fld "$cb" size)" -ge 4096 ] || { echo "ABORT: B's creates did not take the directory to block format ($cb)"; restore; exit 2; }
    rb=$(rs 120 "$B" "k=0; e=0; while [ \$k -lt $((N-4)) ]; do k=\$((k+1)); rm -f $D/nodeB_file\$k 2>/dev/null || e=\$((e+1)); s=\$(stat -c %s $D); [ \$s -lt 4096 ] && break; done; echo RB removed=\$k derr=\$e size=\$s remaining=\$(ls -A $D | wc -l)")
    echo "  $rb"
    K=$(fld "$rb" removed)
    [ "$(fld "$rb" derr)" = 0 ] && [ "$(fld "$rb" size)" -lt 4096 ] || { echo "ABORT: the directory did not shrink back to shortform ($rb)"; restore; exit 2; }
    V=nodeB_file$((K+1)); W=nodeB_file$((K+2))
    # Unpin, arm the pause, kick xfsaild: the k-entry image is copied in and
    # its write is held.  Prove the hold began before going on.
    arm=$(rs 40 "$B" "echo 0 > $P/dbg_ail_pin_ino; echo 0 > $P/dbg_iflush_pause_n; echo $INO > $P/dbg_iflush_pause_ino; echo 1 > /sys/kernel/debug/mxfs/*/ail_push; i=0; while [ \$i -lt 30 ]; do [ \$(cat $P/dbg_iflush_pause_n) -ge 1 ] && break; sleep 0.1; i=\$((i+1)); done; echo ARM pause_n=\$(cat $P/dbg_iflush_pause_n) waited_ds=\$i")
    echo "  $arm"
    PAUSE_SEEN=$(fld "$arm" pause_n)
    # V: refresh reads the platter (creator's image), V leaves the in-core fork.
    value_now_into rv "$B" 40 "$OUT/rv_rv_1.txt" '^RV ' "rv on $B" "rm -f $D/$V && echo RV ok=1 size=\$(stat -c %s $D) remaining=\$(ls -A $D | wc -l)"
    echo "  $rv"
    # Let the held write land, then W: the refresh reads B's own k-entry image.
    sleep $(( PAUSE_MS / 1000 + 1 ))
    value_now_into rw "$B" 40 "$OUT/rv_rw_2.txt" '^RW ' "rw on $B" "rm -f $D/$W && echo 0 > $P/dbg_iflush_pause_ino && echo RW ok=1 pause_n=\$(cat $P/dbg_iflush_pause_n) size=\$(stat -c %s $D) remaining=\$(ls -A $D | wc -l) v_listed=\$(ls -A $D | grep -c '^$V\$') v_stat=\$(test -e $D/$V && echo 1 || echo 0) own_hits=\$(cat $P/sf_own_image_hits) recorded=\$(cat $P/sf_own_image_recorded)"
    echo "  $rw"
    # Publish and read back cold on the creator.
    value_now_into sb "$B" 60 "$OUT/rv_sb_3.txt" '^SB ' "sb on $B" "sync; echo SB v_listed=\$(ls -A $D | grep -c '^$V\$') v_stat=\$(test -e $D/$V && echo 1 || echo 0) w_listed=\$(ls -A $D | grep -c '^$W\$') remaining=\$(ls -A $D | wc -l)"
    echo "  $sb"
    value_now_into va "$A" 60 "$OUT/rv_va_4.txt" '^VA ' "va on $A" "echo 3 > /proc/sys/vm/drop_caches; echo VA v_listed=\$(ls -A $D | grep -c '^$V\$') v_stat=\$(test -e $D/$V && echo 1 || echo 0) w_listed=\$(ls -A $D | grep -c '^$W\$') remaining=\$(ls -A $D | wc -l)"
    echo "  $va"
    dm=""
    for n in $A $B; do
        dd=$(rs 60 "$n" "dmesg | awk '/$MK/{f=1} f' > /tmp/d0963lag_win.txt
            echo DM node=$n readd=\$(grep -a 'P-SFM-READD' /tmp/d0963lag_win.txt | grep -ac 'ino=$INO ') drop=\$(grep -ac 'P-SFM-DROP' /tmp/d0963lag_win.txt) sfmerge=\$(grep -a 'P-SFMERGE' /tmp/d0963lag_win.txt | grep -ac 'ino=$INO ') own=\$(grep -a 'P963-SF-OWN-IMAGE' /tmp/d0963lag_win.txt | grep -ac 'ino=$INO ') pause=\$(grep -a 'P963-IFLUSH-PAUSE ' /tmp/d0963lag_win.txt | grep -ac 'ino=$INO ') pause_end=\$(grep -ac 'P963-IFLUSH-PAUSE-END' /tmp/d0963lag_win.txt) kick=\$(grep -ac 'P963-AIL-PUSH' /tmp/d0963lag_win.txt) relbase=\$(grep -ac 'P963-SF-RELEASE-BASE' /tmp/d0963lag_win.txt) dirwrite=\$(grep -a 'P56-DIRWRITE' /tmp/d0963lag_win.txt | grep -ac 'ino=$INO ') shut=\$(grep -ac 'Shutting down filesystem' /tmp/d0963lag_win.txt) corrupt=\$(grep -ac 'Corruption of in-memory' /tmp/d0963lag_win.txt)
            grep -a 'P-SFM-READD\|P963-SF-OWN-IMAGE\|P-SFMERGE' /tmp/d0963lag_win.txt | grep -a 'ino=$INO ' | head -4 | cut -c1-230")
        echo "$dd" | sed 's/^/     /'
        dm="$dm"$'\n'"$dd"
        rs 60 "$n" "dmesg | awk '/$MK/{f=1} f'" > "$OUT/dmesg_${n}_lap$r.txt"
    done
    { echo "$ca"; echo "$lb"; echo "$cb"; echo "$rb"; echo "$arm"; echo "$rv"; echo "$rw"; echo "$sb"; echo "$va"; echo "$dm"; } > "$OUT/lap$r.txt"
    lb_line=$(echo "$dm" | grep -a "^DM node=$B"); la_line=$(echo "$dm" | grep -a "^DM node=$A")
    echo "--- verdict lap $r ($MODE) ---"
    ck "the held write began before V was removed (pause seen)" "$([ "${PAUSE_SEEN:-0}" -ge 1 ] && echo 1 || echo 0)" "1"
    ck "xfsaild was kicked through debugfs (P963-AIL-PUSH on B)" "$([ "$(fld "$lb_line" kick)" -ge 1 ] && echo 1 || echo 0)" "1"
    ck "the held write ended (P963-IFLUSH-PAUSE-END on B)" "$([ "$(fld "$lb_line" pause_end)" -ge 1 ] && echo 1 || echo 0)" "1"
    ck "B published the directory during the lap (P56-DIRWRITE for it)" "$([ "$(fld "$lb_line" dirwrite)" -ge 1 ] && echo 1 || echo 0)" "1"
    ck "V was removed (rm returned 0)" "$(fld "$rv" ok)" "1"
    ck "W was removed (rm returned 0)" "$(fld "$rw" ok)" "1"
    ck "no shutdown on B" "$(fld "$lb_line" shut)" "0"
    ck "no shutdown on A" "$(fld "$la_line" shut)" "0"
    if [ "$MODE" = control ]; then
        ck "control: the merge re-added V on B (P-SFM-READD for the directory)" "$([ "$(fld "$lb_line" readd)" -ge 1 ] && echo 1 || echo 0)" "1"
        ck "control: a merge was installed on B (P-SFMERGE for the directory)" "$([ "$(fld "$lb_line" sfmerge)" -ge 1 ] && echo 1 || echo 0)" "1"
        ck "control: V lists on B after the sync (the resurrected dirent)" "$(fld "$sb" v_listed)" "1"
        ck "control: V does not resolve on B (dangling: stat fails)" "$(fld "$sb" v_stat)" "0"
        ck "control: V lists on A cold (the dangling dirent was published)" "$(fld "$va" v_listed)" "1"
        ck "control: W is gone on both nodes" "$(fld "$sb" w_listed)$(fld "$va" w_listed)" "00"
    else
        echo "  INFO fix: P963-SF-OWN-IMAGE lines printed this lap on B = $(fld "$lb_line" own) (budgeted: first 32 then one in 500; the counter below is the evidence)"
        ck "fix: the refresh recognised B's own image at least once this lap (sf_own_image_hits >= 1 after W)" "$([ "$(fld "$rw" own_hits)" -ge 1 ] && echo 1 || echo 0)" "1"
        ck "fix: images were recorded at flush on B this lap (sf_own_image_recorded >= 1)" "$([ "$(fld "$rw" recorded)" -ge 1 ] && echo 1 || echo 0)" "1"
        ck "fix: the merge re-added nothing on B (no P-SFM-READD for the directory)" "$(fld "$lb_line" readd)" "0"
        ck "fix: V is gone on B after the sync" "$(fld "$sb" v_listed)" "0"
        ck "fix: V is gone on A cold" "$(fld "$va" v_listed)" "0"
        ck "fix: W is gone on both nodes" "$(fld "$sb" w_listed)$(fld "$va" w_listed)" "00"
        ck "fix: the remaining count agrees on both nodes" "$(fld "$sb" remaining)" "$(fld "$va" remaining)"
    fi
    if [ "$MODE" = fix ]; then
        rmrc=$(rs 60 "$A" "rm -rf $D; echo rmrc=\$?")
        echo "  INFO cleanup on A: $rmrc"
    else
        rmrc=$(rs 60 "$A" "rm -rf $D 2>&1 | head -2 | tr '\n' ' '; echo rmrc=\$?; test -d $D && echo left=1 || echo left=0")
        echo "  INFO control cleanup attempt on A: $(echo "$rmrc" | tr '\n' ' ') (a dangling dirent cannot be removed; the directory is left for inspection)"
    fi
done
restore
echo "=== d0963_sf_lagging_flush $LABEL ($MODE): fails=$fails wall=$(el)s out=$OUT $(date -u +%FT%TZ) ==="
[ "$fails" -eq 0 ]
