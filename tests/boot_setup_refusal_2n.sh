#!/bin/bash
# boot_setup_refusal_2n.sh — a TCP mount that read the bootstrap record IDLE,
# and finds a bootstrap term in progress by the time it opens the record for
# admission, must REFUSE; it must never mount past it.
#
# WHAT IS UNDER TEST.  On the TCP transport a mount reads the bootstrap record
# twice: v5_bootstrap_peek, before anything is built (it arms the RESUME and
# TAKEOVER arms), and v5_bootstrap_setup, after the disklock exists.  Until
# 0.90.40 the TCP mount treated EVERY setup failure as reportable
# (P-BOOT-TCP-NOT-GATED) and mounted on — measured on 2/net/mesh/drbd: an
# ordinary recovery ran over a sealed victim's slice in the middle of a
# bootstrap, and the bootstrap it belonged to became terminally REFUSED
# (D-TCP-MOUNT-CONTINUES-PAST-A-BOOTSTRAP-IN-PROGRESS-AND-RECOVERS-A-SEALED-
# VICTIM).  From 0.90.40 only a volume without the region (-ENOENT) mounts on;
# anything else logs P-BOOT-SETUP-REFUSED and unwinds.
#
# HOW THE SHAPE IS MADE, WITH NOTHING FABRICATED.  Setup refuses with neither a
# resume nor a takeover armed only when the record moved between the two reads:
# IDLE at the peek, a claimed term at setup.  Both nodes are destroyed with
# MXFS mounted (a real whole-cluster outage), then:
#   B  mounts first and is HELD right after its peek (bootstrap_inject=17,
#      TEST ONLY): the peek read the record IDLE, and B has registered nothing
#      yet (a B registered under its new key while A fences is the separate
#      shape MODE=regwindow grades);
#   A  mounts second and is the bootstrap owner: one frozen survivor scan, the
#      claim, the seal, phase-3 fencing, the adoption of K — and is HELD there
#      (bootstrap_inject=13, TEST ONLY), the record RECOVERING;
#   B  is released (the hold cleared) and reaches setup under A's term.
# Graded on B: P-BOOT-SETUP-REFUSED, B not mounted, and none of the lines the
# defect produced (P-BOOT-TCP-NOT-GATED, P163-RECOVERY-COMPLETE, a heartbeat
# slot claimed).  A lap where B's peek already saw the term
# (P-BOOT-TAKEOVER-CANDIDATE) or B failed before setup is VACUOUS: it never
# reached the branch.  Then A is released and must complete, B must join, every
# file both nodes fsynced before the outage must read back on both, and the
# volume must check clean.
#
# Budget (derived; a timeout is a failure): prep <= 300 (measured 45-58) +
# payload ~15 + destroy ~10 + boot both 60-150 + module copy ~30 + A to the
# hold (62 s dead window + 2.5 s poll + claim, seal, phase-3 fence, adoption:
# measured 65-75 for the claim) bound HOLD_BOUND 200 + B to its refusal (the
# READ KEYS sleep in flight when the delay is cleared, DELAY_MS, plus the
# unwind) bound DELAY_S + 60 + A's completion (two slice replays) and B's join
# bound JOIN_BOUND 300 each + read-back ~20 + two unmounts ~20 + chk_mxfs ~60.
# At the bounds: 300 + 15 + 10 + 150 + 30 + 200 + 160 + 600 + 20 + 20 + 60 =
# 1565; the caller's bound is 1600 s.
#
# MODE=concurrent instead mounts both nodes at once after the outage, with no
# knob at all, and grades that the term does not end REFUSED and both mount
# (on the first attempt or one retry): the shape of
# D-PAIR-OUTAGE-BOOTSTRAP-REFUSED-WHEN-A-VICTIM-HOST-REMOUNTS without the delay
# that widened it.  MODE=staggered starts B's mount STAGGER_S (45) after A's
# claim instead — a peer that boots later, arriving while A's seal scan waits
# out its dead window.
#
# Usage: tests/boot_setup_refusal_2n.sh <label>
# Env:   MODE (race|concurrent|staggered|regwindow), MXFS_NODE_LIST (test1,test2: A,B), MXFS_CONFIG (2/net/mesh/direct),
#        DELAY_S (100), HOLD_BOUND (200), JOIN_BOUND (300), NFILES (32)
# Exit 0 PASS, 1 FAIL, 2 ABORT/INFRA, 3 VACUOUS.
set -u
LABEL=${1:?label}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
export MXFS_CONFIG=${MXFS_CONFIG:-2/net/mesh/direct}
if [ "$(python3 tools/configuration.py get "$MXFS_CONFIG" transport)" != tcp ]; then
    echo "ABORT: the branch under test is the TCP mount's; $MXFS_CONFIG is not a TCP configuration"
    exit 2
fi
A=${MXFS_NODE_LIST%%,*}          # the bootstrap owner, held after K
B=${MXFS_NODE_LIST##*,}          # the mount that peeked IDLE
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
KO=/root/mxfs.ko.prep
NFILES=${NFILES:-32}
DELAY_S=${DELAY_S:-100}
HOLD_BOUND=${HOLD_BOUND:-200}
JOIN_BOUND=${JOIN_BOUND:-300}
CHK=/src/mxfs/tools/chk_mxfs
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_bsr_$LABEL
mkdir -p "$OUT"
fails=0
. "$(dirname "$0")/lib/rig.sh"
VIRSH="timeout 30 virsh -c qemu:///system"
MODARGS=${MXFS_MODARGS:-$(mxfs_rig_modargs)}
PARAM=/sys/module/mxfs/parameters
echo "=== boot_setup_refusal_2n label=$LABEL A(owner)=$A B(late setup)=$B config=$MXFS_CONFIG delay=${DELAY_S}s $(date -u +%FT%TZ) ==="
s0=$(date +%s)
el() { echo $(( $(date +%s) - s0 )); }
field(){ grep -aoE "(^| )$2=[^ ]*" "$1" | head -1 | cut -d= -f2; }
waitboot() {
    local n w=0
    for n in "$@"; do
        until [ "$(timeout 15 $SSH "$n" 'test -e /run/nologin && echo booting || echo ready' 2>/dev/null | grep -a 'booting\|ready' | tail -1)" = ready ] || [ $w -ge 40 ]; do
            w=$((w+1)); sleep 5
        done
    done
    echo "STAGE boot-wait $* polls=$w at +$(el)s"
}
deploy_ko() {
    local n=$1
    value_now_into got "$n" 150 "$OUT/${n}_md5.txt" '^[0-9a-f]{32}$' "the module copy on $n" \
        "for try in 1 2 3 4 5 6; do mountpoint -q /src && break; mkdir -p /src; timeout 12 mount -t nfs 192.168.120.1:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null; sleep 4; done; cp /src/mxfs/mxfs.ko $KO && md5sum $KO | cut -c1-32"
    ck "$n holds the tree build (md5)" "$got" "$MD5"
}
journal_into() {    # <node> <file> <mark>
    measure "$1" 60 "$2" '^JOURNAL_END$' "the kernel journal of $1" \
        "dmesg | sed -n '/$3/,\$p' | cut -c1-600; echo JOURNAL_END"
}

# ---- 0. the build carries the branch this lap grades
if [ "$(strings -a mxfs.ko | grep -c 'P-BOOT-SETUP-REFUSED')" = 0 ]; then
    echo "ABORT: mxfs.ko has no P-BOOT-SETUP-REFUSED branch (before 0.90.40); this lap grades the fix"
    echo "RESULT: ABORT label=$LABEL stage=build evidence=$OUT"; exit 2
fi
SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
MD5=$(md5sum mxfs.ko | cut -c1-32)
echo "build srcversion=$SV md5=$MD5"
waitboot "$A" "$B"
MXFS_FORCE_PREP=1 timeout 300 ./run.sh "$MXFS_CONFIG" prep_cluster > "$OUT/prep.log" 2>&1
prc=$?
echo "STAGE prep rc=$prc wall=$(el)s  $(grep -am1 'prep_cluster OK\|FAIL' "$OUT/prep.log" | cut -c1-140)"
[ $prc = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=prep evidence=$OUT"; exit 2; }
for n in "$A" "$B"; do
    value_now_into sv "$n" 30 "$OUT/${n}_srcversion.txt" '^[0-9A-F]{16,}$' "the loaded module's srcversion on $n" "cat /sys/module/mxfs/srcversion"
    ck "prep deployed the tree build on $n" "$sv" "$SV"
done
mxfs_dev_resolve "$A"; MXFS_DEV=$MXFS_DEV_RESOLVED; export MXFS_DEV

# ---- 1. both slices dirty, then the whole cluster dies
for n in "$A" "$B"; do
    measure "$n" 60 "$OUT/${n}_files.txt" '^FILES_END$' "$n's fsynced payload" \
        "d=$MNT/bsr_${LABEL}_$n; mkdir -p \$d && for i in \$(seq $NFILES); do printf 'bsr %s %s file %s\n' $LABEL $n \$i > \$d/f\$i; done; sync -f $MNT; cd \$d && sha256sum f* | sort; echo FILES_END"
    grep -av '^FILES_END' "$OUT/${n}_files.txt" > "$OUT/${n}_files_sha.txt"
    ck "$n fsynced $NFILES files before the outage" "$(grep -ac '^[0-9a-f]\{64\}  f' "$OUT/${n}_files_sha.txt")" "$NFILES"
done
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=payload evidence=$OUT"; exit 2; }
$VIRSH destroy "$A" > /dev/null 2>&1
$VIRSH destroy "$B" > /dev/null 2>&1
echo "STAGE whole-cluster outage: both nodes destroyed at +$(el)s"
sleep 5
$VIRSH start "$A" > /dev/null 2>&1
$VIRSH start "$B" > /dev/null 2>&1
waitboot "$A" "$B"
deploy_ko "$A"
deploy_ko "$B"
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=deploy evidence=$OUT"; exit 2; }

MARK="BSR-MARK-$LABEL"
# ---- MODE=concurrent: no knob at all — both nodes mount at once after the
#      outage, as fstab does after a power cut.  One of them bootstraps; the
#      term must not end REFUSED, the other must mount on its first attempt or
#      on one retry, and every fsynced file must read back on both.
#      Bound: the bootstrap (62 s dead window + claim, fence, two replays) and
#      the other's admission, 300 s, as the joiner's bound.
# ---- MODE=regwindow: B mounts first and is HELD registered under its new key
#      (its REGISTER replaced its previous boot's key), just before its
#      bootstrap setup (bootstrap_inject=18, TEST ONLY); A mounts and
#      bootstraps.  A's phase 3 can prove B's absent victim key only by the
#      witnessed LU reset, which is refused while B is registered, so A must
#      WAIT (P-BOOT-FENCE-WAIT); then B is released, its setup finds A's term
#      and refuses, and its unwind unregisters.  Graded as concurrent; a lap
#      where A never waited is VACUOUS.  Bound: JOIN_BOUND + DELAY_S each.
if [ "${MODE:-race}" = concurrent ] || [ "${MODE:-race}" = staggered ] || [ "${MODE:-race}" = regwindow ]; then
    MB=$JOIN_BOUND
    [ "$MODE" = regwindow ] && MB=$((JOIN_BOUND + DELAY_S))
    launch() {  # <node> [extra module args]
        rsx 60 "$1" "echo $MARK > /dev/kmsg; lsmod | grep -q '^mxfs ' || insmod $KO dyndbg=+p $MODARGS ${2:-}; echo INSMOD_RC=\$?; nohup sh -c 'timeout $MB mount -t mxfs $MXFS_DEV $MNT; echo MOUNT_RC=\$?' > /run/bsr_mount.log 2>&1 < /dev/null & echo LAUNCHED" > "$OUT/${1}_mount_launch.txt"
    }
    if [ "$MODE" = staggered ]; then
        # MODE=staggered: B boots later than A — its mount starts STAGGER_S
        # after A's claim, inside the dead window A's seal scan waits out, so
        # it finds A's term, registers as a takeover contender and watches.
        launch "$A"
        wait_for_into claimed "$A" 120 "$MARK" "P-BOOT-CLAIMED"
        [ "$claimed" = timeout ] && { echo "RESULT: VACUOUS label=$LABEL stage=claim (A never claimed) evidence=$OUT"; exit 3; }
        sleep "${STAGGER_S:-45}"
        launch "$B"
    elif [ "$MODE" = regwindow ]; then
        launch "$B" "bootstrap_inject=18"
        wait_for_into breg "$B" 60 "$MARK" "P-BOOT-INJECT-HOLD point=18"
        [ "$breg" = timeout ] && { echo "RESULT: VACUOUS label=$LABEL stage=register (B never reached the hold after its REGISTER) evidence=$OUT"; exit 3; }
        launch "$A"
        # A's bootstrap reaches phase 3 after two dead-window scans (~130 s)
        wait_for_into await "$A" "$HOLD_BOUND" "$MARK" "P-BOOT-FENCE-WAIT"
        rsx 30 "$B" "echo 0 > $PARAM/bootstrap_inject" > /dev/null
        [ "$await" = timeout ] && { echo "RESULT: VACUOUS label=$LABEL stage=fence (A never waited on a fence held up by B's registration) evidence=$OUT"; exit 3; }
        echo "STAGE A waiting on its fence with B registered; B released at +$(el)s"
    else
        launch "$A" & launch "$B" &
        wait
    fi
    for n in "$A" "$B"; do capture_require "$OUT/${n}_mount_launch.txt" '^LAUNCHED$' "$n's mount launch"; done
    echo "STAGE mounts launched (mode=$MODE) at +$(el)s (bound ${MB}s)"
    for n in "$A" "$B"; do
        value_now_into "rc_$n" "$n" $((MB + 30)) "$OUT/${n}_mount_rc.txt" '^[0-9]+$' "$n's mount outcome" \
            "for i in \$(seq $((MB + 10))); do grep -q MOUNT_RC= /run/bsr_mount.log && break; sleep 1; done; sed -n 's/^MOUNT_RC=//p' /run/bsr_mount.log | tail -1"
        rsx 30 "$n" "echo 0 > $PARAM/dbg_pr_read_keys_delay_ms" > /dev/null
        journal_into "$n" "$OUT/${n}_journal.txt" "$MARK"
        echo "  $n: mount rc=$(cat "$OUT/${n}_mount_rc.txt" | tail -1); $(grep -aoE 'P-BOOT-(CLAIMED|CLAIM-LOST|CLAIM-BUSY|FENCE-WAIT|FENCE-BLOCKED|FENCE-UNPROVEN|REFUSING|REFUSED|RECOVERY-COMPLETE|MOUNT-REFUSED|ADMISSION-REFUSED[A-Z-]*|SETUP-REFUSED|TAKEOVER-CANDIDATE)' "$OUT/${n}_journal.txt" | sort | uniq -c | tr '\n' ' ')"
    done
    if [ "$MODE" = regwindow ] && [ "$(cnt "$OUT/${A}_journal.txt" 'P-BOOT-FENCE-WAIT')" = 0 ]; then
        echo "RESULT: VACUOUS label=$LABEL stage=fence (A never waited on a fence held up by B's registration) evidence=$OUT"; exit 3
    fi
    if [ "$MODE" = regwindow ]; then
        ck "B refused at setup (P-BOOT-SETUP-REFUSED)" "$(cnt "$OUT/${B}_journal.txt" 'P-BOOT-SETUP-REFUSED')" 1
        ck "B did not mount past it (P-BOOT-TCP-NOT-GATED)" "$(cnt "$OUT/${B}_journal.txt" 'P-BOOT-TCP-NOT-GATED')" 0
        ck "B ran no recovery on its first attempt (P163-RECOVERY-COMPLETE)" "$(cnt "$OUT/${B}_journal.txt" 'P163-RECOVERY-COMPLETE')" 0
        ck "A's term was never refused (P-BOOT-REFUSING)" "$(cnt "$OUT/${A}_journal.txt" 'P-BOOT-REFUSING')" 0
    fi
    measure "$A" 60 "$OUT/rec_concurrent.txt" '^BOOTSTRAP ' "the record after both mounts" "$CHK --bootstrap $MXFS_DEV 2>&1"
    echo "STAGE record: $(grep -a '^BOOTSTRAP state=' "$OUT/rec_concurrent.txt" | cut -c1-120)"
    ck "the bootstrap term did not end REFUSED" "$(grep -ac '^BOOTSTRAP state=REFUSED' "$OUT/rec_concurrent.txt")" 0
    for n in "$A" "$B"; do
        rsx $((JOIN_BOUND + 30)) "$n" "mountpoint -q $MNT || { echo $MARK-retry > /dev/kmsg; timeout $JOIN_BOUND mount -t mxfs $MXFS_DEV $MNT; echo RETRY_RC=\$?; }; mountpoint -q $MNT && echo MOUNTED || echo NOT_MOUNTED" > "$OUT/${n}_final.txt"
        capture_require "$OUT/${n}_final.txt" '^(MOUNTED|NOT_MOUNTED)$' "$n's mount (one retry)"
        ck "$n is mounted (first attempt or one retry)" "$(grep -ac '^MOUNTED' "$OUT/${n}_final.txt")" 1
        ck "no shutdown or oops on $n" "$(( $(cnt "$OUT/${n}_journal.txt" 'hutting down filesystem') + $(cnt "$OUT/${n}_journal.txt" 'BUG:\|Oops') ))" 0
    done
    for r in "$A" "$B"; do
        for w in "$A" "$B"; do
            measure "$r" 60 "$OUT/read_${w}_on_${r}.txt" '^READ_END$' "$w's files read on $r" \
                "cd $MNT/bsr_${LABEL}_$w 2>/dev/null && sha256sum f* | sort; echo READ_END"
            ck "$w's fsynced files read back on $r" "$(grep -av '^READ_END' "$OUT/read_${w}_on_${r}.txt" | md5sum | cut -c1-32)" "$(md5sum < "$OUT/${w}_files_sha.txt" | cut -c1-32)"
        done
    done
    for n in "$B" "$A"; do
        rsx 60 "$n" "timeout 45 umount $MNT; echo UMOUNT_RC=\$?" > "$OUT/${n}_umount.txt"
        ck "$n unmounted" "$(field "$OUT/${n}_umount.txt" UMOUNT_RC)" 0
    done
    measure "$A" 120 "$OUT/chk.txt" '^CHK_RC=' "the cold check" "$CHK $MXFS_DEV 2>&1 | tail -5; echo CHK_RC=\${PIPESTATUS[0]}"
    ck "cold chk_mxfs is clean" "$(field "$OUT/chk.txt" CHK_RC)" 0
    echo "RESULT: $( [ $fails = 0 ] && echo PASS || echo FAIL ) label=$LABEL mode=$MODE fails=$fails wall=$(el)s evidence=$OUT"
    [ $fails = 0 ]; exit
fi

# ---- 2. B mounts first and is held right after its peek; A mounts and is held
#      after K
rsx 60 "$B" "echo $MARK > /dev/kmsg; lsmod | grep -q '^mxfs ' || insmod $KO dyndbg=+p $MODARGS; echo INSMOD_RC=\$?; echo 17 > $PARAM/bootstrap_inject; nohup sh -c 'timeout $((HOLD_BOUND + DELAY_S + 120)) mount -t mxfs $MXFS_DEV $MNT; echo MOUNT_RC=\$?' > /run/bsr_mount.log 2>&1 < /dev/null & echo LAUNCHED" > "$OUT/B_mount_launch.txt"
capture_require "$OUT/B_mount_launch.txt" '^LAUNCHED$' "B's mount launch"
wait_for_into bheld "$B" 60 "$MARK" "P-BOOT-INJECT-HOLD point=17"
if [ "$bheld" = timeout ]; then
    rsx 30 "$B" "echo 0 > $PARAM/bootstrap_inject" > /dev/null
    echo "RESULT: VACUOUS label=$LABEL stage=peek-hold (B never reached the hold after its peek) evidence=$OUT"; exit 3
fi
echo "STAGE B held after its peek at +$(el)s"
rsx 60 "$A" "echo $MARK > /dev/kmsg; lsmod | grep -q '^mxfs ' || insmod $KO dyndbg=+p $MODARGS; echo INSMOD_RC=\$?; echo 13 > $PARAM/bootstrap_inject; nohup timeout $((HOLD_BOUND + JOIN_BOUND + 600)) mount -t mxfs $MXFS_DEV $MNT > /run/bsr_mount.log 2>&1 & echo LAUNCHED" > "$OUT/A_mount_launch.txt"
capture_require "$OUT/A_mount_launch.txt" '^LAUNCHED$' "A's bootstrap mount launch"
echo "STAGE A's bootstrap mount launched at +$(el)s (waiting for the hold after K, bound ${HOLD_BOUND}s)"
wait_for_into held "$A" "$HOLD_BOUND" "$MARK" "P-BOOT-INJECT-HOLD point=13"
journal_into "$A" "$OUT/A_at_hold.txt" "$MARK"
if [ "$held" = timeout ]; then
    grep -a 'P-BOOT' "$OUT/A_at_hold.txt" | sed 's/.*mxfs: /    /' | cut -c1-180 | tail -8
    rsx 30 "$B" "echo 0 > $PARAM/bootstrap_inject" > /dev/null
    echo "RESULT: VACUOUS label=$LABEL stage=hold (A never held a RECOVERING term) evidence=$OUT"; exit 3
fi
grep -a 'P-BOOT-CLAIMED\|P-BOOT-SEALED\|P-BOOT-ADOPT \|P-BOOT-INJECT-HOLD' "$OUT/A_at_hold.txt" | sed 's/.*mxfs: /    /' | cut -c1-160 | head -5
measure "$A" 60 "$OUT/rec_held.txt" '^BOOTSTRAP ' "the record while A is held" "$CHK --bootstrap $MXFS_DEV 2>&1"
echo "STAGE A held at +$(el)s: $(grep -a '^BOOTSTRAP state=' "$OUT/rec_held.txt" | cut -c1-160)"

# ---- 3. B released: its setup runs under A's term
rsx 30 "$B" "echo 0 > $PARAM/bootstrap_inject; echo CLEARED" > "$OUT/B_clear.txt"
capture_require "$OUT/B_clear.txt" '^CLEARED$' "releasing B's hold"
echo "STAGE B released at +$(el)s; waiting for its mount to end (bound $((DELAY_S + 60))s)"
value_now_into brc "$B" $((DELAY_S + 90)) "$OUT/B_mount_rc.txt" '^[0-9]+$' "B's mount outcome" \
    "for i in \$(seq $((DELAY_S + 60))); do grep -q MOUNT_RC= /run/bsr_mount.log && break; sleep 1; done; sed -n 's/^MOUNT_RC=//p' /run/bsr_mount.log | tail -1"
journal_into "$B" "$OUT/B_journal.txt" "$MARK"
rsx 20 "$B" "mountpoint -q $MNT && echo MOUNTED || echo NOT_MOUNTED; cat /run/bsr_mount.log" > "$OUT/B_state.txt"
echo "STAGE B's mount ended rc=$brc at +$(el)s: $(grep -ao '^MOUNTED\|^NOT_MOUNTED' "$OUT/B_state.txt")"
grep -a 'P-BOOT-\|P163-RECOVERY-COMPLETE\|claimed heartbeat slot' "$OUT/B_journal.txt" | sed 's/.*mxfs: /    /' | cut -c1-170 | head -12
if [ "$(cnt "$OUT/B_journal.txt" 'P-BOOT-TAKEOVER-CANDIDATE')" != 0 ]; then
    echo "RESULT: VACUOUS label=$LABEL stage=peek (B's peek already saw A's term: the takeover arm, not setup) evidence=$OUT"; exit 3
fi
if [ "$(cnt "$OUT/B_journal.txt" 'P-BOOT-SETUP-REFUSED\|P-BOOT-TCP-NOT-GATED')" = 0 ]; then
    echo "  B never reached the setup branch; its last lines:"
    grep -a 'mxfs' "$OUT/B_journal.txt" | sed 's/.*mxfs: /    /' | cut -c1-170 | tail -6
    echo "RESULT: VACUOUS label=$LABEL stage=setup (B failed before setup) evidence=$OUT"; exit 3
fi
ck "B's setup found the term in progress (P-BOOT-ADMISSION-REFUSED state=RECOVERING)" "$(cnt "$OUT/B_journal.txt" 'P-BOOT-ADMISSION-REFUSED state=RECOVERING')" 1
ck "B refused at setup (P-BOOT-SETUP-REFUSED)" "$(cnt "$OUT/B_journal.txt" 'P-BOOT-SETUP-REFUSED')" 1
ck "B did not mount past it (P-BOOT-TCP-NOT-GATED)" "$(cnt "$OUT/B_journal.txt" 'P-BOOT-TCP-NOT-GATED')" 0
ck "B ran no recovery (P163-RECOVERY-COMPLETE)" "$(cnt "$OUT/B_journal.txt" 'P163-RECOVERY-COMPLETE')" 0
ck "B claimed no heartbeat slot" "$(cnt "$OUT/B_journal.txt" 'claimed heartbeat slot')" 0
ck "B is not mounted" "$(grep -ac '^NOT_MOUNTED' "$OUT/B_state.txt")" 1
ck "B's mount returned an error" "$([ "$brc" != 0 ] && echo 1 || echo 0)" 1
ck "no shutdown or oops on B" "$(( $(cnt "$OUT/B_journal.txt" 'hutting down filesystem') + $(cnt "$OUT/B_journal.txt" 'BUG:\|Oops') ))" 0
measure "$A" 60 "$OUT/rec_after_b.txt" '^BOOTSTRAP ' "the record after B's refusal" "$CHK --bootstrap $MXFS_DEV 2>&1"
ck "A's term is unchanged by B (record line)" "$(grep -a '^BOOTSTRAP state=' "$OUT/rec_after_b.txt" | sed 's/ seq=[^ ]*//; s/ stamp[^ ]*//g')" "$(grep -a '^BOOTSTRAP state=' "$OUT/rec_held.txt" | sed 's/ seq=[^ ]*//; s/ stamp[^ ]*//g')"

# ---- 4. A released: the bootstrap completes; B joins; the payload reads back
rsx 30 "$A" "echo 0 > $PARAM/bootstrap_inject; echo RELEASED" > "$OUT/A_release.txt"
capture_require "$OUT/A_release.txt" '^RELEASED$' "releasing A's hold"
wait_for_into done_a "$A" "$JOIN_BOUND" "$MARK" "P-BOOT-RECOVERY-COMPLETE"
journal_into "$A" "$OUT/A_journal.txt" "$MARK"
ck "A completed the whole-cluster bootstrap" "$([ "$done_a" != timeout ] && echo 1 || echo 0)" 1
ck "A's bootstrap was not refused" "$(cnt "$OUT/A_journal.txt" 'P-BOOT-REFUSING\|P-BOOT-FINISH-REFUSED\|P-BOOT-RECONCILE-FAILED')" 0
value_now_into amnt "$A" 60 "$OUT/A_mounted.txt" '^(MOUNTED|NOT_MOUNTED)$' "A's mount state" \
    "for i in \$(seq 30); do mountpoint -q $MNT && break; sleep 1; done; mountpoint -q $MNT && echo MOUNTED || echo NOT_MOUNTED"
ck "A is mounted" "$amnt" "MOUNTED"
echo "STAGE A completed at +$(el)s; B joins"
rsx $((JOIN_BOUND + 30)) "$B" "echo $MARK-join > /dev/kmsg; timeout $JOIN_BOUND mount -t mxfs $MXFS_DEV $MNT; echo MOUNT_RC=\$?; mountpoint -q $MNT && echo MOUNTED || echo NOT_MOUNTED" > "$OUT/B_join.txt"
capture_require "$OUT/B_join.txt" '^(MOUNTED|NOT_MOUNTED)$' "B's join"
ck "B joined after the bootstrap completed" "$(grep -ac '^MOUNTED' "$OUT/B_join.txt")" 1
for r in "$A" "$B"; do
    for w in "$A" "$B"; do
        measure "$r" 60 "$OUT/read_${w}_on_${r}.txt" '^READ_END$' "$w's files read on $r" \
            "cd $MNT/bsr_${LABEL}_$w 2>/dev/null && sha256sum f* | sort; echo READ_END"
        ck "$w's fsynced files read back on $r" "$(grep -av '^READ_END' "$OUT/read_${w}_on_${r}.txt" | md5sum | cut -c1-32)" "$(md5sum < "$OUT/${w}_files_sha.txt" | cut -c1-32)"
    done
done
for n in "$B" "$A"; do
    rsx 60 "$n" "timeout 45 umount $MNT; echo UMOUNT_RC=\$?" > "$OUT/${n}_umount.txt"
    ck "$n unmounted" "$(field "$OUT/${n}_umount.txt" UMOUNT_RC)" 0
done
measure "$A" 120 "$OUT/chk.txt" '^CHK_RC=' "the cold check" "$CHK $MXFS_DEV 2>&1 | tail -5; echo CHK_RC=\${PIPESTATUS[0]}"
ck "cold chk_mxfs is clean" "$(field "$OUT/chk.txt" CHK_RC)" 0
echo "RESULT: $( [ $fails = 0 ] && echo PASS || echo FAIL ) label=$LABEL fails=$fails wall=$(el)s evidence=$OUT"
[ $fails = 0 ]
