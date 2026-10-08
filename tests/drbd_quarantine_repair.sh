#!/bin/bash
# drbd_quarantine_repair.sh — the operator's way back from a terminal replay
# refusal, on the 2/net/mesh/drbd rig pair (D-QUARANTINED-SLOT-EXHAUSTS-
# CLUSTER-ADMISSION-376, D-DRBD-OUTAGE-BOOTSTRAP-REFUSES-THE-LAST-SURVIVORS-
# OWN-LOG).  Design: docs/quarantine-repair.md.
#
#   tests/drbd_quarantine_repair.sh full     reproduce a quarantine and repair it:
#       1. scripts/drbd_rig.sh death-test with DEATH_FORCE_REFUSE=1 — node 1
#          refuses node 2's slice and quarantines the slot; the fsynced sets of
#          both nodes are recorded first (the rig prints their checksums);
#       2. node 1 unmounts cleanly: nothing is mounted anywhere;
#       3. chk_mxfs --show-quarantine names the slot and the VERDICT DIGEST;
#          chk_mxfs -n records what the discard leaves BEFORE any repair;
#       4. chk_mxfs --accept-quarantine-loss SLOT --confirm DIGEST --archive-to
#          (an archive on node 1's own root disk, disjoint from the DRBD LUN);
#       then everything `verify` does, with the recorded checksums.
#   tests/drbd_quarantine_repair.sh verify   after a repair: node 1 mounts, node 2
#       is released and rejoins (it claims the repaired slot), both read the
#       fsynced sets (compared when N1SUM/N2SUM are given), both churn files in
#       every AG and read them back, both unmount, and a cold chk_mxfs -n must
#       be clean, with no quarantine and the bootstrap record IDLE.
#
# Env:
#   MXFS_GROUP       rig group (default g2)
#   QREPAIR_TOOLS    the tools directory as the NODES see it (default: this
#                    tree's tools/, under the /src NFS mount)
#   QREPAIR_EVID     evidence directory (default <tree>/tests/evidence/quarantine_repair/<stamp>)
#   RIG              the drbd_rig.sh to drive (default: this tree's)
#   QREPAIR_KO       the mxfs.ko the nodes load as /src/mxfs/mxfs.ko (default:
#                    this tree's), for prep_node.sh's md5 check
#   N1SUM, N2SUM     `verify` only: the fsynced sets' checksums to compare
#
# Budgets (each derived from a measurement on this rig, 0.90.95, 2026-10-07):
#   accept: 23 s measured (two 10 s liveness windows + four check passes over a
#   20 GiB volume + a 64 MiB slice copy and overwrite) -> 60;  a cold check:
#   the rig's own 120;  churn: 2 x 200 x 64 KiB fsynced files, seconds -> 60.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
. "$REPO/tools/mxfs_lab.sh"
SSH="$REPO/tools/mxfs_sshpass.sh"
GROUP=${MXFS_GROUP:-g2}
RIG=${RIG:-$REPO/scripts/drbd_rig.sh}
DEV=/dev/drbd0
MNT=/mnt/shared
MODE=${1:-}
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
EVID=${QREPAIR_EVID:-$REPO/tests/evidence/quarantine_repair/$STAMP-$MODE}
case "$REPO" in
    /home/steve/src/*) NODE_TREE=/src/${REPO#/home/steve/src/} ;;
    *)                 NODE_TREE=$REPO ;;
esac
TOOLS=${QREPAIR_TOOLS:-$NODE_TREE/tools}
ACCEPT_BUDGET=60
CHK_BUDGET=120
CHURN_BUDGET=60

read -r -a NODES <<<"$("$REPO/tools/mxfs_lab.sh" group "$GROUP")"
[ "${#NODES[@]}" = 2 ] || { echo "group $GROUP has ${#NODES[@]} nodes, not 2"; exit 2; }
N1=${NODES[0]}; N2=${NODES[1]}

say() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$EVID/run.log"; }
die() { say "FAIL: $*"; exit 1; }
ssh_n() { timeout "${3:-60}" "$SSH" "$(lab_addr "$1")" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you|^$'; }

mkdir -p "$EVID" || { echo "cannot create $EVID"; exit 1; }
# the module the nodes load is /src/mxfs/mxfs.ko (prep_node.sh MXFS_REPO);
# prep_node.sh refuses one whose md5 is not this
KO_MD5=$(md5sum "${QREPAIR_KO:-$REPO/mxfs.ko}" | awk '{print $1}')
[ ${#KO_MD5} = 32 ] || { echo "no module at ${QREPAIR_KO:-$REPO/mxfs.ko} (QREPAIR_KO)"; exit 2; }
PREP="MXFS_DEV=$DEV MXFS_KO_MD5=$KO_MD5 MXFS_REPO=/src/mxfs bash /src/mxfs/tests/setup/prep_node.sh tcp"

reproduce() {
    local out n
    # the death test needs both mounted; a volume a previous repair left
    # unmounted is mounted as it is (QREPAIR_FRESH=1 formats a new one)
    if [ "${QREPAIR_FRESH:-0}" = 1 ]; then
        env MXFS_GROUP="$GROUP" "$RIG" mxfs > "$EVID/mxfs.log" 2>&1 || die "mkfs/mount: $(tail -2 "$EVID/mxfs.log" | tr '\n' ' ')"
    fi
    for n in "$N1" "$N2"; do
        out=$(ssh_n "$n" "mountpoint -q $MNT && echo MOUNTED" 20)
        grep -q MOUNTED <<<"$out" && continue
        ssh_n "$n" "$PREP 2>&1 | tail -2" 180 > "$EVID/premount.$n"
        grep -aq '^NODE_PREP_OK' "$EVID/premount.$n" || die "$n did not mount before the death test: $(tail -2 "$EVID/premount.$n" | tr '\n' ' ')"
    done
    say "1. reproducer: DEATH_FORCE_REFUSE=1 $RIG death-test (group $GROUP)"
    env MXFS_GROUP="$GROUP" DEATH_FORCE_REFUSE=1 "$RIG" death-test > "$EVID/death_test.log" 2>&1
    out=$(grep -a ' n1 set ' "$EVID/death_test.log" | tail -1)
    N1SUM=$(sed -n 's/.* n1 set \([0-9a-f]\{32\}\),.*/\1/p' <<<"$out")
    N2SUM=$(sed -n 's/.* n2 set \([0-9a-f]\{32\}\);.*/\1/p' <<<"$out")
    [ ${#N1SUM} = 32 ] && [ ${#N2SUM} = 32 ] || die "the death test recorded no checksums: $(tail -3 "$EVID/death_test.log")"
    grep -aq 'refused .* transaction(s), each with its report' "$EVID/death_test.log" \
        || die "the death test did not end in a refused replay: $(tail -3 "$EVID/death_test.log")"
    say "  fsynced sets recorded: n1 $N1SUM n2 $N2SUM; $(grep -a 'refused .* transaction' "$EVID/death_test.log" | tail -1 | cut -c12-160)"

    say "2. $N1 unmounts: nothing is mounted anywhere ($N2 is off and fenced)"
    out=$(ssh_n "$N1" "timeout 30 umount $MNT; echo UMOUNT_RC=\$?; mountpoint -q $MNT && echo STILL_MOUNTED" 45)
    grep -q 'UMOUNT_RC=0' <<<"$out" && ! grep -q STILL_MOUNTED <<<"$out" || die "$N1 would not unmount: $out"
}

mount_both_if_needed() {
    local n out
    for n in "$N1" "$N2"; do
        out=$(ssh_n "$n" "mountpoint -q $MNT && echo MOUNTED" 20)
        grep -q MOUNTED <<<"$out" && continue
        ssh_n "$n" "$PREP 2>&1 | tail -2" 180 > "$EVID/premount.$n"
        grep -aq '^NODE_PREP_OK' "$EVID/premount.$n" || die "$n did not mount: $(tail -2 "$EVID/premount.$n" | tr '\n' ' ')"
    done
}

# The ADOPTED form, the 2026-10-07 incident's shape: a whole-pair outage with
# ONE node mounted and writing, so the restart's bootstrap has one victim, the
# slot it adopts as its own log.  That replay is made to refuse with the same
# test knob the death test uses (dbg_fr_taint_items_over=1, set at module load
# on the node that mounts first), which ends the term REFUSED over the adopted
# slot with escrow K_REPLAY_REFUSED.  --clear-bootstrap must then refuse, and
# the repair accepts the loss straight from the escrow.
DRBD_UP='modprobe drbd
    ll=$(drbdadm sh-ll-dev mxfs 2>/dev/null)
    for i in $(seq 1 30); do [ -b "$ll" ] && break; iscsiadm -m node --loginall=automatic >/dev/null 2>&1; udevadm settle -t 5 >/dev/null 2>&1; [ -b "$ll" ] || sleep 1; done
    drbdadm up mxfs 2>&1 | tail -1
    for i in $(seq 1 120); do [ "$(drbdadm cstate mxfs) $(drbdadm dstate mxfs)" = "Connected UpToDate/UpToDate" ] && break; sleep 1; done
    drbdadm primary mxfs 2>&1 | tail -1
    mountpoint -q /src || { mkdir -p /src; timeout 20 mount -t nfs 192.168.120.1:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp; }
    systemctl stop mxfs-rig-boot 2>/dev/null
    echo "DRBD_STATE $(drbdadm role mxfs) $(drbdadm dstate mxfs) $(drbdadm cstate mxfs)"'
reproduce_adopted() {
    local out n
    mount_both_if_needed
    say "1. fsynced sets on both; $N2 unmounts cleanly; $N1 keeps writing"
    out=$(ssh_n "$N1" "mkdir -p $MNT/adopt/n1 && for i in \$(seq 1 64); do head -c 65536 /dev/urandom > $MNT/adopt/n1/f\$i; done && sync -f $MNT && cd $MNT/adopt/n1 && md5sum f* | sort -k2 | md5sum | cut -c1-32" 60)
    N1SUM=$(tail -1 <<<"$out")
    out=$(ssh_n "$N2" "mkdir -p $MNT/adopt/n2 && for i in \$(seq 1 64); do head -c 65536 /dev/urandom > $MNT/adopt/n2/f\$i; done && sync -f $MNT && cd $MNT/adopt/n2 && md5sum f* | sort -k2 | md5sum | cut -c1-32" 60)
    N2SUM=$(tail -1 <<<"$out")
    [ ${#N1SUM} = 32 ] && [ ${#N2SUM} = 32 ] || die "could not record the sets ($N1SUM / $N2SUM)"
    out=$(ssh_n "$N2" "timeout 30 umount $MNT; echo UMOUNT_RC=\$?" 45)
    grep -q 'UMOUNT_RC=0' <<<"$out" || die "$N2 would not unmount: $out"
    # every 50 writes a log force: the churn must be IN the slice when the
    # pair dies, not in the CIL (a writer that never syncs leaves the slice
    # holding nothing to refuse)
    out=$(ssh_n "$N1" "nohup setsid bash -c 'i=0; while :; do i=\$((i+1)); echo \$i > $MNT/adopt/n1/live\$((i % 200)); [ \$((i % 50)) = 0 ] && sync -f $MNT; done' >/dev/null 2>&1 < /dev/null & sleep 3; echo WRITER_UP" 30)
    grep -q WRITER_UP <<<"$out" || die "no writer on $N1"
    say "  sets n1 $N1SUM n2 $N2SUM; destroying both nodes at once ($N1 mounted alone, writing)"
    for n in "$N1" "$N2"; do timeout 60 virsh -c qemu:///system destroy "$n" >/dev/null 2>&1; done
    "$REPO/scripts/lab_power.sh" up "$N1" "$N2" > "$EVID/outage_power" 2>&1 || die "boot: $(tail -1 "$EVID/outage_power")"
    for n in "$N1" "$N2"; do
        ( ssh_n "$n" "$DRBD_UP" 200 > "$EVID/drbdup.$n" ) &
    done
    wait
    for n in "$N1" "$N2"; do
        grep -q 'DRBD_STATE Primary/Primary UpToDate/UpToDate Connected' "$EVID/drbdup.$n" || die "$n DRBD: $(tail -1 "$EVID/drbdup.$n")"
    done
    say "2. $N1 mounts first with the replay refusal armed (dbg_fr_taint_items_over=1)"
    ssh_n "$N1" "dmesg -C; MXFS_EXTRA_MODARGS=dbg_fr_taint_items_over=1 $PREP 2>&1 | grep -a NODE_PREP | tail -1
        echo 0 > /sys/module/mxfs/parameters/dbg_fr_taint_items_over
        mountpoint -q $MNT && echo STILL_MOUNTED
        dmesg | grep -aoE 'P-BOOT-[A-Z-]+|P227-FR-ATOMIC-SKIP' | sort | uniq -c | sort -rn | head -12 | tr '\n' ' '" 300 > "$EVID/boot_refused.$N1"
    ssh_n "$N1" "dmesg" 30 > "$EVID/kernlog_boot.$N1"
    grep -q STILL_MOUNTED "$EVID/boot_refused.$N1" && die "$N1 mounted: the adopted replay was not refused ($(tail -1 "$EVID/boot_refused.$N1"))"
    ssh_n "$N1" "$TOOLS/chk_mxfs --bootstrap $DEV" 20 > "$EVID/bootstrap.before"
    grep -q 'state=REFUSED.*escrow=4' "$EVID/bootstrap.before" || die "no adopted refusal: $(head -1 "$EVID/bootstrap.before")"
    say "  term REFUSED with escrow K_REPLAY_REFUSED: $(head -1 "$EVID/bootstrap.before" | grep -o 'term=[0-9]*\|K=[0-9]*\|refused_slot=[0-9]*' | tr '\n' ' ')"
    out=$(ssh_n "$N1" "timeout 30 $TOOLS/chk_mxfs --clear-bootstrap $DEV 2>&1; echo CLEAR_RC=\$?; $TOOLS/chk_mxfs --bootstrap $DEV | head -1" 45)
    echo "$out" > "$EVID/clear_bootstrap.refused"
    grep -q 'CLEAR_RC=4' <<<"$out" && grep -q 'state=REFUSED.*escrow=4' <<<"$out" || die "--clear-bootstrap did not refuse the adopted term: $out"
    say "  --clear-bootstrap refused it, record unchanged"
}

repair() {
    local out slot digest
    say "3. the verdict, and what discarding the slice leaves (before any repair)"
    ssh_n "$N1" "$TOOLS/chk_mxfs --show-quarantine $DEV; echo SHOW_RC=\$?" 30 > "$EVID/show_quarantine.before"
    slot=$(grep -aE 'heartbeat slot .*: (RECOVERY GUARD|ADOPTED SLICE)' "$EVID/show_quarantine.before" | head -1 | sed 's/.*heartbeat slot \([0-9]*\):.*/\1/')
    digest=$(grep -a 'VERDICT DIGEST' "$EVID/show_quarantine.before" | head -1 | awk '{print $3}')
    [ -n "$slot" ] && [ ${#digest} = 16 ] || die "no quarantine to repair: $(tail -5 "$EVID/show_quarantine.before" | tr '\n' ' ')"
    say "  slot $slot quarantined, verdict digest $digest"
    ssh_n "$N1" "timeout $CHK_BUDGET $TOOLS/chk_mxfs -n $DEV; echo CHK_RC=\$?" $((CHK_BUDGET + 15)) > "$EVID/chk.before"
    say "  before repair: $(grep -a '^Inode fork ownership' "$EVID/chk.before" | cut -c1-140); $(grep -a '^chk_mxfs:' "$EVID/chk.before"); $(grep -a CHK_RC "$EVID/chk.before")"

    say "4. chk_mxfs --accept-quarantine-loss $slot (archive on $N1's root disk)"
    out=$(ssh_n "$N1" "mkdir -p /root/qarchive/$STAMP && timeout $ACCEPT_BUDGET $TOOLS/chk_mxfs --accept-quarantine-loss $slot --confirm $digest --archive-to /root/qarchive/$STAMP/slot$slot.txt $DEV 2>&1; echo ACCEPT_RC=\$?" $((ACCEPT_BUDGET + 15)))
    echo "$out" > "$EVID/accept.log"
    grep -q 'ACCEPT_RC=0' <<<"$out" || die "the repair did not finish (budget ${ACCEPT_BUDGET}s): $(grep -aE 'repair:|STOPPED|ACCEPT_RC' "$EVID/accept.log" | tail -4 | tr '\n' ' ')"
    say "  $(grep -a 'REPAIRED: AG' "$EVID/accept.log" | head -1 | cut -c1-140 | grep . || echo 'no fork/free-space cross-link to repair')"
    say "  $(grep -a 'pass 3:' "$EVID/accept.log")  /  $(grep -a 'bootstrap record REFUSED -> IDLE' "$EVID/accept.log" | cut -c1-80)"
    ssh_n "$N1" "ls -l /root/qarchive/$STAMP/" 20 > "$EVID/archive.ls"
}

verify() {
    local out n s1 s2
    say "5. $N1 mounts the repaired volume"
    ssh_n "$N1" "dmesg -C; $PREP 2>&1 | tail -2" 180 > "$EVID/mount.$N1"
    grep -aq '^NODE_PREP_OK' "$EVID/mount.$N1" || die "$N1 did not mount: $(tail -2 "$EVID/mount.$N1" | tr '\n' ' ')"
    say "  $N1: $(grep -a '^NODE_PREP_OK' "$EVID/mount.$N1" | cut -c1-120)"

    say "6. $N2 is released, boots, resyncs and mounts: it claims the repaired slot"
    env MXFS_GROUP="$GROUP" "$RIG" rejoin "$N2" > "$EVID/rejoin.log" 2>&1 || die "$N2 did not rejoin: $(tail -3 "$EVID/rejoin.log" | tr '\n' ' ')"
    for n in "$N1" "$N2"; do
        ssh_n "$n" "dmesg | grep -aE 'P-SLIFE slot|disklock: claimed|claim_slot|P300-CLAIM' | cut -c1-220 | tail -4" 20 > "$EVID/claim.$n"
    done
    say "  $N2 mounted; its claim: $(tail -1 "$EVID/claim.$N2" | cut -c1-160)"

    say "7. both read the fsynced sets"
    for n in "$N1" "$N2"; do
        out=$(ssh_n "$n" "cd $MNT/$SETDIR/n1 && md5sum f* | sort -k2 | md5sum | cut -c1-32; cd $MNT/$SETDIR/n2 && md5sum f* | sort -k2 | md5sum | cut -c1-32" 60)
        echo "$out" > "$EVID/sums.$n"
        s1=$(sed -n 1p <<<"$out"); s2=$(sed -n 2p <<<"$out")
        [ ${#s1} = 32 ] && [ ${#s2} = 32 ] || die "$n cannot read the fsynced sets: $out"
        if [ -n "${N1SUM:-}" ]; then
            [ "$s1" = "$N1SUM" ] || die "$n reads n1 set $s1, recorded $N1SUM"
            [ "$s2" = "$N2SUM" ] || die "$n reads n2 set $s2, recorded $N2SUM"
        fi
        say "  $n: n1 $s1 n2 $s2${N1SUM:+ (both as recorded before the death)}"
    done
    [ "$(cat "$EVID/sums.$N1")" = "$(cat "$EVID/sums.$N2")" ] || die "the two nodes read different sets"

    say "8. both churn: 200 fsynced 64 KiB files each, read back, half deleted"
    for n in "$N1" "$N2"; do
        ( ssh_n "$n" "d=$MNT/qrepair/$n; mkdir -p \$d && for i in \$(seq 1 200); do head -c 65536 /dev/urandom > \$d/g\$i; done && sync -f $MNT && (cd \$d && md5sum g* | sort -k2 | md5sum | cut -c1-32) && for i in \$(seq 1 2 200); do rm \$d/g\$i; done && sync -f $MNT && echo CHURN_OK" $CHURN_BUDGET > "$EVID/churn.$n" ) &
    done
    wait
    for n in "$N1" "$N2"; do
        grep -q CHURN_OK "$EVID/churn.$n" || die "$n churn failed (budget ${CHURN_BUDGET}s): $(tail -2 "$EVID/churn.$n" | tr '\n' ' ')"
    done
    for n in "$N1" "$N2"; do
        out=$(ssh_n "$n" "for m in $N1 $N2; do (cd $MNT/qrepair/\$m && md5sum g* | sort -k2 | md5sum | cut -c1-32); done" 60)
        echo "$out" > "$EVID/churn_read.$n"
    done
    [ "$(cat "$EVID/churn_read.$N1")" = "$(cat "$EVID/churn_read.$N2")" ] || die "the nodes read different churn sets"
    say "  both churned and read the same 2 x 100 surviving files"

    say "9. both unmount; cold chk_mxfs -n"
    for n in "$N2" "$N1"; do
        out=$(ssh_n "$n" "timeout 30 umount $MNT; echo UMOUNT_RC=\$?" 45)
        grep -q 'UMOUNT_RC=0' <<<"$out" || die "$n would not unmount: $out"
    done
    ssh_n "$N1" "timeout $CHK_BUDGET $TOOLS/chk_mxfs -n $DEV; echo CHK_RC=\$?; $TOOLS/chk_mxfs --show-quarantine $DEV | grep -aE 'quarantined verdicts|usable RW'; $TOOLS/chk_mxfs --bootstrap $DEV | head -1 | cut -c1-60" $((CHK_BUDGET + 30)) > "$EVID/chk.after"
    grep -q 'CHK_RC=0' "$EVID/chk.after" || die "cold chk after the repair: $(grep -aE 'ERROR|^chk_mxfs:' "$EVID/chk.after" | head -5 | tr '\n' ' ')"
    grep -aq 'quarantined verdicts    0' "$EVID/chk.after" || die "a quarantine is still on the volume"
    grep -aq 'BOOTSTRAP state=IDLE' "$EVID/chk.after" || die "the bootstrap record is not IDLE: $(grep -a BOOTSTRAP "$EVID/chk.after")"
    say "  $(grep -a '^Inode fork ownership' "$EVID/chk.after" | cut -c1-120)"
    say "  cold chk clean (CHK_RC=0), no quarantine, $(grep -a 'usable RW' "$EVID/chk.after" | sed 's/^ *//'), bootstrap IDLE"
}

SETDIR=death
case "$MODE" in
    full)   reproduce; repair; verify; say "PASS: quarantine -> accepted loss -> slot reused, both mounted, fsynced sets intact, cold chk clean (evidence $EVID)" ;;
    adopted) SETDIR=adopt; reproduce_adopted; repair; verify; say "PASS: adopted-slice refusal -> clear-bootstrap refused -> accepted loss -> both mounted, fsynced sets intact, cold chk clean (evidence $EVID)" ;;
    verify) verify; say "PASS: verify (evidence $EVID)" ;;
    *)      sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
