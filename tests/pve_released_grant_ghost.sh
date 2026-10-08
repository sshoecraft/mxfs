#!/bin/bash
# pve_released_grant_ghost.sh — a host releases its exclusive grants while
# their master cannot acknowledge the releases, the master dies, the host takes
# the master's ledger pages over and works in the same directories again, then
# the host loses power too (a total outage), and both must come back with no
# operator action.
#
# For D-DRBD-OUTAGE-BOOTSTRAP-REFUSES-THE-LAST-SURVIVORS-OWN-LOG.  The chain
# under test, read from the code:
#   - a release publishes its clean-release marker {resource, grant seq,
#     lineage} durably, drops the local mirror and sends the release to the
#     resource's master; it stays pending until the master acknowledges it
#     (dlm/dlm.c mxfs_dlm_unlock_open);
#   - the master dies first, so its ledger page still records this host as
#     the exclusive holder under that seq;
#   - this host takes the page over and imports the record as a holder of its
#     own (dlm_import_holder), and its next lock of the resource adopts the
#     record with the seq it already released (P-TAUTH-ADOPT-LOCAL);
#   - the inode layer refuses to install a seq its own journal certifies as
#     released (P-RELMARK-REINSTALL-REFUSED), so every image of that tenure is
#     logged with no authority class;
#   - after the outage the bootstrap replays this host's log and refuses those
#     images (P227-FR-REFUSED-IMAGE), the transaction is skipped whole and the
#     volume is refused until an operator repairs it.
# On 2026-10-07 the same refusal followed a dual write and a dropped link; here
# the master is frozen (virsh suspend) while the releases go out, then
# destroyed, which is the same lost acknowledgement without the dual write.
#
# Runs on the NESTED pair only (it destroys both VMs): pve9-2 = participant 0
# (192.168.120.137, the host that releases and survives), pve9-1 = participant
# 1 (192.168.120.192, the master that dies).
#
# Usage: tests/pve_released_grant_ghost.sh
# Env:
#   RELEASE_BY      how participant 0's grants are released while the master is
#                   frozen: 'evict' (drop_caches; the eviction's release also
#                   frees the inode, and with it the in-memory record of the
#                   marker, so the refusal cannot fire) or 'peer' (participant 1
#                   lists the directories while participant 0 writes in them,
#                   so each listing makes participant 0 release to the master
#                   with the inode still cached, as the 2026-10-07 survivor's
#                   churn did; participant 1 is frozen mid-churn; adopts only
#                   when a release happens to be in flight at the freeze) or
#                   'close' (participant 1 frozen first; participant 0, with
#                   ex_close_release_ms=50, overwrites the files it holds EX
#                   on, so each close releases EX through the full drain with
#                   the inode still cached and the release unacknowledged;
#                   then rewrites them, adopting every record it imported:
#                   deterministic for files, but a regular file's tenure
#                   carries no in-memory marker, so the refusal never fires:
#                   a control build adopted 100 and stayed clean) or 'pause'
#                   (participant 0 parks every release drain with
#                   dbg_bast_pause_ino=all, participant 1 lists every
#                   directory so participant 0 owes each a release, participant
#                   1 is frozen while they are parked, then they complete into
#                   the frozen master with the directories still cached and
#                   participant 0 reworks them: deterministic for directories,
#                   the incident's shape) (evict)
#   CHURN_S         seconds participant 1 lists before the freeze, peer mode (5)
#   P0_CHURN_S      seconds participant 0 rewrites the files round after round
#                   before its one rework pass, peer mode (0: the rework pass
#                   alone, started with participant 1's listing, which is the
#                   shape that reproduced the refusal on 2026-10-07; with 25 s
#                   of rounds two laps adopted nothing)
#   DIRS            directories participant 0 works in (16: about half of them
#                   are mastered by participant 1)
#   JOIN_BUDGET     seconds for both hosts mounted, Primary/Primary (300: the
#                   heartbeat scan ~64 s, DRBD connect and the boot program's
#                   ordering, twice over)
#   EVICT_S         seconds participant 0 is given to evict and release the
#                   directories while participant 1 is frozen (20: reclaim's
#                   5 s period, DRBD's ping timeout freezing I/O until the
#                   fence handler excludes the frozen peer, twice over)
#   RECOVER_BUDGET  seconds from the peer's destruction to participant 0's
#                   P163-RECOVERY-COMPLETE (120, as tests/pve_outage_lone_survivor.sh)
#   RESTART_BUDGET  seconds from starting both VMs to both mounted (400, as
#                   tests/pve_outage_lone_survivor.sh)
# Exit 0 only if both hosts remount after the outage with no refusal and every
# file participant 0 wrote and synced before the outage reads back as written.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
VIRSH="virsh -c qemu:///system"
P0=192.168.120.137; P0VM=pve9-2
P1=192.168.120.192; P1VM=pve9-1
RES=mxfs; MNT=/mnt/shared
RELEASE_BY=${RELEASE_BY:-evict}
CHURN_S=${CHURN_S:-5}
P0_CHURN_S=${P0_CHURN_S:-0}
case "$RELEASE_BY" in evict|peer|close|pause) ;; *) echo "RELEASE_BY must be evict, peer, close or pause" >&2; exit 2 ;; esac
DIRS=${DIRS:-16}
JOIN_BUDGET=${JOIN_BUDGET:-300}
EVICT_S=${EVICT_S:-20}
RECOVER_BUDGET=${RECOVER_BUDGET:-120}
RESTART_BUDGET=${RESTART_BUDGET:-400}
EVID="$REPO/tests/evidence/pve_released_grant_ghost/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$EVID" || exit 1

on() {  # <host> <cmd> [timeout]
    timeout "${3:-30}" "$SSHP" "$1" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you|^$'
    return "${PIPESTATUS[0]}"
}
say() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$EVID/log"; }
mounted() {  # <host>
    [ "$(on "$1" "grep -c ' $MNT mxfs ' /proc/mounts" 15)" = 1 ]
}
whole() {
    local h s
    for h in "$P0" "$P1"; do
        s=$(on "$h" "grep ' cs:' /proc/drbd; grep -c ' $MNT mxfs ' /proc/mounts" 15)
        case "$s" in *"cs:Connected ro:Primary/Primary ds:UpToDate/UpToDate"*) ;; *) return 1 ;; esac
        [ "$(tail -1 <<<"$s")" = 1 ] || return 1
    done
}
wait_for() {  # <budget> <what> <cmd...>: poll every 5 s
    local budget=$1 what=$2 t0
    shift 2
    t0=$(date +%s)
    until "$@"; do
        if [ $(( $(date +%s) - t0 )) -ge "$budget" ]; then
            say "FAIL: $what not reached within ${budget}s"
            return 1
        fi
        sleep 5
    done
    say "$what after $(( $(date +%s) - t0 ))s"
}
since_mark() {  # <host> <mark> <egrep>: count of matching kernel lines since the mark
    on "$1" "journalctl -k -b --no-pager | sed -n '/mxfs-test: $2/,\$p' | grep -a -c -E '$3'" 20 | tail -1
}

say "evidence $EVID"
wait_for "$JOIN_BUDGET" "pair whole (mounted, Primary/Primary, UpToDate)" whole || exit 1
for h in "$P0" "$P1"; do on "$h" "cat /sys/module/mxfs/srcversion; cat /sys/module/mxfs/version" 15 | tr '\n' ' ' | sed "s/^/$h build: /" | tee -a "$EVID/log"; echo | tee -a "$EVID/log"; done

# 1. participant 0 creates in each directory: it takes each one EX and its
# directory blocks are logged under that grant, so each release owes a marker
G=$MNT/ghost/$(date -u +%H%M%S)
on "$P0" "mkdir -p $G && cd $G && for d in \$(seq 1 $DIRS); do mkdir d\$d; for f in \$(seq 1 20); do echo \$f > d\$d/f\$f; done; done; sync; echo P0_CREATE_RC=\$?" 180 | tee -a "$EVID/log"
# hold participant 0's log tail from here to the outage (dbg_ail_pin_ino on a
# file it then logs), so the checkpoints of the work below stay in the window
# the bootstrap replays, as the 2026-10-07 survivor's wedged writeback held them
pino=$(on "$P0" "echo pin > $G/pin && stat -c %i $G/pin" 30 | tail -1)
[[ "$pino" =~ ^[0-9]+$ ]] || { say "ABORT: no pin inode ($pino)"; exit 1; }
on "$P0" "echo $pino > /sys/module/mxfs/parameters/dbg_ail_pin_ino && echo again >> $G/pin && sync && cat /sys/module/mxfs/parameters/dbg_ail_pin_ino" 60 | sed 's/^/pinned ino /' | tee -a "$EVID/log"
on "$P0" "echo 'module mxfs format \"P-RELMARK-EVICT\" +p' > /proc/dynamic_debug/control; echo '<5>mxfs-test: ghost run master frozen' > /dev/kmsg" 15

# 2. freeze the master, let participant 0 evict the directories (each eviction
# publishes its marker and sends a release nobody acknowledges), and at once
# work in every directory again: those locks wait on the frozen master, and
# the fence handler's exclusion of it a few seconds later makes participant 0
# the master of its pages, so they are re-driven against the imported records
# the moment the takeover lands -- before the release's retry tick, as the
# 2026-10-07 survivor's churn locked 16 ms after its recovery
# The rework's last pass writes every file's final content; the check after the
# outage reads exactly this back.
REWORK="for d in \$(seq 1 $DIRS); do for f in \$(seq 21 30); do echo \$f > d\$d/f\$f; done; mv d\$d/f1 d\$d/g1; done; sync; echo P0_REWORK_RC=\$?"
if [ "$RELEASE_BY" = pause ]; then
    PARAM=/sys/module/mxfs/parameters
    # participant 1 walks to the run directory BEFORE the drains are parked:
    # participant 0 holds it EX from the creates, and a parked release of it
    # would hold every lookup below it, so no directory would be asked for
    # (2026-10-07 23:07 CDT: one drain parked, on the run directory, and nothing
    # was adopted)
    on "$P1" "ls -f $G > /dev/null && echo P1_WALKED" 30 | tee -a "$EVID/log"
    on "$P0" "echo 'module mxfs format \"P-BAST-PAUSE\" +p' > /proc/dynamic_debug/control; echo 8000 > $PARAM/dbg_bast_pause_ms && echo 18446744073709551615 > $PARAM/dbg_bast_pause_ino && echo PARKING_ON" 15 | tee -a "$EVID/log"
    # every directory read waits on participant 0's parked release of that
    # directory; -f reads the directory alone, no stat of its files
    on "$P1" "for d in \$(seq 1 $DIRS); do ls -f $G/d\$d > /dev/null & done; wait; echo P1_LISTED" 60 > "$EVID/p1-list.out" 2>&1 &
    p1job=$!
    sleep 3
    say "freezing $P1VM (participant 1) with participant 0's releases parked"
    $VIRSH suspend "$P1VM" 2>&1 | tee -a "$EVID/log"
    on "$P0" "echo 0 > $PARAM/dbg_bast_pause_ino; echo PARKED=\$(journalctl -k -b --no-pager | sed -n '/mxfs-test: ghost run master frozen/,\$p' | grep -ac 'P-BAST-PAUSE ')" 15 | tee -a "$EVID/log"
    sleep 8     # the parked drains finish their hold and release into the frozen master
    kill "$p1job" 2>/dev/null; wait "$p1job" 2>/dev/null
    on "$P0" "echo '<5>mxfs-test: ghost run rework' > /dev/kmsg; cd $G && $REWORK" $(( RECOVER_BUDGET + 60 )) | tee -a "$EVID/log"
elif [ "$RELEASE_BY" = close ]; then
    say "freezing $P1VM (participant 1)"
    $VIRSH suspend "$P1VM" 2>&1 | tee -a "$EVID/log"
    # the knob is set only for the release pass and cleared before the rework;
    # the VM's destruction at the outage resets it in any case
    on "$P0" "echo 50 > /sys/module/mxfs/parameters/ex_close_release_ms && cd $G && for d in \$(seq 1 $DIRS); do for f in \$(seq 2 20); do echo \$f > d\$d/f\$f; done; done; sleep 3; echo 0 > /sys/module/mxfs/parameters/ex_close_release_ms; echo RELEASE_PASS_RC=\$?; echo '<5>mxfs-test: ghost run rework' > /dev/kmsg; for d in \$(seq 1 $DIRS); do for f in \$(seq 2 20); do echo \$f > d\$d/f\$f; done; done; $REWORK" $(( RECOVER_BUDGET + 90 )) | tee -a "$EVID/log"
elif [ "$RELEASE_BY" = evict ]; then
    say "freezing $P1VM (participant 1)"
    $VIRSH suspend "$P1VM" 2>&1 | tee -a "$EVID/log"
    on "$P0" "cd /; sync; echo 2 > /proc/sys/vm/drop_caches; echo DROP_RC=\$?; echo '<5>mxfs-test: ghost run rework' > /dev/kmsg; cd $G && $REWORK" $(( RECOVER_BUDGET + 60 )) | tee -a "$EVID/log"
else
    # participant 0 rewrites f21-f30 in every directory, round after round,
    # while participant 1 lists them; the freeze lands with releases in flight
    # and participant 0's writes then wait on the frozen master, so the first
    # thing they do after the takeover is lock the records it imported
    on "$P1" "end=\$(( SECONDS + $CHURN_S + 30 )); n=0; while [ \$SECONDS -lt \$end ]; do for d in \$(seq 1 $DIRS); do ls -l $G/d\$d > /dev/null & done; wait; n=\$((n+1)); done; echo P1_LIST_ROUNDS=\$n" $(( CHURN_S + 40 )) > "$EVID/p1-churn.out" 2>&1 &
    p1job=$!
    on "$P0" "cd $G && end=\$(( SECONDS + $P0_CHURN_S )); n=0; while [ \$SECONDS -lt \$end ]; do for d in \$(seq 1 $DIRS); do for f in \$(seq 21 30); do echo r\$n > d\$d/f\$f; done; done; n=\$((n+1)); done; echo P0_CHURN_ROUNDS=\$n; echo '<5>mxfs-test: ghost run rework' > /dev/kmsg; $REWORK" $(( CHURN_S + EVICT_S + RECOVER_BUDGET + 60 )) > "$EVID/p0-churn.out" 2>&1 &
    p0job=$!
    sleep "$CHURN_S"
    say "freezing $P1VM (participant 1) mid-churn"
    $VIRSH suspend "$P1VM" 2>&1 | tee -a "$EVID/log"
    wait "$p0job"; echo "p0 churn rc=$?" >> "$EVID/p0-churn.out"
    kill "$p1job" 2>/dev/null; wait "$p1job" 2>/dev/null
    cat "$EVID/p0-churn.out" "$EVID/p1-churn.out" | tee -a "$EVID/log"
fi
say "P0 since the freeze: P-RELMARK-EVICT $(since_mark "$P0" 'ghost run master frozen' 'P-RELMARK-EVICT') P-TAUTH-RELEASE-UNACKED $(since_mark "$P0" 'ghost run master frozen' 'P-TAUTH-RELEASE-UNACKED') P-RBLK-RELEASE-SKIP-DEAD-MASTER $(since_mark "$P0" 'ghost run master frozen' 'P-RBLK-RELEASE-SKIP-DEAD-MASTER') fence-peer $(since_mark "$P0" 'ghost run master frozen' 'fence-peer')"

# 3. the master is dead to participant 0 by now; make it so for good
recovered() {
    local c
    c=$(since_mark "$P0" 'ghost run master frozen' 'P163-RECOVERY-COMPLETE')
    [[ "$c" =~ ^[0-9]+$ ]] && [ "$c" -gt 0 ]
}
wait_for "$RECOVER_BUDGET" "survivor $P0VM P163-RECOVERY-COMPLETE" recovered || exit 1
say "destroying $P1VM"
$VIRSH destroy "$P1VM" 2>&1 | tee -a "$EVID/log"
mounted "$P0" || { say "FAIL: the survivor lost its mount"; exit 1; }

# 4. what the re-work met
on "$P0" "journalctl -k -b --no-pager | sed -n '/mxfs-test: ghost run master frozen/,\$p' | grep -aE 'P-TAUTH-ADOPT-LOCAL|P-TAUTH-ADOPT-REGRANT|P-TAUTH-REAFFIRM|P-RELMARK-REINSTALL-REFUSED|P-TAUTH-IMPORT-RESIDUE|P-TAUTH-RELEASE-UNACKED|P-RBLK-RELEASE-SKIP|P163-RECOVERY-COMPLETE|mxfs-test'" 30 > "$EVID/p0-before-outage.txt"
ADOPTED=$(grep -c 'P-TAUTH-ADOPT-LOCAL' "$EVID/p0-before-outage.txt")
say "P0 before the outage: ADOPT-LOCAL $ADOPTED ADOPT-REGRANT $(grep -c 'P-TAUTH-ADOPT-REGRANT' "$EVID/p0-before-outage.txt") REINSTALL-REFUSED $(grep -c 'P-RELMARK-REINSTALL-REFUSED' "$EVID/p0-before-outage.txt")"
grep -a 'P-RELMARK-REINSTALL-REFUSED' "$EVID/p0-before-outage.txt" | head -5 | cut -c1-300 | tee -a "$EVID/log"

# 5. the outage
on "$P0" "echo '<5>mxfs-test: ghost run outage' > /dev/kmsg" 15
say "destroying $P0VM (the survivor, mount live)"
$VIRSH destroy "$P0VM" 2>&1 | tee -a "$EVID/log"
say "starting both VMs"
$VIRSH start "$P0VM" 2>&1 | tee -a "$EVID/log"
$VIRSH start "$P1VM" 2>&1 | tee -a "$EVID/log"
T0=$(date +%s)
refused() {
    local c
    c=$(on "$P0" "journalctl -k -b --no-pager | grep -a -c -E 'P-BOOT-REFUSED|P-BOOT-ADMISSION-REFUSED'" 20 | tail -1)
    [[ "$c" =~ ^[0-9]+$ ]] && [ "$c" -gt 0 ]
}
verdict=timeout
while [ $(( $(date +%s) - T0 )) -lt "$RESTART_BUDGET" ]; do
    if whole; then verdict=both-mounted; break; fi
    if refused; then verdict=refused; break; fi
    sleep 10
done
say "restart verdict: $verdict after $(( $(date +%s) - T0 ))s"
for h in "$P0" "$P1"; do
    on "$h" "journalctl -b --no-pager -o short-monotonic | grep -aE 'kernel: (mxfs|XFS|drbd)|mxfs-drbd'" 90 > "$EVID/boot0-$h.log"
    on "$h" "journalctl -b -1 --no-pager -o short-monotonic | grep -aE 'kernel: (mxfs|XFS|drbd)|mxfs-drbd|mxfs-test'" 90 > "$EVID/boot-1-$h.log"
done
say "P0 boot0: P227-FR-REFUSED-IMAGE $(grep -c 'P227-FR-REFUSED-IMAGE' "$EVID/boot0-$P0.log") ATOMIC-SKIP $(grep -c 'ATOMIC-SKIP' "$EVID/boot0-$P0.log")"
grep -ahE 'P-BOOT-(CLAIM|ADOPT |ADOPTED-REFUSED|REFUSING|REFUSED|COMPLETE)|P227-FR-REFUSED-(WHY|IMAGE)|ATOMIC-SKIP|mounted /dev/drbd0' "$EVID/boot0-$P0.log" "$EVID/boot0-$P1.log" | cut -c1-260 | head -40 | tee -a "$EVID/log"
[ "$verdict" = both-mounted ] || { say "FAIL ($verdict)"; exit 1; }

# 6. what participant 0 wrote and synced before the outage, read from both hosts
CHECK="bad=0; for d in \$(seq 1 $DIRS); do for f in \$(seq 2 30); do [ \"\$(cat $G/d\$d/f\$f 2>/dev/null)\" = \$f ] || { echo MISSING d\$d/f\$f; bad=\$((bad+1)); }; done; [ \"\$(cat $G/d\$d/g1 2>/dev/null)\" = 1 ] || { echo MISSING d\$d/g1; bad=\$((bad+1)); }; [ -e $G/d\$d/f1 ] && { echo STALE d\$d/f1; bad=\$((bad+1)); }; done; echo CONTENT_BAD=\$bad"
lost=0
for h in "$P0" "$P1"; do
    out=$(on "$h" "$CHECK" 60)
    grep -E 'MISSING|STALE' <<<"$out" | head -10 | sed "s/^/$h /" | tee -a "$EVID/log"
    n=$(grep -o 'CONTENT_BAD=[0-9]*' <<<"$out" | cut -d= -f2)
    if [ -z "$n" ]; then
        # a read-back that outran its 60 s is a pace failure, not lost data
        say "$h content check: no answer within 60 s (read-back too slow; content not judged)"
        slow=1
    else
        say "$h content check: $n bad"
        [ "$n" = 0 ] || lost=1
    fi
done
if [ "$lost" = 0 ] && [ "${slow:-0}" = 1 ]; then
    say "FAIL (pace): the read-back did not finish; nothing read back was wrong"
    exit 4
fi
if [ "$lost" = 0 ] && [ "$ADOPTED" -eq 0 ]; then
    say "NOT EXERCISED: participant 0 adopted no imported record, so the lap says nothing about the re-grant"
    exit 3
fi
[ "$lost" = 0 ] && { say "PASS"; exit 0; }
say "FAIL (content)"
exit 1
