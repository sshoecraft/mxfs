#!/bin/bash
# live_holder_wait.sh — closure arm for
# D-ACQUIRE-TIMEOUT-BEHIND-LIVE-HOLDER-FAILSTOPS-REQUESTER-0912.
#
# H holds F's grant with its release drain paused (the D-512 T2 pausepoint,
# stage 1 = before the dirty-page flush, PAUSE_MS long): a LIVE holder whose
# release outlasts the requester's acquire budget (TCP: 3 x 60 x 1 s = 180 s;
# CAW: 120 s base liveness-extended to a 480 s cap).  W reads F.  Before
# 0.75.28 W's read exhausted the budget at ~184 s and W shut its own
# filesystem down ('DLM inode lock unrecoverable', SHUTDOWN_CORRUPT_INCORE),
# withdrew, and was fenced (s517g).  From 0.75.28 W parks (P-LKWAIT-LIVE).
#
# Verdict: W's read returns ONLY after H's P-D512-RELPAUSE-END, ordered on H's
# own clock; md5_W == md5_H; W logged P-LKWAIT-LIVE (TCP at PAUSE_MS > 180 s;
# CAW only at PAUSE_MS > 480 s); zero shutdowns/splats on either node.
#
# the budget rule (derived): setup ~5 s + PAUSE_MS + drain (< 10 s) + captures ~10 s.
# The read bound is PAUSE_MS/1000 + 60: a read still outstanding 60 s after
# the pause end is a FAIL, never a reason to wait longer.
#
# WHICH NODE MASTERS THE TARGET IS NOT A DETAIL.  Which node masters a
# resource is a hash of its resource id, so the inode this harness happens to
# create decides whether W's acquire is a REMOTE request over the wire or a
# purely LOCAL queue insertion.  Those are different code paths with different
# waiter handling, and a lap that silently got the other one is not a
# comparison with the previous lap — it is a different measurement wearing the
# same label.  s579b scored a full set of PASSes that way: it drew a locally
# mastered inode where its predecessor had drawn a remotely mastered one, and
# the two laps' blocking-notification counts (238 vs 237) looked like a
# before/after when they were two different mechanisms.
#
# So the target is now CHOSEN, not accepted, and the choice is asserted.  The
# drop probe fires only on the remote-master send path, so its firing IS the
# proof that the inode is remotely mastered from W; MASTER=local inverts the
# test, MASTER=any keeps the old take-what-you-get behaviour.
#
# READERS>1 PUTS TWO WAITS ON ONE RESOURCE FROM ONE NODE, which is the only
# shape that can make two tasks share one acquisition record — the record is
# named for the resource and mode, not for the task, because the master keeps
# one entry per (resource, sender node).  Sharing means one age and one
# notification clock between them, and the first to finish retires it under
# the other.  A design consult predicted that matters; this is the lap that
# decides whether it happens at all.  At READERS>1 the lap ASSERTS the collide
# probe fired: an instrument that stays silent and a system with nothing to
# report are the same observation, so the assertion is what makes a later
# quiet lap mean something.
#
# GAP_MS>0 WIDENS THE GAP BETWEEN W'S ATTEMPTS (dl_acq_gap_ino, TEST ONLY).
# The requester registers a pending entry only for the one second each attempt
# waits; between attempts there is none.  Before 0.84.0 a grant landing in that
# gap was bounced — mirror unwound, release sent, the master retiring the
# grant and promoting the next waiter, and this wait's own next re-send
# queueing again at the BACK.  The gap is ordinarily 50 ms to 5 s, so the
# holder's release rarely lands in it; with GAP_MS the gap is most of each
# cycle and the release lands in it with probability GAP/(GAP+1000).  A lap
# where it did not (adopted=0) has not exercised the path and says so.  GAP_MS
# must stay under the acquisition table's 15 s idle retirement.
#
# Usage: tests/live_holder_wait.sh <label> [H=test1] [W=test2]
# Env:   MXFS_MNT (default /mnt/shared), PAUSE_MS (default 240000),
#        MASTER=remote|local|any (default remote), READERS (default 1),
#        GAP_MS (default 0 = off; 10000 is the between-attempt adoption lap).
# Leaves both nodes mounted and clears the pause knobs.  Exit 0 PASS, 1 FAIL,
# 2 INFRA/ABORT.
set -u
LABEL=${1:?label}
H=${2:-test1}; W=${3:-test2}
PAUSE_MS=${PAUSE_MS:-240000}
MASTER=${MASTER:-remote}
READERS=${READERS:-1}
GAP_MS=${GAP_MS:-0}
case "$GAP_MS" in ''|*[!0-9]*) echo "ABORT: GAP_MS must be an integer"; exit 2;; esac
[ "$GAP_MS" -lt 14000 ] || { echo "ABORT: GAP_MS must stay under the 15 s acquisition idle retirement"; exit 2; }
# KILL_AFTER_S>0: SIGKILL the (single) reader that many seconds into its wait
# behind the live holder.  The reader is blocked in open()'s cluster acquire —
# a fallible boundary — so from 0.84.2 it must leave the wait within a few
# seconds (the engine checks for a fatal signal at each one-second attempt
# boundary), abandon the acquisition by name (LOCK_CANCEL), and the master
# must remove the queued waiter (ack outcome 2) and go on serving: H's pause
# ends on its own clock and a fresh read afterwards returns H's bytes.  What
# this lap measures is that a killed task does not stay in a legitimate,
# receipted wait for as long as the holder's drain, and that nothing it
# queued at the master outlives it.
KILL_AFTER_S=${KILL_AFTER_S:-0}
case "$KILL_AFTER_S" in ''|*[!0-9]*) echo "ABORT: KILL_AFTER_S must be an integer"; exit 2;; esac
# TCP_FAULT_S>0 (D-0958): TCP_FAULT_AT_S seconds into W's wait, W's DLM link
# to H (TCP port 7600, both directions) is black-holed with iptables for
# TCP_FAULT_S seconds, then restored.  This is the REAL transport fault the
# per-inode request-drop knob only imitates: W's re-sends and H's receipts
# both stop, the socket sees retransmits or a reconnect, and the lease (UDP
# multicast) and the disk heartbeat keep membership alive.  The fault must
# stay under the transport's 40 s reconnect-or-dead budget: a longer one
# measures a death, not a repair.  What the lap asserts is unchanged (the read
# returns H's bytes after H's pause, no shutdown, no death); what it ADDS is
# the transport's own account of the fault -- reconnects, receipts going stale,
# the DEGRADED report and its retraction -- as evidence, not verdicts.
TCP_FAULT_S=${TCP_FAULT_S:-0}
TCP_FAULT_AT_S=${TCP_FAULT_AT_S:-60}
case "$TCP_FAULT_S" in ''|*[!0-9]*) echo "ABORT: TCP_FAULT_S must be an integer"; exit 2;; esac
case "$TCP_FAULT_AT_S" in ''|*[!0-9]*) echo "ABORT: TCP_FAULT_AT_S must be an integer"; exit 2;; esac
[ "$TCP_FAULT_S" -lt 40 ] || { echo "ABORT: TCP_FAULT_S must stay under the 40 s reconnect-or-dead budget"; exit 2; }
[ "$TCP_FAULT_S" -gt 0 ] && { [ "$KILL_AFTER_S" -ne 0 ] || [ "$READERS" -ne 1 ]; } && { echo "ABORT: TCP_FAULT_S needs READERS=1 and KILL_AFTER_S=0"; exit 2; }
[ "$TCP_FAULT_S" -gt 0 ] && [ $(( TCP_FAULT_AT_S + TCP_FAULT_S + 30 )) -ge $(( PAUSE_MS / 1000 )) ] && { echo "ABORT: the fault window must end at least 30 s before the pause does"; exit 2; }
# RW=write (D-0958, 0.84.10): W's operation behind the paused holder is a
# 4 KiB append + fsync through python's os.write — the buffered write path's
# fallible first ride — followed by md5sum.  A legitimate, receipted wait is
# never refused, so the write must WAIT for the holder's release and land:
# write_bytes=4096, and H's digest read after W's return equals W's.
# RW=create with TARGET=dir (D-0958, 0.84.11): the target is a DIRECTORY H
# holds in EX with its release paused, and W's operation behind it is a
# create of a new name in it through python's os.open(O_CREAT|O_EXCL) — the
# create's first acquire of the parent inside xfs_create, the fallible
# namespace boundary.  A legitimate, receipted wait is never refused, so the
# create must WAIT for the holder's release and land: create_fd returned,
# create_rc=0, and H's listing of the directory after W's return equals W's.
# The candidates, the probe's re-dirty and the digest are all directory
# forms of the file ones (mkdir + an entry; an entry added; the sorted names).
# RW=unlink|rename|link|symlink with TARGET=dir (0.84.12): the same control
# for the other namespace operations.  Each acts on the directory's `seed`
# entry (unlink, rename source, link source) and/or writes WNAME (rename
# target, link, symlink) through python's os.<op>; the op must WAIT for the
# holder's release and land, and H's cold listing afterwards equals W's.
# RW=lookup with TARGET=dir (0.84.13): W stats the directory's `seed` entry
# by path behind the paused holder — the lookup's own acquires of the
# directory (the consumer refresh and the directory read), both fallible
# since 0.84.13; a receipted wait must land (lookup_ino, rc 0), the listing
# is unchanged.  RW=dio_unaligned with TARGET=file (0.84.13): the candidates
# are fallocated (unwritten past the first block) and W's operation is one
# O_DIRECT pwrite of 4096 bytes at offset 8704 inside the unwritten region
# — the first ride waits behind the holder, the overwrite-only mapping
# answers -EAGAIN, and the exclusive retry's ride (fallible since 0.84.13)
# takes the EX; the write must land (dio_write_bytes=4096) and H must read
# W's bytes.  HOLDER=pr (0.84.14, RW=dio_unaligned only): H re-dirties and
# syncs, W reads (H's EX is drained with nothing armed, W caches PR), H reads
# (a clean PR beside W's) and only THEN arms the pause — so W's open and the
# write's first ride are cached fast paths and the first request W sends is
# the mtime/ctime update's ILOCK_EXCL (xfs_vn_update_time, fallible under the
# write since 0.84.14); that EX revokes H's PR, H's release is the paused
# one, and the write must wait it out and land.
RW=${RW:-read}
TARGET=${TARGET:-file}
HOLDER=${HOLDER:-ex}
case "$HOLDER" in ex|pr) ;; *) echo "ABORT: HOLDER must be ex or pr"; exit 2;; esac
[ "$HOLDER" = pr ] && [ "$RW" != dio_unaligned ] && { echo "ABORT: HOLDER=pr is the timestamp-acquire shape and needs RW=dio_unaligned"; exit 2; }
case "$RW" in read|write|dio_unaligned|chmod|fallocate|getxattr|listxattr|setxattr|removexattr|setxattr_nofork|mmap_read|mmap_write|create|unlink|rename|link|symlink|lookup) ;; *) echo "ABORT: RW must be read, write, dio_unaligned, chmod, fallocate, getxattr, listxattr, setxattr, removexattr, setxattr_nofork, mmap_read, mmap_write, create, unlink, rename, link, symlink or lookup"; exit 2;; esac
# RW=setxattr_nofork: as RW=setxattr on an inode whose attr fork was removed
# first (the driver sets and removes user.d958 before announcing), so the
# change's first request is the add-fork reservation.
# RW=mmap_read / RW=mmap_write (0.84.21): the same driver maps the file
# MAP_SHARED before the re-dirty and, on release, a forked child reads the
# first 4 bytes (a read fault) or stores b'mmw!' at offset 0 and msyncs (a
# write fault).  The fault's acquires (the counted hold, the timestamp
# update) must wait the pause out and land — no SIGBUS, no
# P958-FAULT-REFUSED — and a store must be visible cold on H.
# RW=setxattr / RW=removexattr (0.84.20): the same driver issues one
# fsetxattr (no attribute set beforehand: the add-fork reservation is the
# first request) or one fremovexattr (user.d958 set beforehand).  Each must
# wait the pause out and land, visible cold on H, with no
# P958-XATTRSET-REFUSED / P958-XATTR-REFUSED.
# RW=getxattr / RW=listxattr (0.84.19): the same parked driver sets
# user.d958=v958 on its fd before announcing and, on release, issues one
# fgetxattr / flistxattr; the read's attr-fork PR (xfs_attr_get /
# xfs_attr_list, fallible since 0.84.19) is the request the paused release
# answers.  It must wait the pause out and return the value, with no
# P958-XATTR-REFUSED, and change nothing.
# RW=chmod / RW=fallocate (0.84.15): W's operation is one fchmod(0640) or one
# fallocate(1 MiB, 4096: the size grows) through an fd that tests/held_fd_op.py
# opened BEFORE H re-dirtied the target (so H's EX revoked W's grant and the
# operation's own EX — the ILOCK_EXCL inside xfs_trans_alloc_ichange, or
# fallocate's IOLOCK_EXCL take, both fallible since 0.84.15 — is the request
# H's paused release answers).  The change must land (op_ok=1, rc 0), H must
# see it cold, and the file's bytes must be unchanged on both nodes.
case "$RW" in chmod|fallocate|getxattr|listxattr|setxattr|removexattr|setxattr_nofork|mmap_read|mmap_write) ATTROP=$RW ;; *) ATTROP="" ;; esac
[ -n "$ATTROP" ] && [ "$TARGET" != file ] && { echo "ABORT: RW=$RW needs TARGET=file"; exit 2; }
case "$TARGET" in file|dir) ;; *) echo "ABORT: TARGET must be file or dir"; exit 2;; esac
case "$RW" in create|unlink|rename|link|symlink|lookup) NSOP=$RW ;; *) NSOP="" ;; esac
[ -n "$NSOP" ] && [ "$TARGET" != dir ] && { echo "ABORT: RW=$RW needs TARGET=dir"; exit 2; }
[ "$TARGET" = dir ] && [ -z "$NSOP" ] && { echo "ABORT: TARGET=dir is the namespace control; use RW=create|unlink|rename|link|symlink|lookup"; exit 2; }
[ "$RW" != read ] && { [ "$READERS" -ne 1 ] || [ "$KILL_AFTER_S" -ne 0 ] || [ "$TCP_FAULT_S" -ne 0 ]; } && { echo "ABORT: RW=$RW needs READERS=1, KILL_AFTER_S=0 and TCP_FAULT_S=0"; exit 2; }
# The name W writes in the target directory, and the entry it reads.
WNAME=.${RW}_by_w
ENAME=seed
[ "$KILL_AFTER_S" -gt 0 ] && [ "$READERS" -ne 1 ] && { echo "ABORT: KILL_AFTER_S needs READERS=1"; exit 2; }
case "$READERS" in ''|*[!0-9]*|0) echo "ABORT: READERS must be a positive integer"; exit 2;; esac
case "$MASTER" in remote|local|any) ;; *) echo "ABORT: MASTER must be remote, local or any"; exit 2;; esac
cd "$(dirname "$0")/.." || exit 2
SSH=tools/mxfs_sshpass.sh
MNT=${MXFS_MNT:-/mnt/shared}
P=/sys/module/mxfs/parameters
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_livewait_$LABEL
mkdir -p "$OUT"
# rs/rsx/capture_require (tests/lib/rig.sh): every capture a verdict is taken
# from is proven to hold its tool's shape first; a failed acquisition is an
# ABORT, never a count of zero.  A node's kernel log is always taken from the
# lap marker, so the marker line IS its shape.
. "$(dirname "$0")/lib/rig.sh"
fails=0
# ck: tests/lib/rig.sh (sourced above) provides it, and its version ABORTs on an EMPTY value instead of printing a FAIL about MXFS
hd() { rsx 20 "$1" "dmesg | sed -n \"/$MARK/,\\\$p\""; }
# hdcap <node> <file>: the node's log from the lap marker, validated
hdcap() { hd "$1" > "$2"; capture_require "$2" "$MARK" "the kernel log on $1 from the lap marker (${2##*/})"; }
# probe <node> <timeout> <file> <shape> <what> <cmd>: a one-shot remote
# measurement whose lines feed a verdict, validated
probe() { rsx "$2" "$1" "$6" > "$3"; capture_require "$3" "$4" "$5"; }
# W's operation under test: a timeout (124) IS the stall the verdict
# measures, so it is kept as the result; anything else that leaves no
# md5_rc= line is a failed instrument
wread_require() { [ "$1" = 124 ] || capture_require "$OUT/w_read.txt" 'md5_rc=' "W's operation under test"; }
t0=$(date +%s)
el() { echo $(( $(date +%s) - t0 )); }
clear_knobs() {
    timeout 20 $SSH "$H" "echo 0 > $P/dbg_rel_pause_ms; echo 0 > $P/dbg_rel_pause_stage; echo 0 > $P/dbg_rel_pause_ino; echo 0 > $P/dbg_probe_ino" >/dev/null 2>&1
    timeout 20 $SSH "$W" "echo 0 > $P/dl_acq_gap_ino; echo 0 > $P/dl_acq_gap_ms; echo 0 > $P/dbg_probe_ino" >/dev/null 2>&1
}
# The notification probes this lap reads (P7S-BAST-FIRE on the master,
# P7B-BASTNOTIFY on the holder) print only for inode numbers up to 256 unless
# the inode is named here; on an aged filesystem every candidate is above that
# and the lap read them all as undetermined (s585a).  Named on BOTH nodes,
# because which one masters the inode is exactly what is being asked.
probe_ino() { for n in "$H" "$W"; do timeout 15 $SSH "$n" "echo $1 > $P/dbg_probe_ino" >/dev/null 2>&1; done; }

echo "=== live_holder_wait label=$LABEL H=$H W=$W pause_ms=$PAUSE_MS out=$OUT $(date -u +%FT%TZ) ==="
TREESV=$(modinfo mxfs.ko 2>/dev/null | sed -n 's/^srcversion: *//p')
for n in "$H" "$W"; do
    info=$(timeout 15 $SSH "$n" "echo sv=\$(cat /sys/module/mxfs/srcversion) ft=\$(cat $P/force_transport) m=\$(grep -c ' mxfs ' /proc/mounts) k=\$(test -w $P/dl_drop_lockreq_ino && echo 1 || echo 0)" 2>/dev/null | filt | tr -d '\r')
    echo "  INFO $n $info"
    # The master is now established from which node LOGS a blocking
    # notification, not from whether a request-drop knob fires, so the knob is
    # no longer a precondition for this lap.  Its presence is still reported
    # because a build without it is a build older than the selection probe.
    [[ "$info" == *"sv=$TREESV"* ]] || { echo "ABORT: $n srcversion != tree '$TREESV' ($info)"; exit 2; }
    [[ "$info" == *"m=1"* ]] || { echo "ABORT: $n not mounted ($info)"; exit 2; }
    [[ "$info" == *"ft=0"* ]] && ncaw=$(( ${ncaw:-0} + 1 ))
done
# CAW has no lock master: grants live in on-disk slots, so no node logs a
# master's blocking notification and "which node masters the target" has no
# answer.  Both nodes on force_transport=0 selects the CAW lap: the target is
# the first candidate, the master-side notification budget is not scored, and
# the wait is witnessed by CAW's own probes (P-WAIT-EXTEND past the 120 s base,
# P-LKWAIT-LIVE past the 480 s cap).  Everything else scores the same.
CAW=0; [ "${ncaw:-0}" = 2 ] && CAW=1
echo "  INFO transport=$([ $CAW = 1 ] && echo caw || echo tcp)"
if [ "$GAP_MS" -gt 0 ]; then
    g=$(timeout 15 $SSH "$W" "test -w $P/dl_acq_gap_ino && test -w $P/dl_acq_gap_ms && echo 1 || echo 0" 2>/dev/null | filt | tr -dc '0-9')
    [ "${g:-0}" = "1" ] || { echo "ABORT: $W has no writable dl_acq_gap_ino/dl_acq_gap_ms knob (build older than 0.84.0)"; exit 2; }
fi
for n in "$H" "$W"; do
    g=$(timeout 15 $SSH "$n" "test -w $P/dbg_probe_ino && echo 1 || echo 0" 2>/dev/null | filt | tr -dc '0-9')
    [ "${g:-0}" = "1" ] || { echo "ABORT: $n has no writable dbg_probe_ino knob (build older than 0.84.0); the locality probe is blind above ino 256"; exit 2; }
done
MARK="LIVEWAIT-$LABEL-$$"
for n in "$H" "$W"; do timeout 12 $SSH "$n" "echo '$MARK' > /dev/kmsg" >/dev/null 2>&1; done

DM="dmesg | awk '/$MARK/{f=1} f'"
disarm_drop() { timeout 20 $SSH "$W" "echo 0 > $P/dl_drop_lockreq_ino" >/dev/null 2>&1; }

# 1. Pick a target whose master is the one this lap means to measure.  H writes
#    eight candidates; W probes each with the request-drop knob, which sits on
#    the REMOTE-master send path only, so the probe firing is the proof that
#    the inode is remotely mastered from W and its silence is the proof that it
#    is not.  Counts are scoped to this run's kernel-log mark: an unscoped
#    count inherits the previous lap's hits and picks the wrong file.
# The digest a node reports for the target: the file's bytes, or the sorted
# names of the directory.  Both sides of every comparison use this.
dgst() { if [ "$TARGET" = dir ]; then echo "ls -1A '$1' | sort | md5sum | cut -d' ' -f1"; else echo "md5sum '$1' | cut -d' ' -f1"; fi; }
# H's re-dirty of a target (takes EX): a rewrite of the file, or a new entry
# in the directory.  $2 names the entry so repeated re-dirties are distinct.
redirty() { if [ "$TARGET" = dir ]; then echo ": > '$1/$2'"; elif [ "$RW" = dio_unaligned ]; then echo "dd if=/dev/urandom of='$1' bs=4096 count=1 conv=notrunc status=none"; else echo "dd if=/dev/urandom of='$1' bs=4096 count=8 status=none"; fi; }
if [ "$RW" = dio_unaligned ]; then
# 64 KiB fallocated, first block written: the region past it stays unwritten
# so W's unaligned overwrite-only attempt answers -EAGAIN and retries EX.
timeout 45 $SSH "$H" "
    for i in 1 2 3 4 5 6 7 8; do
        f='$MNT/.livewait_${LABEL}_'\$i
        rm -f \"\$f\"; fallocate -l 65536 \"\$f\" || exit 1
        dd if=/dev/urandom of=\"\$f\" bs=4096 count=1 conv=notrunc status=none || exit 1
        echo \$i \$(stat -c %i \"\$f\")
    done
    sync
  " 2>"$OUT/h_setup.err" | filt > "$OUT/h_cands.txt"
elif [ "$TARGET" = dir ]; then
timeout 45 $SSH "$H" "
    for i in 1 2 3 4 5 6 7 8; do
        f='$MNT/.livewait_${LABEL}_'\$i
        mkdir -p \"\$f\" && : > \"\$f/seed\" || exit 1
        echo \$i \$(stat -c %i \"\$f\")
    done
    sync
  " 2>"$OUT/h_setup.err" | filt > "$OUT/h_cands.txt"
else
timeout 45 $SSH "$H" "
    for i in 1 2 3 4 5 6 7 8; do
        f='$MNT/.livewait_${LABEL}_'\$i
        dd if=/dev/urandom of=\"\$f\" bs=4096 count=8 status=none || exit 1
        echo \$i \$(stat -c %i \"\$f\")
    done
    sync
  " 2>"$OUT/h_setup.err" | filt > "$OUT/h_cands.txt"
fi
[ "$(grep -ac . "$OUT/h_cands.txt")" = "8" ] || {
    echo "ABORT: H wrote $(grep -ac . "$OUT/h_cands.txt")/8 candidates: [$(filt < "$OUT/h_setup.err" | tail -3 | tr '\n' ' ')]"
    clear_knobs; exit 2; }

ino=""; CAND=""; MLOC=""
if [ "$CAW" = 1 ]; then
    read -r CAND ino < "$OUT/h_cands.txt"; MLOC=caw
fi
[ -n "$ino" ] || while read -r idx cino <&3; do
    [ -n "$cino" ] || continue
    cf="$MNT/.livewait_${LABEL}_$idx"
    # H holds a conflicting grant, W reads: the MASTER of this inode is the
    # node that fires the blocking notification, and it says so in its own
    # log.  BOTH answers are then first-hand.
    #
    # The previous probe armed the request-drop knob and called a candidate
    # LOCAL when the knob did not fire.  That reads an ABSENCE as an answer,
    # and the absence has more than one cause: s580b picked ino 140 that way,
    # called it local, and measured the remote path -- test1 fired 26
    # notifications for it while test2, the node the lap was counting, fired
    # none.  A probe whose two branches rest on different quality of evidence
    # will keep doing that, so neither branch rests on silence now.
    probe_ino "$cino"
    timeout 25 $SSH "$H" "$(redirty "$cf" probe_by_h); sync" </dev/null >/dev/null 2>&1
    timeout 25 $SSH "$W" "echo 3 > /proc/sys/vm/drop_caches; $(dgst "$cf") >/dev/null 2>&1" </dev/null >/dev/null 2>&1
    sleep 3
    f1=$(timeout 20 $SSH "$H" "$DM | grep -ac 'P7S-BAST-FIRE ino=$cino '" </dev/null 2>/dev/null | filt | tr -dc '0-9')
    f2=$(timeout 20 $SSH "$W" "$DM | grep -ac 'P7S-BAST-FIRE ino=$cino '" </dev/null 2>/dev/null | filt | tr -dc '0-9')
    f1=${f1:-0}; f2=${f2:-0}
    if   [ "$f1" -ge 1 ] && [ "$f2" -eq 0 ]; then loc=remote
    elif [ "$f2" -ge 1 ] && [ "$f1" -eq 0 ]; then loc=local
    else loc=undetermined
    fi
    echo "  INFO candidate idx=$idx ino=$cino master=$loc (P7S-BAST-FIRE $H=$f1 $W=$f2) at +$(el)s"
    [ "$loc" = "undetermined" ] && continue
    if [ "$MASTER" = "any" ] || [ "$loc" = "$MASTER" ]; then
        ino=$cino; CAND=$idx; MLOC=$loc; break
    fi
done 3< "$OUT/h_cands.txt"
[ -n "$ino" ] || {
    echo "ABORT: none of the eight candidates is $MASTER-mastered from $W — this lap cannot measure the path it names"
    disarm_drop; clear_knobs; exit 2; }
F="$MNT/.livewait_${LABEL}_$CAND"
probe_ino "$ino"
echo "  INFO target ino=$ino file=$F master=$MLOC (wanted $MASTER) at +$(el)s"

# 1a. RW=chmod / RW=fallocate: park W's driver holding an O_RDWR fd on the
#     target NOW, before H re-dirties it — H's EX then revokes the grant the
#     open cached, and the operation's own EX is the first request W sends
#     once the go marker appears.  Opened inside the wait, the open's own
#     acquire would meet the paused release first and the lap would measure
#     open, not the operation.
if [ -n "$ATTROP" ]; then
    timeout 20 $SSH "$W" "rm -f /tmp/lw_w.out /tmp/lw_op.pid /tmp/lw_op.open /tmp/lw_go" </dev/null >/dev/null 2>&1
    timeout 25 $SSH "$W" "nohup sh -c 'echo \$\$ > /tmp/lw_op.pid; exec python3 /src/mxfs/tests/held_fd_op.py \"$F\" $ATTROP /tmp/lw_op.open /tmp/lw_go' > /tmp/lw_w.out 2>&1 &" </dev/null >/dev/null 2>&1
    opened=0
    for i in 1 2 3 4 5 6 7 8 9 10; do
        o=$(timeout 15 $SSH "$W" "test -e /tmp/lw_op.open && echo 1 || echo 0" </dev/null 2>/dev/null | filt | tr -dc '0-9')
        [ "${o:-0}" = "1" ] && { opened=1; break; }
        sleep 2
    done
    OPPID=$(timeout 15 $SSH "$W" "cat /tmp/lw_op.pid" </dev/null 2>/dev/null | filt | tr -dc '0-9')
    echo "  INFO RW=$RW: W parked holding an O_RDWR fd on the target pid=${OPPID:-none} opened=$opened at +$(el)s"
    [ "$opened" = "1" ] && [ -n "$OPPID" ] || { echo "ABORT: W could not park holding an open fd on the target"; clear_knobs; exit 2; }
fi

# 1b. Arm the pause on the chosen inode and re-dirty it, so H holds the grant
#     with unflushed pages.
#     ORDER DIFFERS BY TARGET, and it is not a style choice.  A file: arm, then
#     re-dirty — H holds nothing after W's probe read, so its dd takes EX
#     without releasing anything.  A directory: re-dirty, THEN arm — after W's
#     probe listing H still caches PR on the directory, and its own create's
#     PR-to-EX upgrade is answered -EDEADLK and goes through the self-demote
#     release drain, which is exactly where the pause sits.  Measured (s595b):
#     armed first, H's own `: > held_by_h` parked 240 s behind its own pause
#     (P-D512-RELPAUSE from the bast worker with selfdem=1, H's create in
#     mxfs_ilock_fallible under it), the digest `ls` queued behind that, and
#     the lap aborted on an empty capture.
if [ "$TARGET" = dir ]; then
timeout 25 $SSH "$H" "
    $(redirty "$F" held_by_h) || { echo dd2_rc=\$? >&2; exit 1; }
    echo $ino > $P/dbg_rel_pause_ino
    echo 1 > $P/dbg_rel_pause_stage
    echo $PAUSE_MS > $P/dbg_rel_pause_ms
    $(dgst "$F")
  " 2>>"$OUT/h_setup.err" | filt > "$OUT/h_setup.txt"
elif [ "$HOLDER" = pr ]; then
# 0.84.14: the holder keeps a CLEAN PR.  H re-dirties and syncs (EX), W
# reads (BAST, H's EX drained with nothing armed, W caches PR), H reads
# again (PR beside W's PR), and the pause is armed last.  W's write then
# fast-paths its open and its shared ride on the cached PR, and its
# timestamp update's EX is the request that revokes H's PR — the release
# that pauses.
timeout 40 $SSH "$H" "$(redirty "$F" held_by_h) || { echo dd2_rc=\$? >&2; exit 1; }; sync" 2>>"$OUT/h_setup.err" | filt >/dev/null
wpr=$(timeout 40 $SSH "$W" "$(dgst "$F")" </dev/null 2>>"$OUT/h_setup.err" | filt | grep -aoE '^[0-9a-f]{32}' | head -1)
echo "  INFO HOLDER=pr: H re-dirtied, W cached PR (md5=${wpr:-none}) at +$(el)s"
timeout 40 $SSH "$H" "
    $(dgst "$F")
    echo $ino > $P/dbg_rel_pause_ino
    echo 1 > $P/dbg_rel_pause_stage
    echo $PAUSE_MS > $P/dbg_rel_pause_ms
  " 2>>"$OUT/h_setup.err" | filt > "$OUT/h_setup.txt"
[ -n "$wpr" ] && [ "$wpr" = "$(grep -aoE '^[0-9a-f]{32}' "$OUT/h_setup.txt" | head -1)" ] || { echo "ABORT: HOLDER=pr: W's cached read does not match H's (W=${wpr:-none})"; clear_knobs; exit 2; }
else
timeout 25 $SSH "$H" "
    echo $ino > $P/dbg_rel_pause_ino
    echo 1 > $P/dbg_rel_pause_stage
    echo $PAUSE_MS > $P/dbg_rel_pause_ms
    $(redirty "$F" held_by_h) || { echo dd2_rc=\$? >&2; exit 1; }
    $(dgst "$F")
  " 2>>"$OUT/h_setup.err" | filt > "$OUT/h_setup.txt"
fi
md5_h=$(grep -aoE '^[0-9a-f]{32}' "$OUT/h_setup.txt" | head -1)
[ -n "$md5_h" ] || {
    echo "ABORT: H could not arm the pause / re-dirty: stdout=[$(tr '\n' ' ' < "$OUT/h_setup.txt")] stderr=[$(filt < "$OUT/h_setup.err" | tail -5 | tr '\n' ' ')]"
    clear_knobs; exit 2; }
echo "  INFO ino=$ino md5_H=$md5_h at +$(el)s"
# The attribute controls compare mode, blocks and size before and after: the
# reference is H's view after its re-dirty (H holds EX; the stat is local).
attr_h0=""
if [ -n "$ATTROP" ]; then
    value_now_into attr_h0 "$H" 20 "$OUT/rv_attr_h0_1.txt" '^[0-9]+_[0-9]+$' "attr_h0 on $H" "stat -c '%a_%s' '$F'"; attr_h0=$(printf '%s\n' "$attr_h0" | grep -aoE '^[0-9]+_[0-9]+')
    echo "  INFO RW=$RW: reference mode_size on H after the re-dirty = ${attr_h0:-none} at +$(el)s"
    [ -n "$attr_h0" ] || { echo "ABORT: H could not stat the target"; clear_knobs; exit 2; }
fi
tpause=$(date +%s)

# 1c. GAP_MS: arm the between-attempt gap on W for the chosen inode only.
#     Armed AFTER the target is chosen and BEFORE the read, so the candidate
#     probes above ran at the natural cadence.
if [ "$GAP_MS" -gt 0 ]; then
    timeout 20 $SSH "$W" "echo $ino > $P/dl_acq_gap_ino; echo $GAP_MS > $P/dl_acq_gap_ms" >/dev/null 2>&1
    echo "  INFO gap armed on $W: ino=$ino gap_ms=$GAP_MS at +$(el)s"
fi

# 2. W reads F: BAST -> H enters the pause; W must wait it out.  With a gap
#    the claim of a grant that landed in it happens at the NEXT attempt, up
#    to GAP_MS + 1 s later; the 60 s slack covers that.
bound=$(( PAUSE_MS / 1000 + 60 ))
s0=$(date +%s)
# One ssh, READERS concurrent md5sums of the SAME file, each with its own
# output and its own captured exit code.  A bare `wait` that discarded the
# per-reader rc would turn a reader that failed into a lap that passed.  Each
# reader's pid is written before it is waited on, so a KILL lap can name it.
if [ "$KILL_AFTER_S" -gt 0 ]; then
    # Launch detached, kill from a second ssh, then collect.
    timeout 30 $SSH "$W" "
        rm -f /tmp/lw_raw_1.out /tmp/lw_rc_1.out /tmp/lw_pid_1
        nohup sh -c 'md5sum \"$F\" > /tmp/lw_raw_1.out 2>&1 & p=\$!; echo \$p > /tmp/lw_pid_1; wait \$p; echo \$? > /tmp/lw_rc_1.out' >/dev/null 2>&1 &
      " </dev/null >/dev/null 2>&1
    sleep "$KILL_AFTER_S"
    RPID=$(timeout 15 $SSH "$W" "cat /tmp/lw_pid_1" </dev/null 2>/dev/null | filt | tr -dc '0-9')
    kst=$(timeout 15 $SSH "$W" "awk '{print \$3}' /proc/$RPID/stat 2>/dev/null; kill -9 $RPID 2>/dev/null && echo killed" </dev/null 2>/dev/null | filt | tr '\n' ' ')
    tkill=$(date +%s)
    echo "  INFO KILL: reader pid=$RPID state-before=[$kst] SIGKILL sent at +$(el)s ($KILL_AFTER_S s into the wait)"
    gone_s=""
    for i in $(seq 1 30); do
        a=$(timeout 15 $SSH "$W" "test -d /proc/$RPID && echo 1 || echo 0" </dev/null 2>/dev/null | filt | tr -dc '0-9')
        [ "${a:-1}" = "0" ] && { gone_s=$(( $(date +%s) - tkill )); break; }
        sleep 1
    done
    echo "  INFO KILL: reader gone_after=${gone_s:-not-within-30s}s at +$(el)s"
    probe "$W" 15 "$OUT/w_read.txt" 'md5_rc=' "the killed reader's output on $W" "cut -d' ' -f1 /tmp/lw_raw_1.out 2>/dev/null; echo md5_rc=\$(cat /tmp/lw_rc_1.out 2>/dev/null)"
    rrc=0
elif [ "$TCP_FAULT_S" -gt 0 ]; then
    # The reader runs detached on W; the fault is applied from a second ssh
    # and removed by a third, each bounded.  The rules name H's address and
    # port 7600 on either end, so ssh (22), the lease (UDP 7603) and the
    # discovery multicast are untouched.  A leftover rule would black-hole
    # the next lap, so the removal is retried and asserted.
    HIP=$(timeout 15 $SSH "$W" "getent ahostsv4 '$H' | awk 'NR==1{print \$1}'" </dev/null 2>/dev/null | filt | tr -dc '0-9.')
    [ -n "$HIP" ] || { echo "ABORT: $W cannot resolve $H"; clear_knobs; exit 2; }
    timeout 30 $SSH "$W" "
        rm -f /tmp/lw_raw_1.out /tmp/lw_rc_1.out /tmp/lw_pid_1
        nohup sh -c 'md5sum \"$F\" > /tmp/lw_raw_1.out 2>&1 & p=\$!; echo \$p > /tmp/lw_pid_1; wait \$p; echo \$? > /tmp/lw_rc_1.out' >/dev/null 2>&1 &
      " </dev/null >/dev/null 2>&1
    sleep "$TCP_FAULT_AT_S"
    tfault=$(date +%s)
    for n in "$H" "$W"; do timeout 12 $SSH "$n" "echo 'LIVEWAIT-TCPFAULT-$LABEL' > /dev/kmsg" </dev/null >/dev/null 2>&1; done
    measure "$W" 15 "$OUT/rv_fon_2.txt" '^[0-9]+$' "the black-hole rule install on $W" "iptables -I INPUT -p tcp -s $HIP -m multiport --ports 7600 -j DROP && iptables -I OUTPUT -p tcp -d $HIP -m multiport --ports 7600 -j DROP && echo dropped; ss -tn state established '( sport = :7600 or dport = :7600 )' | grep -c '$HIP' || [ \$? = 1 ]"; fon=$(cat "$OUT/rv_fon_2.txt" | tr '\n' ' ')
    echo "  INFO TCP fault: $W black-holed its DLM link to $H ($HIP:7600) at +$(el)s, $TCP_FAULT_AT_S s into the wait, for $TCP_FAULT_S s: [$fon]"
    ck "the black-hole rules were installed on $W" "$(echo "$fon" | grep -ac dropped)" "1"
    sleep "$TCP_FAULT_S"
    foff=""
    for i in 1 2 3; do
        value_now_into foff "$W" 15 "$OUT/rv_foff_3.txt" '^[0-9]+$' "foff on $W" "iptables -D INPUT -p tcp -s $HIP -m multiport --ports 7600 -j DROP; iptables -D OUTPUT -p tcp -d $HIP -m multiport --ports 7600 -j DROP; iptables -S | grep -c '7600' || [ \$? = 1 ]"
        [ "${foff:-1}" = "0" ] && break
        sleep 2
    done
    tfault_end=$(( $(date +%s) - tfault ))
    for n in "$H" "$W"; do timeout 12 $SSH "$n" "echo 'LIVEWAIT-TCPFAULT-END-$LABEL' > /dev/kmsg" </dev/null >/dev/null 2>&1; done
    echo "  INFO TCP fault: rules removed on $W after ${tfault_end}s (rules left matching 7600: ${foff:-?}) at +$(el)s"
    ck "no black-hole rule was left behind on $W" "${foff:-1}" "0"
    # collect the detached reader, bounded like the foreground read
    left=$(( bound - ( $(date +%s) - s0 ) )); [ "$left" -lt 5 ] && left=5
    for i in $(seq 1 "$left"); do
        d=$(timeout 15 $SSH "$W" "test -f /tmp/lw_rc_1.out && echo 1 || echo 0" </dev/null 2>/dev/null | filt | tr -dc '0-9')
        [ "${d:-0}" = "1" ] && break
        sleep 1
    done
    probe "$W" 15 "$OUT/w_read.txt" 'md5_rc=' "the detached reader's output on $W" "cut -d' ' -f1 /tmp/lw_raw_1.out 2>/dev/null; echo md5_rc=\$(cat /tmp/lw_rc_1.out 2>/dev/null)"
    rrc=$([ "${d:-0}" = "1" ] && echo 0 || echo 124)
elif [ -n "$NSOP" ]; then
# The operation is the whole wait: its first acquire of the directory is
# the PR-to-EX request that H's paused release answers.  The listing
# afterwards is W's own view of the directory it now holds.
case "$NSOP" in
create)  PYOP="fd=os.open('$F/$WNAME', os.O_CREAT|os.O_EXCL|os.O_WRONLY, 0o644); print('create_fd=%d' % fd)" ;;
unlink)  PYOP="os.unlink('$F/$ENAME'); print('unlink_ok=1')" ;;
rename)  PYOP="os.rename('$F/$ENAME', '$F/$WNAME'); print('rename_ok=1')" ;;
link)    PYOP="os.link('$F/$ENAME', '$F/$WNAME'); print('link_ok=1')" ;;
symlink) PYOP="os.symlink('target_of_w', '$F/$WNAME'); print('symlink_ok=1')" ;;
lookup)  PYOP="st=os.stat('$F/$ENAME'); print('lookup_ok=1'); print('lookup_ino=%d' % st.st_ino)" ;;
esac
rsx "$bound" "$W" "
    rm -f /tmp/lw_w.out
    python3 -c \"import os; $PYOP\" > /tmp/lw_w.out 2>&1
    echo ${NSOP}_rc=\$? >> /tmp/lw_w.out
    $(dgst "$F") > /tmp/lw_raw_1.out 2>&1; echo \$? > /tmp/lw_rc_1.out
    cut -d' ' -f1 /tmp/lw_raw_1.out
    echo md5_rc=\$(cat /tmp/lw_rc_1.out)
    cat /tmp/lw_w.out
  " > "$OUT/w_read.txt"
rrc=$?
wread_require "$rrc"
elif [ "$RW" = dio_unaligned ]; then
rsx "$bound" "$W" "
    rm -f /tmp/lw_w.out
    python3 -c \"import os,mmap; fd=os.open('$F', os.O_WRONLY|os.O_DIRECT); m=mmap.mmap(-1, 4096); m.write(b'd'*4096); n=os.pwrite(fd, m, 8704); os.fsync(fd); print('dio_write_bytes=%d' % n)\" > /tmp/lw_w.out 2>&1
    echo dio_write_rc=\$? >> /tmp/lw_w.out
    md5sum '$F' > /tmp/lw_raw_1.out 2>&1; echo \$? > /tmp/lw_rc_1.out
    cut -d' ' -f1 /tmp/lw_raw_1.out
    echo md5_rc=\$(cat /tmp/lw_rc_1.out)
    cat /tmp/lw_w.out
  " > "$OUT/w_read.txt"
rrc=$?
wread_require "$rrc"
elif [ -n "$ATTROP" ]; then
# Release the parked driver and wait for it to exit (its output file holds
# op_ok=1 or op_rc=-E); then W's own view of the attributes and the bytes.
rsx "$bound" "$W" "
    : > /tmp/lw_go
    i=0; while [ -d /proc/$OPPID ] && [ \$i -lt $bound ]; do sleep 1; i=\$((i+1)); done
    echo ${ATTROP}_rc=\$([ -d /proc/$OPPID ] && echo 124 || echo 0) >> /tmp/lw_w.out
    echo attr_W=\$(stat -c '%a_%s' '$F') >> /tmp/lw_w.out
    md5sum '$F' > /tmp/lw_raw_1.out 2>&1; echo \$? > /tmp/lw_rc_1.out
    cut -d' ' -f1 /tmp/lw_raw_1.out
    echo md5_rc=\$(cat /tmp/lw_rc_1.out)
    cat /tmp/lw_w.out
  " > "$OUT/w_read.txt"
rrc=$?
wread_require "$rrc"
elif [ "$RW" = write ]; then
rsx "$bound" "$W" "
    rm -f /tmp/lw_w.out
    python3 -c \"import os; fd=os.open('$F', os.O_WRONLY|os.O_APPEND); n=os.write(fd, b'w'*4096); os.fsync(fd); print('write_bytes=%d' % n)\" > /tmp/lw_w.out 2>&1
    echo write_rc=\$? >> /tmp/lw_w.out
    md5sum '$F' > /tmp/lw_raw_1.out 2>&1; echo \$? > /tmp/lw_rc_1.out
    cut -d' ' -f1 /tmp/lw_raw_1.out
    echo md5_rc=\$(cat /tmp/lw_rc_1.out)
    cat /tmp/lw_w.out
  " > "$OUT/w_read.txt"
rrc=$?
wread_require "$rrc"
else
rsx "$bound" "$W" "
    r=1
    while [ \$r -le $READERS ]; do
        ( md5sum '$F' > /tmp/lw_raw_\$r.out 2>&1; echo \$? > /tmp/lw_rc_\$r.out ) &
        r=\$((r+1))
    done
    wait
    r=1
    while [ \$r -le $READERS ]; do
        cut -d' ' -f1 /tmp/lw_raw_\$r.out
        echo md5_rc=\$(cat /tmp/lw_rc_\$r.out)
        r=\$((r+1))
    done
  " > "$OUT/w_read.txt"
rrc=$?
wread_require "$rrc"
fi
tread=$(( $(date +%s) - s0 ))
# The operation under test has returned; the pause knob has done its work.
# Clear it on H NOW, before any H-side read below: with it still armed, H's
# own re-release of the inode (a cold stat after drop_caches re-caches a
# grant, the next eviction releases it) paused for another PAUSE_MS inside
# the verdict's ssh, which timed out with an empty capture and scored a
# landed operation FAIL (s606k-n, s607e/g/i/j: walls +30 s, and a
# P-D512-RELPAUSE-END on H 240 s after the lap had ended).
timeout 20 $SSH "$H" "echo 0 > $P/dbg_rel_pause_ms; echo 0 > $P/dbg_rel_pause_ino" >/dev/null 2>&1
h_up_at_return=$(timeout 10 $SSH "$H" "cut -d' ' -f1 /proc/uptime" 2>/dev/null | filt | tr -dc '0-9.')
md5_w=$(grep -aoE '^[0-9a-f]{32}' "$OUT/w_read.txt" | head -1)
# KILL lap: the reader is dead; the holder's pause runs on regardless.  Wait
# for its end on H's own clock, then a FRESH read from W is what proves the
# abandoned wait left nothing behind (no orphan waiter, no poisoned inode).
md5_w_after=""
if [ "$KILL_AFTER_S" -gt 0 ]; then
    pw=$(( PAUSE_MS / 1000 + 30 ))
    for i in $(seq 1 "$pw"); do
        e=$(timeout 15 $SSH "$H" "$DM | grep -ac 'P-D512-RELPAUSE-END ino=$ino'" </dev/null 2>/dev/null | filt | tr -dc '0-9')
        [ "${e:-0}" -ge 1 ] && break
        sleep 1
    done
    # a failed md5sum (EIO) is the measurement: its text is output
    probe "$W" 90 "$OUT/w_read_after_kill.txt" '.' "W's fresh read after the pause" "echo 3 > /proc/sys/vm/drop_caches; md5sum '$F' 2>&1; true"
    md5_w_after=$(grep -aoE '^[0-9a-f]{32}' "$OUT/w_read_after_kill.txt" | head -1)
    echo "  INFO KILL: after the pause ended, W's fresh read md5=${md5_w_after:-none} (H=$md5_h) at +$(el)s"
fi
sleep 5
hdcap "$H" "$OUT/dmesg_$H.txt"; hdcap "$W" "$OUT/dmesg_$W.txt"
paused=$(grep -ac "P-D512-RELPAUSE ino=$ino stage=1" "$OUT/dmesg_$H.txt")
ended=$(grep -ac "P-D512-RELPAUSE-END ino=$ino" "$OUT/dmesg_$H.txt")
end_ts=$(grep -a "P-D512-RELPAUSE-END ino=$ino" "$OUT/dmesg_$H.txt" | head -1 | sed -n 's/^\[ *\([0-9.]*\)\].*/\1/p')
end_before_read=$(awk -v e="${end_ts:-0}" -v u="${h_up_at_return:-0}" 'BEGIN{print (e>0 && u>0 && e<=u+1.0)?1:0}')
lkwait=$(grep -ac 'P-LKWAIT-LIVE' "$OUT/dmesg_$W.txt")
unrec=$(grep -ac 'DLM inode lock unrecoverable' "$OUT/dmesg_$W.txt")
retries=$(grep -ac 'P36-RETRY' "$OUT/dmesg_$W.txt")
echo "  INFO W read: wall=${tread}s (bound ${bound}s) rc=$rrc md5_W=${md5_w:-none} raw=[$(head -c 120 "$OUT/w_read.txt" | tr '\n' ' ')]; H paused=$paused ended=$ended end_ts=${end_ts:-none} h_up_at_return=${h_up_at_return:-none}; W P-LKWAIT-LIVE=$lkwait P36-RETRY=$retries unrecoverable=$unrec"
ck "H entered the release-drain pause (BAST from W landed)" "$paused" "1"
if [ "$KILL_AFTER_S" -gt 0 ]; then
    killsig=$(grep -a 'P958-ACQ-FATAL-SIGNAL' "$OUT/dmesg_$W.txt" | grep -ac "ino=$ino ")
    killed=$(grep -a 'P958-ACQ-KILLED\|P912-ACQ-UNRECEIPTED .* killed=1' "$OUT/dmesg_$W.txt" | grep -ac "ino=$ino ")
    kcancel=$(grep -a 'P958-ACQ-CANCEL-SENT' "$OUT/dmesg_$W.txt" | grep -ac "ino=$ino ")
    kack=$(grep -a 'P958-ACQ-CANCEL-ACK' "$OUT/dmesg_$W.txt" | grep -a "ino=$ino " | grep -ao 'outcome=[0-9]' | sort | uniq -c | tr '\n' ' ')
    krx=$(grep -a 'P958-CANCEL-RX' "$OUT/dmesg_$H.txt" | grep -a "ino=$ino " | grep -ao 'outcome=[0-9]' | sort | uniq -c | tr '\n' ' ')
    echo "  INFO KILL: W fatal_signal=$killsig killed=$killed cancel_sent=$kcancel acks=[${kack}]; H cancel_rx outcomes=[${krx}]; reader rc=[$(grep -ao 'md5_rc=[0-9]*' "$OUT/w_read.txt" | head -1)]"
    ck "the killed reader left the wait within 10 s of SIGKILL" "$([ -n "$gone_s" ] && [ "$gone_s" -le 10 ] && echo 1 || echo 0)" "1"
    ck "the engine saw the fatal signal at an attempt boundary (P958-ACQ-FATAL-SIGNAL)" "$([ "$killsig" -ge 1 ] && echo 1 || echo 0)" "1"
    ck "the classifier abandoned the wait for the killed task (P958-ACQ-KILLED)" "$([ "$killed" -ge 1 ] && echo 1 || echo 0)" "1"
    ck "W told the master by name (LOCK_CANCEL sent)" "$([ "$kcancel" -ge 1 ] && echo 1 || echo 0)" "1"
    ck "the master removed the queued waiter (cancel outcome 2)" "$(echo "$krx" | grep -aq 'outcome=2' && echo 1 || echo 0)" "1"
    ck "W received the ack naming the removed waiter (outcome=2)" "$(echo "$kack" | grep -aq 'outcome=2' && echo 1 || echo 0)" "1"
    ck "H's pause still ended on its own (the holder was not disturbed)" "$ended" "1"
    ck "W's fresh read after the pause returned H's bytes (nothing left behind)" "$([ -n "$md5_w_after" ] && [ "$md5_w_after" = "$md5_h" ] && echo same || echo differ)" "same"
else
ck "W's read returned a digest (no stall past the pause, no error)" "$([ -n "$md5_w" ] && echo 1 || echo 0)" "1"
ck "W's read waited for the pause (>= $(( PAUSE_MS / 1000 - 5 ))s)" "$([ "$tread" -ge $(( PAUSE_MS / 1000 - 5 )) ] && echo 1 || echo 0)" "1"
ck "H's pause-end stamp precedes W's read return on H's clock" "$end_before_read" "1"
if [ "$RW" = write ]; then
    # W appended behind the holder; the reference is now H's digest of the
    # file AFTER W's write landed, read fresh on H.
    probe "$H" 30 "$OUT/h_read_final.txt" '.' "H's fresh read after W's operation" "echo 3 > /proc/sys/vm/drop_caches; md5sum '$F' 2>&1 | cut -d' ' -f1; true"
    md5_h_final=$(grep -aoE '^[0-9a-f]{32}' "$OUT/h_read_final.txt" | head -1)
    echo "  INFO RW=write: $(grep -a 'write_bytes\|write_rc' "$OUT/w_read.txt" | tr '\n' ' ') md5_W=${md5_w:-none} md5_H_after=${md5_h_final:-none} (H before the wait: $md5_h)"
    ck "W's write behind the live holder landed 4096 bytes (waited, not refused)" "$(grep -ac '^write_bytes=4096' "$OUT/w_read.txt")" "1"
    ck "W's write returned 0" "$(grep -ac '^write_rc=0' "$OUT/w_read.txt")" "1"
    ck "H reads the file W appended to with W's digest (both nodes see the write)" "$([ -n "$md5_w" ] && [ "$md5_w" = "$md5_h_final" ] && echo same || echo differ)" "same"
    ck "the file changed from H's pre-wait content (the append is real)" "$([ -n "$md5_w" ] && [ "$md5_w" != "$md5_h" ] && echo 1 || echo 0)" "1"
    ck "no write refusal for the target (P958-WRITE-REFUSED)" "$(grep -a 'P958-WRITE-REFUSED' "$OUT/dmesg_$W.txt" | grep -ac "ino=$ino ")" "0"
elif [ "$RW" = dio_unaligned ]; then
    probe "$H" 30 "$OUT/h_read_final.txt" '.' "H's fresh read after W's operation" "echo 3 > /proc/sys/vm/drop_caches; md5sum '$F' 2>&1 | cut -d' ' -f1; true"
    md5_h_final=$(grep -aoE '^[0-9a-f]{32}' "$OUT/h_read_final.txt" | head -1)
    echo "  INFO RW=dio_unaligned: $(grep -a 'dio_write_bytes\|dio_write_rc' "$OUT/w_read.txt" | tr '\n' ' ') md5_W=${md5_w:-none} md5_H_after=${md5_h_final:-none} (H before the wait: $md5_h)"
    ck "W's unaligned direct write behind the live holder landed 4096 bytes (waited, not refused)" "$(grep -ac '^dio_write_bytes=4096' "$OUT/w_read.txt")" "1"
    ck "W's direct write returned 0" "$(grep -ac '^dio_write_rc=0' "$OUT/w_read.txt")" "1"
    ck "H reads the file W wrote into with W's digest (both nodes see the write)" "$([ -n "$md5_w" ] && [ "$md5_w" = "$md5_h_final" ] && echo same || echo differ)" "same"
    ck "the file changed from H's pre-wait content (the write is real)" "$([ -n "$md5_w" ] && [ "$md5_w" != "$md5_h" ] && echo 1 || echo 0)" "1"
    ck "no write refusal for the target (P958-WRITE-REFUSED)" "$(grep -a 'P958-WRITE-REFUSED' "$OUT/dmesg_$W.txt" | grep -ac "ino=$ino ")" "0"
elif [ -n "$ATTROP" ]; then
    # W changed an attribute behind the holder; the reference is H's COLD
    # stat of the file after the change landed, and the bytes must be the
    # same on both nodes and unchanged from before.
    # ONE cold pass on H: drop caches once, then stat, digest and (last, so
    # its spaces do not split the earlier fields) the attribute.  A second
    # drop_caches for the attribute alone (s606k-n) evicted H's freshly
    # cached grant while the lap's release-pause knob was still armed for
    # this inode, parked H's own release for the pause length, and the
    # capture timed out empty.  getfattr is told the names are absolute or
    # it prints a warning ahead of the value; an absent attribute prints
    # "No such attribute", captured too.
    h_after=$(timeout 30 $SSH "$H" "echo 3 > /proc/sys/vm/drop_caches; stat -c 'attr_H=%a_%s' '$F'; md5sum '$F' | cut -d' ' -f1; echo xattr_H=\$(getfattr --absolute-names -n user.d958 --only-values '$F' 2>&1 | tr -d '\n')" </dev/null 2>/dev/null | filt | tr '\n' ' ')
    attr_h_final=$(echo "$h_after" | grep -ao 'attr_H=[0-9_]*' | cut -d= -f2)
    md5_h_final=$(echo "$h_after" | grep -aoE '[0-9a-f]{32}' | head -1)
    xattr_h_final=$(echo "$h_after" | sed -n 's/.*xattr_H=//p' | sed 's/ *$//' | head -c 80)
    attr_w_final=$(grep -ao '^attr_W=[0-9_]*' "$OUT/w_read.txt" | cut -d= -f2)
    echo "  INFO RW=$RW: $(grep -a "${ATTROP}_ok\|${ATTROP}_rc" "$OUT/w_read.txt" | tr '\n' ' ') attr_W=${attr_w_final:-none} attr_H_after=${attr_h_final:-none} (reference ${attr_h0}); md5_W=${md5_w:-none} md5_H_after=${md5_h_final:-none} (H before the wait: $md5_h)"
    ck "W's $RW behind the live holder landed (waited, not refused: ${ATTROP}_ok=1 reported)" "$(grep -ac "^${ATTROP}_ok=1" "$OUT/w_read.txt")" "1"
    ck "W's $RW driver exited inside the bound" "$(grep -ac "^${ATTROP}_rc=0" "$OUT/w_read.txt")" "1"
    case "$ATTROP" in getxattr|listxattr|setxattr|removexattr|setxattr_nofork) XA=1 ;; *) XA="" ;; esac
    if [ "$ATTROP" = mmap_write ] || [ "$ATTROP" = mmap_read ]; then
        echo "  INFO RW=$RW: driver lines [$(grep -a "^mmap_ok\|^${ATTROP}_" "$OUT/w_read.txt" | tr '\n' ' ')]; md5_W=${md5_w:-none} md5_H_after=${md5_h_final:-none} (H before the wait: $md5_h)"
        ck "the driver's mapping was made before the wait (mmap_ok=1)" "$(grep -ac '^mmap_ok=1' "$OUT/w_read.txt")" "1"
        ck "W's $RW behind the live holder landed (${ATTROP}_ok=1 reported, no SIGBUS)" "$(grep -ac "^${ATTROP}_ok=1" "$OUT/w_read.txt")" "1"
        # The harness itself appends `<op>_rc=0` when the driver exits; a
        # signalled child is reported by the driver as `<op>_rc=-<sig>`.
        ck "the faulting child was not signalled (no ${ATTROP}_rc=-<sig> line)" "$(grep -ac "^${ATTROP}_rc=-" "$OUT/w_read.txt")" "0"
        ck "no fault refusal for the target (P958-FAULT-REFUSED)" "$(grep -a 'P958-FAULT-REFUSED' "$OUT/dmesg_$W.txt" | grep -ac "ino=$ino ")" "0"
        ck "the mode and size are unchanged on H" "${attr_h_final:-none}" "$attr_h0"
        if [ "$ATTROP" = mmap_write ]; then
            ck "H reads the file W wrote through its mapping with W's digest (both nodes see the store)" "$([ -n "$md5_w" ] && [ "$md5_w" = "$md5_h_final" ] && echo same || echo differ)" "same"
            ck "the file changed from H's pre-wait content (the store is real)" "$([ -n "$md5_w" ] && [ "$md5_w" != "$md5_h" ] && echo 1 || echo 0)" "1"
            measure "$H" 20 "$OUT/rv_rv1_1.txt" '^READ_RC=[0-9]+$' "rv1 on $H" "head -c 4 '$F'; printf '\nREAD_RC=%s\n' \$?"; rv1=$(grep -av '^READ_RC=' "$OUT/rv_rv1_1.txt" | tr -d '\n')
            ck "H's first bytes are W's store, cold (mmw!)" "$rv1" "mmw!"
        else
            ck "the file's bytes are unchanged and equal on both nodes (a read fault moves no data)" "$([ -n "$md5_w" ] && [ "$md5_w" = "$md5_h_final" ] && [ "$md5_w" = "$md5_h" ] && echo same || echo differ)" "same"
        fi
    elif [ -n "$XA" ]; then
        echo "  INFO RW=$RW: driver line [$(grep -a "^${ATTROP}_ok=1" "$OUT/w_read.txt" | head -1)]; user.d958 cold on H=[${xattr_h_final:-?}]"
        case "$ATTROP" in getxattr|listxattr|removexattr|setxattr_nofork)
            ck "the driver's set landed before the wait (setxattr_ok=1)" "$(grep -ac '^setxattr_ok=1' "$OUT/w_read.txt")" "1" ;;
        esac
        [ "$ATTROP" = setxattr_nofork ] && ck "the driver removed the attribute (and the fork) before the wait (removexattr_ok=1)" "$(grep -ac 'removexattr_ok=1' "$OUT/w_read.txt")" "1"
        case "$ATTROP" in
        getxattr)
            ck "W's read behind the live holder returned the value it set (value=v958)" "$(grep -a '^getxattr_ok=1' "$OUT/w_read.txt" | grep -ac 'value=v958$')" "1"
            ck "H reads the same attribute value cold (v958)" "${xattr_h_final:-none}" "v958" ;;
        listxattr)
            ck "W's listing behind the live holder names the attribute it set (user.d958)" "$(grep -a '^listxattr_ok=1' "$OUT/w_read.txt" | grep -ac 'user\.d958')" "1"
            ck "H reads the same attribute value cold (v958)" "${xattr_h_final:-none}" "v958" ;;
        setxattr|setxattr_nofork)
            ck "H reads the attribute W set behind the holder, cold (v958)" "${xattr_h_final:-none}" "v958" ;;
        removexattr)
            ck "H no longer sees the attribute W removed behind the holder, cold" "$(echo "${xattr_h_final:-}" | grep -aci 'no such attribute')" "1" ;;
        esac
        ck "the mode and size are unchanged on H (the operation moves no data)" "${attr_h_final:-none}" "$attr_h0"
        ck "the file's bytes are unchanged and equal on both nodes (the operation moves no data)" "$([ -n "$md5_w" ] && [ "$md5_w" = "$md5_h_final" ] && [ "$md5_w" = "$md5_h" ] && echo same || echo differ)" "same"
    elif [ "$ATTROP" = chmod ]; then
        ck "H sees the new mode cold (0640)" "$(echo "${attr_h_final:-none}" | cut -d_ -f1)" "640"
        ck "W sees the new mode (0640)" "$(echo "${attr_w_final:-none}" | cut -d_ -f1)" "640"
        ck "the size is unchanged on H (a chmod moves no data)" "$(echo "${attr_h_final:-none}" | cut -d_ -f2)" "$(echo "$attr_h0" | cut -d_ -f2)"
        ck "the file's bytes are unchanged and equal on both nodes (a chmod moves no data)" "$([ -n "$md5_w" ] && [ "$md5_w" = "$md5_h_final" ] && [ "$md5_w" = "$md5_h" ] && echo same || echo differ)" "same"
    else
        ck "H sees the allocation cold (size = 1 MiB + 4096)" "$(echo "${attr_h_final:-none}" | cut -d_ -f2)" "1052672"
        ck "W sees the allocation (size = 1 MiB + 4096)" "$(echo "${attr_w_final:-none}" | cut -d_ -f2)" "1052672"
        ck "the mode is unchanged on H (a fallocate changes no attribute but the size)" "$(echo "${attr_h_final:-none}" | cut -d_ -f1)" "$(echo "$attr_h0" | cut -d_ -f1)"
        ck "both nodes read the same bytes after the allocation (H cold == W)" "$([ -n "$md5_w" ] && [ "$md5_w" = "$md5_h_final" ] && echo same || echo differ)" "same"
        ck "the file changed from H's pre-wait content (the allocation is real: zeros past the old size)" "$([ -n "$md5_w" ] && [ "$md5_w" != "$md5_h" ] && echo 1 || echo 0)" "1"
    fi
    ck "no $RW refusal for the target (P958-SETATTR-REFUSED / P958-FALLOCATE-REFUSED / P958-XATTR-REFUSED / P958-XATTRSET-REFUSED / P958-FAULT-REFUSED)" "$(grep -a 'P958-SETATTR-REFUSED\|P958-FALLOCATE-REFUSED\|P958-XATTR-REFUSED\|P958-XATTRSET-REFUSED\|P958-FAULT-REFUSED' "$OUT/dmesg_$W.txt" | grep -ac "ino=$ino ")" "0"
elif [ "$NSOP" = lookup ]; then
    measure "$H" 30 "$OUT/rv_md5_h_final_2.txt" '^READ_RC=[0-9]+$' "md5_h_final on $H" "echo 3 > /proc/sys/vm/drop_caches; $(dgst "$F"); printf '\nREAD_RC=%s\n' \$?"; md5_h_final=$(grep -av '^READ_RC=' "$OUT/rv_md5_h_final_2.txt" | grep -aoE '^[0-9a-f]{32}' | head -1)
    echo "  INFO RW=lookup: $(grep -a 'lookup_ok\|lookup_ino\|lookup_rc' "$OUT/w_read.txt" | tr '\n' ' ') md5_W=${md5_w:-none} md5_H_after=${md5_h_final:-none} (H before the wait: $md5_h)"
    ck "W's lookup behind the live holder landed (waited, not refused: lookup_ok reported)" "$(grep -ac '^lookup_ok=1' "$OUT/w_read.txt")" "1"
    ck "W's lookup returned 0" "$(grep -ac '^lookup_rc=0' "$OUT/w_read.txt")" "1"
    ck "the looked-up entry has an inode number" "$([ "$(grep -ao '^lookup_ino=[0-9]*' "$OUT/w_read.txt" | cut -d= -f2)" -gt 0 ] 2>/dev/null && echo 1 || echo 0)" "1"
    ck "the listing is unchanged and equal on both nodes (a lookup writes nothing)" "$([ -n "$md5_w" ] && [ "$md5_w" = "$md5_h_final" ] && [ "$md5_w" = "$md5_h" ] && echo same || echo differ)" "same"
    ck "no lookup refusal for the target (P958-LOOKUP-REFUSED)" "$(grep -a 'P958-LOOKUP-REFUSED' "$OUT/dmesg_$W.txt" | grep -ac "ino=$ino ")" "0"
elif [ -n "$NSOP" ]; then
    # W acted on the directory behind the holder; the reference is H's
    # listing of the directory AFTER W's operation landed, read cold on H.
    measure "$H" 30 "$OUT/rv_md5_h_final_3.txt" '^READ_RC=[0-9]+$' "md5_h_final on $H" "echo 3 > /proc/sys/vm/drop_caches; $(dgst "$F"); printf '\nREAD_RC=%s\n' \$?"; md5_h_final=$(grep -av '^READ_RC=' "$OUT/rv_md5_h_final_3.txt" | grep -aoE '^[0-9a-f]{32}' | head -1)
    value_now_into name_on_h "$H" 30 "$OUT/rv_name_on_h_4.txt" '^(1|0)$' "name_on_h on $H" "{ test -e '$F/$WNAME' || test -L '$F/$WNAME'; } && echo 1 || echo 0"; name_on_h=$(printf '%s\n' "$name_on_h" | tr -dc '0-9')
    value_now_into entry_on_h "$H" 30 "$OUT/rv_entry_on_h_5.txt" '^(1|0)$' "entry_on_h on $H" "test -e '$F/$ENAME' && echo 1 || echo 0"; entry_on_h=$(printf '%s\n' "$entry_on_h" | tr -dc '0-9')
    echo "  INFO RW=$RW: $(grep -a "${NSOP}_fd\|${NSOP}_ok\|${NSOP}_rc" "$OUT/w_read.txt" | tr '\n' ' ') md5_W=${md5_w:-none} md5_H_after=${md5_h_final:-none} (H before the wait: $md5_h); on H: $WNAME=${name_on_h:-?} $ENAME=${entry_on_h:-?}"
    ck "W's $NSOP behind the live holder landed (waited, not refused: ${NSOP}_fd/_ok reported)" "$(grep -ac "^${NSOP}_fd=\|^${NSOP}_ok=" "$OUT/w_read.txt")" "1"
    ck "W's $NSOP returned 0" "$(grep -ac "^${NSOP}_rc=0" "$OUT/w_read.txt")" "1"
    ck "H lists the directory W acted on with W's digest (both nodes see the change)" "$([ -n "$md5_w" ] && [ "$md5_w" = "$md5_h_final" ] && echo same || echo differ)" "same"
    case "$NSOP" in
    create|rename|link|symlink) ck "H sees $WNAME in the directory" "${name_on_h:-0}" "1" ;;
    esac
    case "$NSOP" in
    unlink|rename) ck "H no longer sees $ENAME in the directory" "${entry_on_h:-1}" "0" ;;
    link)          ck "H still sees $ENAME (link source) in the directory" "${entry_on_h:-0}" "1" ;;
    esac
    ck "the listing changed from H's pre-wait content (the $NSOP is real)" "$([ -n "$md5_w" ] && [ "$md5_w" != "$md5_h" ] && echo 1 || echo 0)" "1"
    ck "no namespace refusal for the target (P958-NAMESPACE-REFUSED)" "$(grep -a 'P958-NAMESPACE-REFUSED' "$OUT/dmesg_$W.txt" | grep -ac "ino=$ino ")" "0"
else
md5_ok=$(grep -acE "^$md5_h\$" "$OUT/w_read.txt")
rc_bad=$(grep -ac 'md5_rc=[^0]' "$OUT/w_read.txt")
ck "every reader's md5 == H md5 (all $READERS saw the holder's flushed bytes)" "$md5_ok" "$READERS"
ck "no reader returned an error" "$rc_bad" "0"
fi
fi
ck "W never took the unrecoverable-timeout shutdown" "$unrec" "0"
if [ "$TCP_FAULT_S" -gt 0 ]; then
    # the transport's account of the fault window and its aftermath, from
    # both nodes: membership must not have moved (no death, no fence), and
    # everything else is reported for the record
    for n in "$H" "$W"; do
        awk "/LIVEWAIT-TCPFAULT-$LABEL/{f=1} f" "$OUT/dmesg_$n.txt" > "$OUT/dmesg_${n}_fault.txt"
        capture_require "$OUT/dmesg_${n}_fault.txt" "LIVEWAIT-TCPFAULT-$LABEL" "the kernel log on $n from the fault marker"
        echo "  INFO fault window on $n: lines=$(grep -ac . "$OUT/dmesg_${n}_fault.txt") reconnect=$(grep -aic 'reconnect' "$OUT/dmesg_${n}_fault.txt") connected=$(grep -aic 'connected\|connection' "$OUT/dmesg_${n}_fault.txt") dead=$(grep -ac 'declaring dead\|no longer responding' "$OUT/dmesg_${n}_fault.txt") degraded=$(grep -ac 'P958-ACQ-DEGRADED ' "$OUT/dmesg_${n}_fault.txt") undegraded=$(grep -ac 'P958-ACQ-UNDEGRADED\|P958-ACQ-RECOVERED' "$OUT/dmesg_${n}_fault.txt") retx=$(grep -ac 'P958-ACQ-RETX' "$OUT/dmesg_${n}_fault.txt") qack=$(grep -ac 'P912-QACK-RX' "$OUT/dmesg_${n}_fault.txt") lkwait=$(grep -ac 'P-LKWAIT-LIVE' "$OUT/dmesg_${n}_fault.txt") unreceipted=$(grep -ac 'P912-ACQ-UNRECEIPTED' "$OUT/dmesg_${n}_fault.txt")"
        grep -ai 'reconnect\|tcp peer\|P958-ACQ-DEGRADED\|P958-ACQ-UNDEGRADED\|P958-ACQ-RECOVERED\|P-LKWAIT-LIVE\|P912-ACQ-UNRECEIPTED\|declaring dead\|no longer responding\|LIVEWAIT-TCPFAULT' "$OUT/dmesg_${n}_fault.txt" | cut -c1-190 | head -14 | sed "s/^/  INFO   $n: /"
        ck "no death was declared on $n across the ${TCP_FAULT_S}s transport fault" "$(grep -ac 'declaring dead\|no longer responding\|P236-FENCE-CERTIFIED' "$OUT/dmesg_${n}_fault.txt")" "0"
    done
fi
if [ "$KILL_AFTER_S" -gt 0 ]; then
    echo "  INFO P-LKWAIT-LIVE=$lkwait not scored with KILL_AFTER_S=$KILL_AFTER_S (the reader left before the budget)"
elif [ "$CAW" = 1 ]; then
    wext=$(grep -a 'P-WAIT-EXTEND' "$OUT/dmesg_$W.txt" | grep -ac "ino=$ino ")
    echo "  INFO CAW wait witnesses on $W for ino=$ino: P-WAIT-EXTEND=$wext P-LKWAIT-LIVE=$lkwait"
    [ "$PAUSE_MS" -gt 120000 ] && ck "W extended its wait past CAW's 120 s base while the holder was alive (P-WAIT-EXTEND >= 1)" "$([ "$wext" -ge 1 ] && echo 1 || echo 0)" "1"
    # The 480 s cap bounds ONE attempt: ilock_begin makes three before the
    # timeout classifier runs (measured caw0912_s2: timed out at 480 s, the
    # second attempt was granted at 547 s when the pause ended).  So the
    # classifier -- the code the old self-shutdown lived in -- is reached only
    # past 3 x 480 s.
    capped=$(grep -ac 'disk lock acquisition timed out after' "$OUT/dmesg_$W.txt")
    echo "  INFO CAW per-attempt caps reached on $W: $capped (the classifier runs after 3)"
    [ "$PAUSE_MS" -gt 1440000 ] && ck "W parked behind the live holder after all three CAW attempts (P-LKWAIT-LIVE >= 1)" "$([ "$lkwait" -ge 1 ] && echo 1 || echo 0)" "1"
elif [ "$PAUSE_MS" -gt 180000 ] && [ "$GAP_MS" -eq 0 ]; then
    ck "W parked behind the live holder (P-LKWAIT-LIVE >= 1)" "$([ "$lkwait" -ge 1 ] && echo 1 || echo 0)" "1"
elif [ "$GAP_MS" -gt 0 ]; then
    # The budget is counted in attempts, and a gap of GAP_MS stretches each
    # attempt to GAP_MS + 1 s, so the pause ends inside the first descent and
    # the classifier is never reached.  Recorded, not scored.
    echo "  INFO P-LKWAIT-LIVE=$lkwait not scored with GAP_MS=$GAP_MS (budget is counted in attempts)"
fi
# BETWEEN-ATTEMPT GRANT ADOPTION (0.84.0).  Every line carries the mount's
# running total; the totals are read, never the line counts.
tot2() { grep -ao "$1 .*total=[0-9]*" "$OUT/dmesg_$2.txt" | grep -ao 'total=[0-9]*' | cut -d= -f2 | sort -n | tail -1; }
gapn=$(grep -ac "P958-ACQ-GAP .* ino=$ino " "$OUT/dmesg_$W.txt")
adopted=$(tot2 P958-ACQ-GRANT-ADOPTED "$W"); claimed=$(tot2 P958-ACQ-GRANT-CLAIMED "$W")
vanished=$(tot2 P958-ACQ-GRANT-VANISHED "$W"); greleased=$(tot2 P958-ACQ-GRANT-RELEASED "$W")
bounced_ino=$(grep -ac "P958-ACQ-GRANT-BOUNCED .* ino=$ino " "$OUT/dmesg_$W.txt")
adopted_ino=$(grep -ac "P958-ACQ-GRANT-ADOPTED .* ino=$ino " "$OUT/dmesg_$W.txt")
claimed_ino=$(grep -ac "P958-ACQ-GRANT-CLAIMED .* ino=$ino " "$OUT/dmesg_$W.txt")
echo "  INFO between-attempt grants on $W (running totals): adopted=${adopted:-0} claimed=${claimed:-0} vanished=${vanished:-0} released=${greleased:-0}; for ino=$ino: adopted=$adopted_ino claimed=$claimed_ino bounced=$bounced_ino; gap probe lines=$gapn"
if [ "$GAP_MS" -gt 0 ]; then
    ck "the gap instrument fired for the target (P958-ACQ-GAP ino=$ino >= 1)" "$([ "$gapn" -ge 1 ] && echo 1 || echo 0)" "1"
    # adopted=0 here means the holder's release landed inside the 1 s attempt
    # window (probability 1000/(GAP_MS+1000)) and the path was NOT exercised:
    # a FAIL that says re-run, never a pass.
    ck "the holder's grant landed in the gap and was ADOPTED for the wait (else re-run: it landed in the attempt window)" "$([ "$adopted_ino" -ge 1 ] && echo 1 || echo 0)" "1"
    ck "the wait's next attempt CLAIMED the adopted grant (no re-send, no re-queue)" "$([ "$claimed_ino" -ge 1 ] && echo 1 || echo 0)" "1"
    ck "the grant was never bounced back to the master for this inode" "$bounced_ino" "0"
    ck "no adopted grant vanished under the wait (running total)" "${vanished:-0}" "0"
    ck "no adopted grant was released unclaimed (running total)" "${greleased:-0}" "0"
else
    ck "no grant for the target was bounced as unsolicited (the wait solicited every grant it got)" "$bounced_ino" "0"
fi
# THE CONTROL FOR THE DEGRADED DETECTOR.  This wait is long and legitimate and
# the master confirms every re-send of it, so it must never be reported
# DEGRADED (0.83.0, acq_degrade_ms): a detector that fires here would be
# escalating a healthy drain.  A remotely mastered lap exercises it; a local
# one cannot (no receipt is needed for a local master) and the count is then
# zero by construction, which is recorded rather than scored.
degraded=$(grep -ac 'P958-ACQ-DEGRADED ' "$OUT/dmesg_$W.txt")
rejected=$(grep -ac 'P958-ACQ-STATUS-REJECTED' "$OUT/dmesg_$W.txt")
if [ "$PAUSE_MS" -gt 60000 ] && [ "${MASTER:-remote}" = remote ]; then
    ck "a confirmed ${PAUSE_MS}ms wait was never reported DEGRADED (control)" "$degraded" "0"
    ck "no status receipt for the confirmed wait was rejected as stale or mismatched" "$rejected" "0"
else
    echo "  INFO degraded-detector control not scored (MASTER=${MASTER:-remote}, pause ${PAUSE_MS}ms): P958-ACQ-DEGRADED=$degraded rejected=$rejected"
fi
# How many blocking notifications did ONE wait cost the holder?
#
# The requester re-sends about once a second for the whole wait.  While a
# re-send was read as a new request, each one re-queued the waiter and fired
# another notification at a holder that was already draining — so this count
# tracked the re-send count instead of the wait count (measured 238 against
# 234 re-sends across one 244 s drain).  A re-send now only re-fires on its
# own interval, so the ceiling is set by the DRAIN LENGTH, not the cadence.
#
# COUNT IT ON THE NODE THAT MASTERS THE RESOURCE, which is not always the
# holder.  The notification is FIRED by the master: for a remotely mastered
# target that is H, but for a locally mastered one the master is W — the
# requester itself.  Counting it on H either way reads 0 for every local lap
# and scores the budget gate as a pass on a node that never fired anything.
# That is exactly how this harness scored 9/9 on a lap that measured nothing
# (s579e), so the node is derived from the locality the probe established, and
# what the HOLDER received is reported next to it as an independent witness.
#
# The budget is derived, not chosen: one fire per 10 s re-fire interval across
# the pause, plus 5 for the opening fire and ordinary jitter.
if [ "$CAW" = 1 ]; then
    echo "  INFO master-side notification budget not scored on CAW (no lock master; P7S-BAST-FIRE H=$(grep -ac "P7S-BAST-FIRE ino=$ino " "$OUT/dmesg_$H.txt") W=$(grep -ac "P7S-BAST-FIRE ino=$ino " "$OUT/dmesg_$W.txt"); holder P7B-BASTNOTIFY=$(grep -ac "P7B-BASTNOTIFY ino=$ino " "$OUT/dmesg_$H.txt"))"
else
MNODE=$([ "$MLOC" = "remote" ] && echo "$H" || echo "$W")
OTHER=$([ "$MLOC" = "remote" ] && echo "$W" || echo "$H")
fire_h=$(grep -ac "P7S-BAST-FIRE ino=$ino " "$OUT/dmesg_$H.txt")
fire_w=$(grep -ac "P7S-BAST-FIRE ino=$ino " "$OUT/dmesg_$W.txt")
bastfire=$([ "$MNODE" = "$H" ] && echo "$fire_h" || echo "$fire_w")
otherfire=$([ "$MNODE" = "$H" ] && echo "$fire_w" || echo "$fire_h")
# SCOPED TO THE TARGET INODE.  Unscoped, this counted every notification the
# holder received for anything -- in s580b it read 27 for a lap whose target
# accounted for one of them, which made the holder-side witness agree with a
# fire count taken on the wrong node.
bastrecv=$(grep -ac "P7B-BASTNOTIFY ino=$ino " "$OUT/dmesg_$H.txt")
acqretx=$(grep -ac 'P958-ACQ-RETX' "$OUT/dmesg_$MNODE.txt")
waitage=$(grep -ao 'wait_age_ms=[0-9]*' "$OUT/dmesg_$MNODE.txt" | cut -d= -f2 | sort -n | tail -1)
bastbudget=$(( PAUSE_MS / 1000 / 10 + 5 ))
echo "  INFO one wait cost the holder: master=$MNODE fired P7S-BAST-FIRE ino=$ino = $bastfire, holder $H received P7B-BASTNOTIFY = $bastrecv (budget $bastbudget, derived from a ${PAUSE_MS}ms drain at one re-fire per 10s); W P36-RETRY=$retries; master P958-ACQ-RETX=$acqretx max wait_age_ms=${waitage:-none}"
# A zero here is not a good result, it is a broken measurement: the wait had a
# blocking holder (asserted above), so the master fired at least once.
ck "the fire count came from a node that actually fired" "$([ "${bastfire:-0}" -ge 1 ] && echo 1 || echo 0)" "1"
# The locality established before the lap must still hold across it.  If the
# OTHER node fired for this inode, the target was remastered mid-lap or the
# selection was wrong, and either way the count above is not this path's.
ck "no notification for this inode came from $OTHER (locality held all lap)" "${otherfire:-0}" "0"
if [ "$MLOC" = "remote" ]; then
    ck "the master absorbed the re-sends instead of re-queueing them" "$([ "${acqretx:-0}" -ge 1 ] && echo 1 || echo 0)" "1"
    # The age the master reports for this waiter must be the age of the WAIT.
    # While every re-send replaced the entry this could never exceed the
    # re-send interval no matter how long the wait really ran.
    ck "the waiter's recorded age grew past one re-send interval" "$([ "${waitage:-0}" -gt 5000 ] && echo 1 || echo 0)" "1"
fi
ck "one wait cost the holder no more than its derived notification budget" "$([ "$bastfire" -le "$bastbudget" ] && echo 1 || echo 0)" "1"
fi

# The three ways the requester's acquisition table can lose a live wait's
# history.  Each degrades to the behaviour that predates the table — a fresh
# name, no backdated queue time, a notification fired — so a non-zero count
# here does not mean this lap is invalid; it means the fix stopped applying
# for that many events, and the notification budget above is the thing that
# would show it.  Report the running TOTAL each probe carries, never the line
# count: both are ratelimited and the line count is the smaller number.
tot() { grep -ao "$1 .*total=[0-9]*" "$OUT/dmesg_$2.txt" | grep -ao 'total=[0-9]*' | cut -d= -f2 | sort -n | tail -1; }
keycol=$(tot P958-ACQ-KEY-COLLIDE "$W"); evictlive=$(tot P958-ACQ-EVICT-LIVE "$W"); idlelost=$(tot P958-ACQ-IDLE-LOST "$W")
echo "  INFO acquisition-table losses on $W (running totals, not line counts): key_collide=${keycol:-0} evict_live=${evictlive:-0} idle_lost=${idlelost:-0}; readers=$READERS"
if [ "$READERS" -gt 1 ]; then
    # THE INSTRUMENT MUST BE SHOWN TO FIRE.  Two readers of one resource in
    # one mode is the only shape that can share a record, so if the probe is
    # silent here it is broken or unreachable, and every quiet lap elsewhere
    # means nothing.  This assertion is what buys those laps their meaning.
    ck "the record-sharing probe fired with $READERS readers on one resource" "$([ "${keycol:-0}" -ge 1 ] && echo 1 || echo 0)" "1"
fi
for n in "$H" "$W"; do
    capture_require "$OUT/dmesg_$n.txt" "$MARK" "the kernel log on $n from the lap marker"
    s=$(grep -aEc 'BUG:|Oops|Shutting down filesystem|Corruption of in-memory' "$OUT/dmesg_$n.txt"); ck "zero splats/shutdowns on $n" "$s" "0"
done
clear_knobs
disarm_drop
RMF=$([ "$TARGET" = dir ] && echo "rm -rf" || echo "rm -f")
timeout 20 $SSH "$H" "$RMF '$MNT'/.livewait_${LABEL}_1 '$MNT'/.livewait_${LABEL}_2 '$MNT'/.livewait_${LABEL}_3 '$MNT'/.livewait_${LABEL}_4 '$MNT'/.livewait_${LABEL}_5 '$MNT'/.livewait_${LABEL}_6 '$MNT'/.livewait_${LABEL}_7 '$MNT'/.livewait_${LABEL}_8" >/dev/null 2>&1
echo "=== live_holder_wait $LABEL: fails=$fails wall=$(el)s out=$OUT $(date -u +%FT%TZ) ==="
[ "$fails" -eq 0 ]
