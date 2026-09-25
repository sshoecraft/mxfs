#!/bin/bash
# d0521_own_slice_cross_stamp_probe.sh — does a 2-node WHOLE-CLUSTER CRASH
# restart make a node's OWN-slice trusted recovery meet a cross-slice on-disk
# LSN stamp, and veto a buffer image it was obliged to apply?
#
# THE DEFECT UNDER TEST (D-FOREIGN-REPLAY-UNGATED-IMAGES hole H2, filed as
# D-OWN-SLICE-PASS1-RECLAIM-REPLAY-CROSS-SLICE-LSN-VETO-0521).  Per-node journal
# slices number their LSNs independently (xlog_alloc_log sets l_curr_cycle = 1
# per slice), so a cross-slice comparison is meaningless.  Foreign replay of a
# DEAD PEER's slice has the authority token to override the meaningless veto
# (xfs_buf_item_recover.c OVERRIDE-APPLY).  A node recovering its OWN slice has
# NO token, and the upstream veto stands:
#
#   xfs/xfs_log.c:784  P-OWN-RECOVERY ... untrusted=0 buflsn_skips=N
#       "skips on a trusted clustered recovery are unverified lost updates"
#
# WHY A WHOLE-CLUSTER CRASH IS THE ONLY SHAPE THAT REACHES IT.  If one node
# dies, the survivor foreign-replays the dead slice and the token gate applies
# (measured: 'foreign replay of slot 1 complete' on both nodes, lap s585b).  If
# both nodes unmount CLEANLY the log is flushed empty and own-slice recovery
# replays nothing — which is why tests/cluster_restart_nomkfs.sh, the existing
# whole-cluster-restart harness, has never produced this census line.  Only a
# crash of BOTH nodes leaves each slice dirty with no peer to replay it.
#
# THE PRECONDITION THIS BUILDS, and why each step is needed:
#   1. B alone creates files in a shared directory and SYNCS.  sync pushes the
#      AIL, so the dir blocks / AGI / inode clusters reach the platter STAMPED
#      WITH B's SLICE LSN.  This is the cross-slice stamp; nothing fakes it.
#   2. A then creates files in the SAME directory.  A must acquire the AG and
#      the dir from B, so A's log now carries images of blocks whose platter
#      copy carries B's number.
#   3. A fsyncs the directory — the dirents are now FSYNC-ACKED to userspace and
#      durable in A's log.  A does NOT sync: the images stay in A's AIL only.
#   4. Both nodes are DESTROYED.  No quiesce, no purge, no peer replay.
#   5. Both remount.  Each replays its OWN slice as a trusted recovery and meets
#      the other's stamps.
#
# NOTHING IS FAKED.  Every block, stamp and log image is written by a real
# mount doing real work; the harness controls only which node acts when, and
# when the power goes out.  No ledger content is authored here.
#
# WHAT A FIRED HOLE LOOKS LIKE: 'P-OWN-RECOVERY ... untrusted=0 buflsn_skips=N'
# with N>=1 on the node whose fsync-acked dirents then turn up MISSING.  That
# pair is a lost update with a named mechanism.
#
# WHAT A CLEAN LAP LOOKS LIKE: recovery ran on a non-empty log (the vacuity
# gate), buflsn_skips=0 on every trusted recovery, and every fsync-acked name
# is present.  A lap where no recovery ran measured NOTHING and says VACUOUS.
#
# the budget rule (derived, measured parts named): prep 45 s (bound 300); phase-1 is
# 3000 creates + sync on one node, ~45 s at the measured ~70 creates/s (bound
# 240); phase-3 is 200 creates + a dir fsync, ~5 s (bound 90); destroy 2x ~4 s;
# VM restart + boot ~60 s (bound 150); module deploy ~15 s (bound 150); each
# mount 3-5 s healthy, bound 90 (18x healthy, past the ~62 s retry budget);
# assertions ~20 s.  Healthy wall ~250 s; wrapper 520 s.
#
# Usage: tests/d0521_own_slice_cross_stamp_probe.sh <label>
# Env:   MXFS_NODE_LIST, MXFS_DEV, MXFS_MODARGS, NB (phase-1 files on B,
#        default 3000), NA (phase-3 files on A, default 200), JOIN_BOUND (90).
set -u
LABEL=${1:?label}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
# the device under test by identity, not by path: the LUN this rig declares
# (data/rigs.json), verified by its WWID on the node, and the node's live mxfs
# mount when it has one; MXFS_DEV names a candidate that must be that LUN.
# mxfs_dev_resolve (tests/lib/rig.sh) ABORTs on anything else, never defaults
. "$(dirname "$0")/lib/rig.sh"
mxfs_dev_resolve "${MXFS_NODE_LIST%%,*}"; export MXFS_DEV=$MXFS_DEV_RESOLVED
A=${MXFS_NODE_LIST%%,*}
B=${MXFS_NODE_LIST##*,}
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
MODARGS=${MXFS_MODARGS:-$(mxfs_rig_modargs)}
KO=/root/mxfs.ko.prep
# B's workload is deliberately MUCH larger than A's.  Both slices are fresh from
# the prep's mkfs, so both start at cycle 1 near block 0; the veto fires only
# when the platter stamp compares >= the replaying node's transaction LSN.
# Doing B's work first AND making it larger drives B's slice position well past
# where A's phase-3 transactions sit in A's own slice, which is what biases the
# meaningless comparison toward the SKIP outcome.  These are real log positions
# reached by real work — the bias is in the workload, not in any number.
NB=${NB:-3000}
NA=${NA:-200}
JOIN_BOUND=${JOIN_BOUND:-90}
DIR=$MNT/d0521_$LABEL
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_d0521_$LABEL
mkdir -p "$OUT"
fails=0
# ck: tests/lib/rig.sh (sourced above) provides it, and its version ABORTs on an EMPTY value instead of printing a FAIL about MXFS
# ckge: tests/lib/rig.sh (sourced above) provides it, and its version ABORTs on an EMPTY value instead of printing a FAIL about MXFS
# rs/rsx/measure/capture_require/cnt (tests/lib/rig.sh): every capture a
# verdict is counted from crosses the boundary in the parent shell first; a
# failed acquisition is an ABORT, never a count of zero.
. "$(dirname "$0")/lib/rig.sh"
# a field is read wherever it sits on the line, not only at its start: an
# arm that prints "SEEN=1 PAUSED=1" on one line had its second field read as
# an empty string under an anchored match, which aborts a healthy lap.
field(){ grep -aoE "(^| )$2=[^ ]*" "$1" | head -1 | cut -d= -f2; }
SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
echo "=== d0521_own_slice_cross_stamp_probe label=$LABEL A=$A B=$B sv=$SV nb=$NB na=$NA $(date -u +%FT%TZ) ==="
s0=$(date +%s)

ready() {   # <node> — pam_nologin clears only when the boot is finished
    local w=0
    until [ "$(timeout 15 $SSH "$1" 'test -e /run/nologin && echo booting || echo ready' 2>/dev/null | grep -a 'booting\|ready' | tail -1)" = ready ] || [ $w -ge 30 ]; do w=$((w+1)); sleep 5; done
}
for n in $A $B; do ready "$n"; done

MXFS_FORCE_PREP=1 timeout 300 ./run.sh 2 tcp prep_cluster > "$OUT/prep.log" 2>&1
prc=$?
echo "STAGE prep rc=$prc wall=$(( $(date +%s) - s0 ))s  $(grep -am1 'prep_cluster OK\|FAIL' "$OUT/prep.log" | cut -c1-140)"
[ $prc = 0 ] || { echo "RESULT: FAIL label=$LABEL stage=prep evidence=$OUT"; exit 2; }
value_now_into rv1 "$A" 30 "$OUT/rv_rv1_1.txt" '^[0-9A-F]+$' "rv1 on $A" 'cat /sys/module/mxfs/srcversion 2>/dev/null'
ck "the rig runs this build" "$rv1" "$SV"
[ $fails = 0 ] || { echo "RESULT: FAIL label=$LABEL wrong build evidence=$OUT"; exit 2; }

# ---- Phase 1: B alone writes the directory and SYNCS, so the platter copies of
# its dir blocks / AGI / inode clusters carry B's SLICE LSN.
rs 240 "$B" "mkdir -p $DIR && for i in \$(seq 1 $NB); do : > $DIR/b_\$i; done; sync; echo PHASE1_RC=\$?; ls $DIR | wc -l" > "$OUT/phase1.txt"
echo "STAGE phase1 (B stamps the platter) rc=$(field "$OUT/phase1.txt" PHASE1_RC) files=$(tail -1 "$OUT/phase1.txt") wall=$(( $(date +%s) - s0 ))s"
ck "B created and synced its $NB files" "$(field "$OUT/phase1.txt" PHASE1_RC)" "0"

# ---- Phase 2+3: A takes the dir and the AG from B, creates its own names and
# FSYNCS THE DIRECTORY.  A deliberately does NOT sync: the images must stay in
# A's log and AIL only, so the crash leaves them there and nothing else.
rs 90 "$A" "for i in \$(seq 1 $NA); do : > $DIR/a_\$i; done; python3 -c \"import os,sys; fd=os.open('$DIR', os.O_RDONLY); os.fsync(fd); os.close(fd)\"; echo PHASE3_RC=\$?; ls $DIR | grep -c '^a_'" > "$OUT/phase3.txt"
acked=$(tail -1 "$OUT/phase3.txt")
echo "STAGE phase3 (A fsync-acks $NA dirents into its own slice) rc=$(field "$OUT/phase3.txt" PHASE3_RC) acked=$acked wall=$(( $(date +%s) - s0 ))s"
ck "A's directory fsync returned success" "$(field "$OUT/phase3.txt" PHASE3_RC)" "0"
ck "A sees the $NA names it fsync-acked" "$acked" "$NA"
[ $fails = 0 ] || { echo "RESULT: FAIL label=$LABEL precondition not built evidence=$OUT"; exit 2; }

# ---- Phase 4: BOTH nodes die.  No unmount, no quiesce, no purge, no peer
# replay — each slice stays dirty and each node must recover its own.
for n in $A $B; do timeout 30 virsh -c qemu:///system destroy "$n" > /dev/null 2>&1; done
for n in $A $B; do timeout 30 virsh -c qemu:///system start "$n" > /dev/null 2>&1; done
for n in $A $B; do ready "$n"; done
echo "STAGE crash+restart wall=$(( $(date +%s) - s0 ))s"
MD5=$(md5sum mxfs.ko | cut -c1-32)
for n in $A $B; do
    value_now_into got "$n" 150 "$OUT/rv_got_2.txt" '^[0-9a-f]{32}$' "got on $n" "for try in 1 2 3 4 5 6; do mountpoint -q /src && break; mkdir -p /src; timeout 12 mount -t nfs 192.168.1.4:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null; sleep 4; done; cp /src/mxfs/mxfs.ko $KO && md5sum $KO | cut -c1-32"
    ck "$n runs the tree build (md5)" "$got" "$MD5"
done
[ $fails = 0 ] || { echo "RESULT: FAIL label=$LABEL deploy evidence=$OUT"; exit 2; }

# ---- Phase 5: both remount concurrently.  Neither slice was foreign-replayed,
# so each node's own slice is recovered by its owner as a TRUSTED recovery.
join() {  # <node> <tag>
    rsx $((JOIN_BOUND + 60)) "$1" "M=\$(date +%s); echo MARK=\$M; lsmod | grep -q '^mxfs ' || insmod $KO dyndbg=+p $MODARGS; echo INSMOD_RC=\$?; T0=\$(date +%s%N); mountpoint -q $MNT || timeout $JOIN_BOUND mount -t mxfs $MXFS_DEV $MNT; echo MOUNT_RC=\$?; echo WALL_MS=\$(( (\$(date +%s%N) - T0) / 1000000 )); mountpoint -q $MNT && echo MOUNTED || echo NOT_MOUNTED" > "$OUT/$2_join.txt"
}
join "$A" A & join "$B" B & wait
# both join lists always end in their mount state (a refused mount is a
# verdict); an absent state line is a failed acquisition
capture_require "$OUT/A_join.txt" '^(MOUNTED|NOT_MOUNTED)$' "the join of $A"
capture_require "$OUT/B_join.txt" '^(MOUNTED|NOT_MOUNTED)$' "the join of $B"
echo "STAGE join A rc=$(field "$OUT/A_join.txt" MOUNT_RC) wall=$(field "$OUT/A_join.txt" WALL_MS)ms B rc=$(field "$OUT/B_join.txt" MOUNT_RC) wall=$(field "$OUT/B_join.txt" WALL_MS)ms total=$(( $(date +%s) - s0 ))s"
for t in A B; do
    n=$([ "$t" = A ] && echo "$A" || echo "$B")
    m=$(field "$OUT/${t}_join.txt" MARK); require_epoch "$m" "the join mark of $n"
    measure "$n" 60 "$OUT/${t}_journal.txt" '^JOURNAL_END$' "the kernel journal on $n since its join mark" "journalctl -k --since @$m --no-pager 2>/dev/null | cut -c1-700; echo JOURNAL_END"
done
capture_require "$OUT/A_journal.txt" '^JOURNAL_END$' "the kernel journal on $A"
capture_require "$OUT/B_journal.txt" '^JOURNAL_END$' "the kernel journal on $B"

# ---- 1. VACUITY GATE.  If no recovery ran, or every slice was empty, this lap
# says nothing about a veto that can only happen during recovery.
recA=$(cnt "$OUT/A_journal.txt" 'Starting recovery')
recB=$(cnt "$OUT/B_journal.txt" 'Starting recovery')
echo "--- recovery ran: A=$recA B=$recB"
grep -ah 'Starting recovery\|Ending clean mount\|Ending recovery' "$OUT"/A_journal.txt "$OUT"/B_journal.txt | sed 's/.*kernel: /    /' | cut -c1-150 | head -4
if [ $(( recA + recB )) -lt 1 ]; then
    echo "  VACUOUS no node recovered a log — both slices were clean at the crash, so no LSN veto could occur and this lap measured NOTHING about H2"
    echo "RESULT: VACUOUS label=$LABEL wall=$(( $(date +%s) - s0 ))s evidence=$OUT"
    exit 3
fi
ckge "at least one node recovered a dirty log (vacuity gate)" "$(( recA + recB ))" 1

# ---- 2. THE CENSUS.  P-OWN-RECOVERY prints only when a veto or an override
# actually happened, so its ABSENCE is itself the clean answer — but absence
# must be distinguished from "the line could not be read", which the vacuity
# gate above has already ruled out.
echo "--- own-slice recovery census (P-OWN-RECOVERY prints only when skips|overrides > 0):"
grep -ah 'P-OWN-RECOVERY' "$OUT"/A_journal.txt "$OUT"/B_journal.txt | sed 's/.*mxfs: /    /' | cut -c1-220 | head -6
for t in A B; do
    n=$([ "$t" = A ] && echo "$A" || echo "$B")
    f="$OUT/${t}_journal.txt"
    # A TRUSTED census line (untrusted=0) with skips>0 is the H2 hole firing.
    tskip=$(grep -ah 'P-OWN-RECOVERY' "$f" | grep -a 'untrusted=0' | grep -ao 'buflsn_skips=[0-9]*' | cut -d= -f2 | sort -rn | head -1)
    echo "  INFO $t trusted-recovery buflsn_skips=${tskip:-0} (untrusted census lines: $(grep -ah 'P-OWN-RECOVERY' "$f" | grep -ac 'untrusted=1'))"
    ck "$t: zero LSN vetoes on a TRUSTED clustered recovery (each one is a lost update)" "${tskip:-0}" "0"
done

# ---- 3. THE DATA.  Whatever the census says, the fsync-acked names must be
# there.  This is the assertion the user's criterion actually turns on.
for t in A B; do
    n=$([ "$t" = A ] && echo "$A" || echo "$B")
    ck "$n completed its mount" "$(grep -ac '^MOUNTED' "$OUT/${t}_join.txt")" 1
    ck "$n returned a mount rc" "$(field "$OUT/${t}_join.txt" MOUNT_RC)" "0"
    ck "$n: zero shutdown / BUG / Oops" \
       "$(( $(cnt "$OUT/${t}_journal.txt" 'shutting down filesystem') + $(cnt "$OUT/${t}_journal.txt" 'BUG:\|Oops') ))" 0
done
rs 60 "$A" "ls $DIR 2>/dev/null | grep -c '^a_'; ls $DIR 2>/dev/null | grep -c '^b_'" > "$OUT/after.txt"
gota=$(sed -n 1p "$OUT/after.txt"); gotb=$(sed -n 2p "$OUT/after.txt")
echo "--- after recovery: a_* = $gota (fsync-acked $NA), b_* = $gotb (synced $NB)"
ck "every dirent A FSYNC-ACKED survived the whole-cluster crash" "$gota" "$NA"
ck "every dirent B synced survived the whole-cluster crash" "$gotb" "$NB"

echo "RESULT: $( [ $fails = 0 ] && echo PASS || echo FAIL ) label=$LABEL fails=$fails wall=$(( $(date +%s) - s0 ))s evidence=$OUT"
[ $fails = 0 ]
