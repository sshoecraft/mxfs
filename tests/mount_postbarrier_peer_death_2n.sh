#!/bin/bash
# mount_postbarrier_peer_death_2n.sh — a peer dies AFTER the mounting node's
# recovery barrier has admitted it, while it holds a lock the mount needs
# (D-PEER-DEATH-AFTER-ADMISSION-BARRIER-STALLS-MOUNT-THEN-SHUTDOWN).
#
# THE SHAPE, AS MEASURED ON THE UBUNTU PAIR.  test3 held the root inode EX and
# was power-cycled a second before test4's mount looked at the heartbeat table;
# it still read as live, so test4's barrier admitted with a clean cut.  test4's
# monitor declared test3 dead 62 s later, fenced it, and could only RECORD the
# death (P233-MPHASE-DEATH): the slice-replay hook is registered after
# xfs_mountfs returns.  The root acquire waited three 120 s budgets on the
# frozen grant and then shut the filesystem down.
#
# HERE IT IS MADE DETERMINISTIC.  A mounts, writes NFILES files into the root
# directory (A now caches the root inode EX) and fsyncs them.  B, unmounted,
# arms the one-shot mxfs.dbg_barrier_admit_hold_ms and mounts; the hold runs
# right after B's barrier admits and before its root lookup.  When B logs
# P-DBG-ADMIT-HOLD start, A is destroyed.  B's root acquire then waits on A's
# grant exactly as test4's did.
#
# WHAT MUST HOLD (0.90.6): B's root acquire gives up (P-MPHASE-ACQ-GIVEUP or
# P-MPHASE-AGLOCK-GIVEUP), the mount re-runs its barrier (P-MPHASE-REBARRIER),
# the re-run replays and publishes A's slice (barrier complete ... re-run ...
# replayed>=1), and the mount SUCCEEDS: no shutdown, no withdrawal, every file
# A fsynced reads back identical on B, B can write, B unmounts, and the volume
# checks clean.
#
# the budget rule (derived): prep bounded by run.sh (measured 51-65 s) + A's
# payload ~10 + B umount ~5 + B's mount: hold 15 + A's dead window 62 s inside
# the first 120 s acquire budget (the give-up lands when that budget ends,
# ~135 s after the hold) + the re-run's fence check and one-slice replay ~30 =
# ~180 s, bounded 270 + read-back ~15 + umount ~10 + chk_mxfs ~60 + restart A
# ~5.  Summed at the bounds ~ 70 + 10 + 10 + 270 + 30 + 20 + 90 + 10 = 510 s
# after prep; caller bound 700 s including prep.
#
# Usage: tests/mount_postbarrier_peer_death_2n.sh <label>
# Env:   MXFS_NODE_LIST (default test1,test2), MXFS_TRANSPORT (cawd),
#        NFILES (32), HOLD_MS (15000), MOUNT_BOUND (270)
# Exit 0 PASS, 1 FAIL, 2 ABORT/INFRA.
set -u
LABEL=${1:?label}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-cawd}
A=${MXFS_NODE_LIST%%,*}          # holds the root EX, then is destroyed
B=${MXFS_NODE_LIST##*,}          # mounts across A's death
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
NFILES=${NFILES:-32}
HOLD_MS=${HOLD_MS:-15000}
MOUNT_BOUND=${MOUNT_BOUND:-270}
P=/sys/module/mxfs/parameters
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_pbd_$LABEL
mkdir -p "$OUT"
fails=0
. "$(dirname "$0")/lib/rig.sh"
VIRSH="timeout 30 virsh -c qemu:///system"
s0=$(date +%s)
el() { echo $(( $(date +%s) - s0 )); }
echo "=== mount_postbarrier_peer_death_2n label=$LABEL A(holder)=$A B(mounter)=$B transport=$MXFS_TRANSPORT $(date -u +%FT%TZ) ==="

MXFS_FORCE_PREP=1 ./run.sh 2 "$MXFS_TRANSPORT" prep_cluster > "$OUT/prep.log" 2>&1
prc=$?
echo "STAGE prep rc=$prc wall=$(el)s  $(grep -a 'prep_cluster OK' "$OUT/prep.log" | tail -1)"
[ "$prc" = 0 ] || { echo "ABORT: prep failed: $(tail -3 "$OUT/prep.log" | tr '\n' ' ')"; echo "RESULT: ABORT label=$LABEL stage=prep evidence=$OUT"; exit 2; }
mxfs_dev_resolve "$A"; DEV=$MXFS_DEV_RESOLVED
want=$(modinfo mxfs.ko | awk '/^srcversion:/{print $2}')
for n in $A $B; do
    value_now_into sv "$n" 15 "$OUT/sv_$n.txt" '^SV=[0-9A-F]+$' "the loaded srcversion on $n" "echo SV=\$(cat /sys/module/mxfs/srcversion)"
    ck "$n runs the tree build" "${sv#SV=}" "$want"
done
value_now_into k "$B" 10 "$OUT/knob.txt" '^KNOB=(yes|no)$' "the admit-hold knob on $B" "test -e $P/dbg_barrier_admit_hold_ms && echo KNOB=yes || echo KNOB=no"
[ "$k" = KNOB=yes ] || { echo "ABORT: $B's module has no dbg_barrier_admit_hold_ms (build older than 0.90.6)"; echo "RESULT: ABORT label=$LABEL stage=knob evidence=$OUT"; exit 2; }

MARK="PBD-$LABEL-$$"
for n in $A $B; do rs 12 "$n" "echo '$MARK' > /dev/kmsg" >/dev/null; done
window_into "$OUT/a_slot.txt" "$A" 20
aslot=$(grep -ao 'claimed heartbeat slot [0-9]*' "$OUT/a_slot.txt" | tail -1 | grep -o '[0-9]*$')
[ -n "$aslot" ] || { echo "ABORT: could not read A's heartbeat slot"; echo "RESULT: ABORT label=$LABEL stage=slot evidence=$OUT"; exit 2; }
echo "  INFO A=$A heartbeat slot=$aslot"
capture_on_exit() {
    [ -s "$OUT/dmesg_$B.txt" ] || rs 30 "$B" "dmesg | sed -n \"/$MARK/,\\\$p\"" > "$OUT/dmesg_$B.txt" 2>/dev/null
}
trap capture_on_exit EXIT

# B leaves first, so A's writes below take the root EX with nobody to share it
value_now_into rv "$B" 60 "$OUT/b_umount.txt" '^rc=' "B's unmount" "timeout 45 umount $MNT; echo rc=\$?"
ck "B unmounted" "${rv#rc=}" "0"
measure "$A" 60 "$OUT/a_payload.txt" '^PAYLOAD_END$' "A's payload" \
    "for i in \$(seq 1 $NFILES); do dd if=/dev/urandom of=$MNT/pbd_${LABEL}_\$i bs=4096 count=\$((i % 7 + 1)) conv=fsync 2>/dev/null || echo WERR \$i; done; sync; cd $MNT && md5sum pbd_${LABEL}_* ; echo PAYLOAD_END"
count_file_into werr "$OUT/a_payload.txt" '^WERR'
ck "A wrote and fsynced every file" "$werr" "0"
count_file_into nsum "$OUT/a_payload.txt" " pbd_${LABEL}_"
ck "A checksummed every file" "$nsum" "$NFILES"
grep -a " pbd_${LABEL}_" "$OUT/a_payload.txt" | sort -k2 > "$OUT/a_md5.txt"

value_now_into armed "$B" 10 "$OUT/b_arm.txt" '^ARMED=[0-9]+$' "arming the admit hold on $B" "echo $HOLD_MS > $P/dbg_barrier_admit_hold_ms; echo ARMED=\$(cat $P/dbg_barrier_admit_hold_ms)"
ck "the admit hold is armed on B" "${armed#ARMED=}" "$HOLD_MS"
value_now_into l "$B" 15 "$OUT/b_launch.txt" '^LAUNCHED$' "B's detached mount" \
    "rm -f /tmp/pbd_mount.rc; setsid nohup sh -c 'timeout $MOUNT_BOUND mount -t mxfs $DEV $MNT; echo rc=\$? > /tmp/pbd_mount.rc' >/tmp/pbd_mount.log 2>&1 & echo LAUNCHED"
wait_for_into t "$B" 120 "$MARK" "P-DBG-ADMIT-HOLD start"
ck "B's barrier admitted and the hold started (${t}s)" "$([ "$t" != timeout ] && echo yes || echo no)" "yes"
[ "$t" != timeout ] || { echo "RESULT: FAIL label=$LABEL fails=$fails evidence=$OUT"; exit 1; }
$VIRSH destroy "$A" >/dev/null 2>&1; echo "STAGE virsh destroy $A rc=$? at +$(el)s"
tdestroy=$(date +%s)

# the mount's own outcome: its rc file appears when mount(8) returns
mrc=
while [ $(( $(date +%s) - tdestroy )) -lt $((MOUNT_BOUND + 20)) ]; do
    mrc=$(rs 15 "$B" "cat /tmp/pbd_mount.rc 2>/dev/null" | grep -ao '^rc=[0-9]*')
    [ -n "$mrc" ] && break
    sleep 5
done
echo "STAGE B's mount returned '${mrc:-nothing}' $(( $(date +%s) - tdestroy ))s after A's destroy"
ck "B's mount returned (not killed at its bound)" "$([ -n "$mrc" ] && echo yes || echo no)" "yes"
ck "B's mount succeeded" "${mrc#rc=}" "0"

measure "$B" 30 "$OUT/dmesg_$B.txt" '^DMESG_END$' "the kernel log on $B from the lap marker" "dmesg | sed -n \"/$MARK/,\\\$p\"; echo DMESG_END"
count_file_into n233 "$OUT/dmesg_$B.txt" "P233-MPHASE-DEATH slot=$aslot "
ck "B recorded A's death during its mount (P233-MPHASE-DEATH slot=$aslot)" "$n233" "1"
count_file_into ngive "$OUT/dmesg_$B.txt" 'P-MPHASE-ACQ-GIVEUP\|P-MPHASE-AGLOCK-GIVEUP'
ckge "the root acquire gave up on A's frozen grant instead of waiting it out" "$ngive" 1
count_file_into nreb "$OUT/dmesg_$B.txt" 'P-MPHASE-REBARRIER lap='
ckge "the mount re-ran its barrier" "$nreb" 1
count_file_into nrebf "$OUT/dmesg_$B.txt" 'P-MPHASE-REBARRIER-FAILED\|P-MPHASE-REBARRIER-EXHAUSTED'
ck "no re-run failed or ran out of laps" "$nrebf" "0"
rerun=$(grep -a 'barrier complete (re-run for a late death)' "$OUT/dmesg_$B.txt" | tail -1)
echo "  INFO ${rerun:-no re-run completion line}"
rrep=$(printf '%s\n' "$rerun" | grep -ao 'replayed=[0-9]*' | cut -d= -f2)
rpub=$(printf '%s\n' "$rerun" | grep -ao 'published=0x[0-9a-f]*' | cut -d= -f2)
ckge "the re-run replayed A's slice" "${rrep:-0}" 1
ck "the re-run published A's slot" "$(python3 -c "print('yes' if (int('${rpub:-0x0}',16)>>$aslot)&1 else 'no')")" "yes"
count_file_into nshut "$OUT/dmesg_$B.txt" 'hutting down filesystem\|unrecoverable\|P-WITHDRAW\|P-SESSION-POISON'
ck "B never shut down or withdrew" "$nshut" "0"
count_file_into nbug "$OUT/dmesg_$B.txt" 'BUG:\|Oops\|WARNING:'
ck "no kernel splat on B" "$nbug" "0"

measure "$B" 60 "$OUT/b_readback.txt" '^READBACK_END$' "B's read-back" \
    "cd $MNT && md5sum pbd_${LABEL}_* 2>&1; echo READBACK_END"
grep -a " pbd_${LABEL}_" "$OUT/b_readback.txt" | sort -k2 > "$OUT/b_md5.txt"
ck "every file A fsynced reads back identical on B" "$(cmp -s "$OUT/a_md5.txt" "$OUT/b_md5.txt" && echo yes || echo no)" "yes"
measure "$B" 30 "$OUT/b_write.txt" '^W(OK|ERR)$' "B's write" "echo x > $MNT/pbd_${LABEL}_b && sync && rm -f $MNT/pbd_${LABEL}_b && echo WOK || echo WERR"
ck "B can write" "$(grep -ac '^WOK$' "$OUT/b_write.txt")" "1"
value_now_into rv "$B" 60 "$OUT/b_umount2.txt" '^rc=' "B's final unmount" "timeout 45 umount $MNT; echo rc=\$?"
ck "B unmounted cleanly" "${rv#rc=}" "0"
mxfs_chk_on_node "$B" "$OUT/chk.txt" "chk_mxfs on $B after the lap" -v
ck "the volume checks clean" "$(mxfs_chk_rc "$OUT/chk.txt")" "0"

$VIRSH start "$A" >/dev/null 2>&1; echo "STAGE virsh start $A rc=$? at +$(el)s"
echo "RESULT: $([ "$fails" = 0 ] && echo PASS || echo FAIL) label=$LABEL fails=$fails wall=$(el)s evidence=$OUT"
echo "NOTE: $A was destroyed and restarted — prep_cluster before further rig work."
[ "$fails" = 0 ] || exit 1
exit 0
