#!/bin/sh
# fr_mount_barrier_fail.sh — closure arm for
#   D-FOREIGN-REPLAY-FAILURE-PUBLISHED-AS-RECOVERED
#
# The live-path refusal (re-elect/dead_node_notify discarding a failed
# replay) was rig-verified sess234 under a genuine -117.  What kept the
# entry OPEN: the MOUNT-COHORT BARRIER call site (xfs_mxfs_dlm.c step (c))
# has the identical checked-return fix but was never exercised under a
# genuine failure.  This arm exercises BOTH sites with the retryable
# injection knob `dbg_fr_fail_replay` (0.27.6, xfs_log.c: while >0 every
# foreign-slice replay fails -EIO before any work, verdict reason NONE):
#
#   1. knob=1 on ALL nodes; joiner J cleanly unmounts; victim V is
#      virsh-destroyed mid-cluster.
#   2. Survivors elect + fail: P-DBG-FR-FAIL-REPLAY fires, NOTHING is
#      published (no "released heartbeat slot", no P163-RECOVERY-COMPLETE,
#      no P241 terminal), and the reap RE-ARMS (>=2 injection hits over the
#      observation window = retry loop live).
#   3. J mounts INTO the failure: its cohort barrier hits the same knob and
#      must log "replay FAILED (-5) — the slot stays unpublished, its
#      grants stay frozen and it will be replayed again" (the reason-NONE
#      branch) and must NOT publish.  Mount outcome recorded either way
#      (fail-closed -EBUSY after the admission bound is legitimate).
#   4. knob=0 everywhere: the RETRY must genuinely replay V's slice —
#      "foreign replay of ... complete" + slot release — proving the
#      refusal was a delay, never a lost slice (entry step 2).
#   5. V restarted (VM only) for the next prep.
#
# the budget rule (derived): umount J ~5s + HB expiry ~62s + refusal observe 40s +
# mount J <=120s + retry/publish <=95s + sweeps ~40s => ~360s. Bound 420s
# end-to-end by the caller; every remote call bounded here.
# the unkillable-wedge rule: comm-safe process handling only; all ssh bounded; per-node rc.
#
# Usage: tests/fr_mount_barrier_fail.sh <label> [victim] [joiner] [nodes]
#        tests/fr_mount_barrier_fail.sh <label> --cold2
#
# --cold2 (sess413): the 32-node arm CANNOT reach the barrier's own error
# branch — with 30 live survivors one of them always holds the recovery
# lease, so the joiner's barrier only ever waits on it (measured frmb1:
# "being recovered by another survivor" x4 then "barrier failed",
# fail-closed).  cold2 makes the mounting node the ONLY live node:
#   ./run.sh 2 caw prep_cluster (tears down running extras first), victim
#   churns and is virsh-destroyed, the joiner cleanly unmounts, arms
#   dbg_fr_fail_replay=1 locally, and cold-mounts: its cohort barrier must
#   itself fence + replay the dead slice, hit the knob, and log the
#   reason-NONE "replay FAILED ... stays unpublished ... will be replayed
#   again" alert with NOTHING published; the mount fails closed.  Clearing
#   the knob and remounting must fence/replay/publish exactly once.
#   The caller re-preps 32/caw afterwards.
# the budget rule cold2 (derived): prep2 incl. 30-node teardown ~240s + churn/kill
# 20s + failed mount <=140s + remount <=140s + sweeps 40s => ~580s.
set -u
LABEL=${1:?label}
if [ "${2:-}" = --cold2 ]; then MODE=cold2; VICTIM=test2; JOINER=test1; NODES=2
else MODE=live32; VICTIM=${2:-test20}; JOINER=${3:-test21}; NODES=${4:-32}; fi
[ "$VICTIM" = "$JOINER" ] && { echo "victim and joiner must differ"; exit 2; }
cd "$(dirname "$0")/.." || exit 2
SSH=tools/mxfs_sshpass.sh
# the device under test by identity, not by path: the LUN this rig declares
# (data/rigs.json), verified by its WWID on the node, and the node's live mxfs
# mount when it has one; MXFS_DEV names a candidate that must be that LUN.
# mxfs_dev_resolve (tests/lib/rig.sh) ABORTs on anything else, never defaults
. "$(dirname "$0")/lib/rig.sh"
mxfs_dev_resolve "$VICTIM"; DEV=$MXFS_DEV_RESOLVED
MNT=${MXFS_MNT:-/mnt/shared}
OUT=${FRMB_OUT:-tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_frmb}
mkdir -p "$OUT"
t0=$(date +%s)
echo "=== fr_mount_barrier_fail label=$LABEL victim=$VICTIM joiner=$JOINER nodes=$NODES out=$OUT $(date -u +%FT%TZ) ==="

filt() { grep -av '^Unauthorized\|^Warning:\|^If you'; }

if [ "$MODE" = cold2 ]; then
    # ---- cold2: sole-survivor cold-start hits the barrier's OWN error branch
    timeout 300 ./run.sh 2 caw prep_cluster > "$OUT/prep2.log" 2>&1; prc=$?
    grep -q "prep_cluster OK" "$OUT/prep2.log" || { echo "FAIL: 2-node prep failed rc=$prc — see $OUT/prep2.log"; exit 2; }
    echo "2-node cluster formed ($(grep -m1 'prep OK' "$OUT/prep2.log" | cut -c1-100))"
    vc=$(timeout 20 $SSH "$VICTIM" "dmesg | grep -a 'claimed heartbeat slot' | tail -1" 2>/dev/null | filt | tail -1)
    VSLOT=$(printf '%s\n' "$vc" | sed -n 's/.*claimed heartbeat slot \([0-9]*\) .*/\1/p')
    [ -n "${VSLOT:-}" ] || { echo "FAIL: could not learn victim slot ('$vc')"; exit 2; }
    echo "victim=$VICTIM slot=$VSLOT sole-joiner=$JOINER"
    # arm enforcement on the joiner: without it the eventual replay is the
    # DESIGNED default-config blanket refusal (untokenized-image ATOMIC-SKIP
    # -> POLICY-REFUSED) and the retry leg can never assert 'complete'
    # (measured frmb3: enforce_cfg=0, WOULD_APPLY=20, refused=4).
    ek=$(timeout 20 $SSH "$JOINER" "echo 1 > /sys/module/mxfs/parameters/target_cache_protected && echo 1 > /sys/module/mxfs/parameters/foreign_replay_token_enforce && echo EARMED" 2>/dev/null | filt | tr '\n' ' ')
    case "$ek" in *EARMED*) ;; *) echo "FAIL: could not arm enforcement on $JOINER ($ek)"; exit 2;; esac
    jrc=$(timeout 60 $SSH "$JOINER" "umount $MNT && echo UNMOUNTED" 2>/dev/null | filt | tr '\n' ' ')
    case "$jrc" in *UNMOUNTED*) ;; *) echo "FAIL: joiner did not cleanly unmount ($jrc)"; exit 2;; esac
    ch=$(timeout 40 $SSH "$VICTIM" "mkdir -p $MNT/frmb_cold; i=0; while [ \$i -lt 400 ]; do echo x > $MNT/frmb_cold/f\$i || break; i=\$((i+1)); done; echo churn_done=\$i" 2>/dev/null | filt | tail -1)
    echo "victim churn (unsynced): $ch"
    timeout 60 sudo virsh -c qemu:///system destroy "$VICTIM" > /dev/null 2>&1
    tk=$(date +%s); echo "virsh destroy $VICTIM rc=$? at $(date -u +%FT%TZ)"
    arm=$(timeout 20 $SSH "$JOINER" "echo 1 > /sys/module/mxfs/parameters/dbg_fr_fail_replay && echo ARMED; echo '$LABEL-cold2-mark' > /dev/kmsg" 2>/dev/null | filt | tr '\n' ' ')
    case "$arm" in *ARMED*) ;; *) echo "FAIL: could not arm the knob on $JOINER ($arm)"; exit 2;; esac
    sleep 70    # HB expiry (~62s) so the cold mount sees a DEAD member, not a live one
    jm=$(timeout 170 $SSH "$JOINER" "timeout 150 mount -t mxfs $DEV $MNT > /tmp/frmb_cold_mount.log 2>&1; echo MOUNT_RC=\$?; grep -c ' mxfs ' /proc/mounts" 2>/dev/null | filt | tr '\n' ' ')
    echo "cold mount INTO the failure: $jm  (+$(( $(date +%s) - tk ))s after kill)"
    timeout 25 $SSH "$JOINER" "dmesg | sed -n '/$LABEL-cold2-mark/,\$p'" 2>/dev/null | filt > "$OUT/cold_mount_dmesg.txt"
    cinj=$(grep -ac "P-DBG-FR-FAIL-REPLAY slot $VSLOT" "$OUT/cold_mount_dmesg.txt")
    cfail=$(grep -ac "stays unpublished" "$OUT/cold_mount_dmesg.txt")
    cpub=$(grep -ac "released heartbeat slot $VSLOT \|P163-RECOVERY-COMPLETE slot=$VSLOT\|foreign replay of slot $VSLOT complete\|foreign replay of dead slot $VSLOT .* complete" "$OUT/cold_mount_dmesg.txt")
    echo "cold barrier: injection=$cinj unpublished_alerts=$cfail publish_lines=$cpub  first: $(grep -a -m1 'stays unpublished' "$OUT/cold_mount_dmesg.txt" | cut -c1-200)"
    timeout 20 $SSH "$JOINER" "echo 0 > /sys/module/mxfs/parameters/dbg_fr_fail_replay" >/dev/null 2>&1
    jm2=$(timeout 170 $SSH "$JOINER" "grep -qs ' $MNT mxfs ' /proc/mounts && echo ALREADY_MOUNTED || { timeout 150 mount -t mxfs $DEV $MNT > /tmp/frmb_cold_mount2.log 2>&1; echo MOUNT2_RC=\$?; }; grep -c ' mxfs ' /proc/mounts" 2>/dev/null | filt | tr '\n' ' ')
    echo "remount after knob clear: $jm2"
    timeout 25 $SSH "$JOINER" "dmesg | sed -n '/$LABEL-cold2-mark/,\$p' | grep -a 'foreign replay\|P163-RECOVERY-COMPLETE\|released heartbeat slot'" 2>/dev/null | filt > "$OUT/cold_replay_lines.txt"
    rcomplete=$(grep -ac "foreign replay of .*slot $VSLOT.*complete\|foreign replay of slot $VSLOT complete" "$OUT/cold_replay_lines.txt")
    echo "replay-complete lines for slot $VSLOT after clear: $rcomplete  ($(grep -a -m1 complete "$OUT/cold_replay_lines.txt" | cut -c1-160))"
    timeout 60 sudo virsh -c qemu:///system start "$VICTIM" >/dev/null 2>&1
    echo "victim VM restarted rc=$?"
    fail=0
    [ "${cinj:-0}" -ge 1 ] || { echo "FAIL: the cold mount's cohort barrier never hit the injection (cinj=$cinj)"; fail=1; }
    [ "${cfail:-0}" -ge 1 ] || { echo "FAIL: the reason-NONE 'stays unpublished' barrier alert never fired"; fail=1; }
    [ "${cpub:-0}" = 0 ] || { echo "FAIL: $cpub publish lines for slot $VSLOT while the knob was set — a failed replay was published"; fail=1; }
    case "$jm" in *"MOUNT_RC=0"*) echo "note: the cold mount SUCCEEDED with the slice unreplayed — record, inspect $OUT/cold_mount_dmesg.txt for frozen-grant containment";; esac
    [ "${rcomplete:-0}" -ge 1 ] || { echo "FAIL: the slice was never replayed after the knob cleared"; fail=1; }
    case "$jm2" in *ALREADY_MOUNTED*|*"MOUNT2_RC=0"*) ;; *) echo "FAIL: joiner not mounted at the end ($jm2)"; fail=1;; esac
    if [ $fail = 0 ]; then echo "VERDICT PASS: the mount-cohort barrier's own error branch refused to publish under forced failure, and the cleared knob's cold retry replayed slot $VSLOT"; else echo "VERDICT FAIL"; fi
    echo "=== done label=$LABEL mode=cold2 total=$(( $(date +%s) - t0 ))s out=$OUT ==="
    exit $fail
fi

# victim identity (slot) from its claim line
vc=$(timeout 20 $SSH "$VICTIM" "(journalctl -k -o cat --since -60min 2>/dev/null; dmesg) | grep -a 'claimed heartbeat slot' | tail -1" 2>/dev/null | filt | tail -1)
VSLOT=$(printf '%s\n' "$vc" | sed -n 's/.*claimed heartbeat slot \([0-9]*\) .*/\1/p')
[ -n "${VSLOT:-}" ] || { echo "FAIL: could not learn victim slot ('$vc')"; exit 2; }
echo "victim=$VICTIM slot=$VSLOT joiner=$JOINER"

# 1. arm the knob fleet-wide, mark kmsg, cleanly unmount the joiner
tests/fleet_set_params.sh "dbg_fr_fail_replay=1" "$NODES" "$OUT/knob_on.txt" > /dev/null 2>&1; prc=$?
[ $prc = 0 ] && ! grep -q SETFAIL "$OUT/knob_on.txt" || { echo "FAIL: knob arm refused (module < 0.27.6?)"; exit 2; }
MARK="FRMB-$LABEL-$$-$(date -u +%s)"
for i in $(seq 1 "$NODES"); do ( timeout 20 $SSH "test$i" "echo '$MARK' > /dev/kmsg" >/dev/null 2>&1 ) & done; wait
jrc=$(timeout 60 $SSH "$JOINER" "umount $MNT && echo UNMOUNTED; grep -c ' mxfs ' /proc/mounts" 2>/dev/null | filt | tr '\n' ' ')
echo "joiner umount: $jrc"
case "$jrc" in *UNMOUNTED*) ;; *) echo "FAIL: joiner did not cleanly unmount"; exit 2;; esac

# 2. kill the victim; wait for the survivors' refusal
TK=$(date -u +%FT%TZ); tk=$(date +%s)
timeout 60 sudo virsh -c qemu:///system destroy "$VICTIM" > "$OUT/virsh.txt" 2>&1
echo "virsh destroy $VICTIM rc=$? at $TK"
# HB expiry ~62s then election+injection; observe until first hit, bound 100s
inj=""
while :; do
    now=$(date +%s)
    inj=$(timeout 15 $SSH test1 "dmesg | sed -n '/$MARK/,\$p' | grep -a -m1 'P-DBG-FR-FAIL-REPLAY slot $VSLOT'" 2>/dev/null | filt | tail -1)
    [ -n "$inj" ] && { echo "injection hit on test1 at +$(( now - tk ))s: $(printf '%s' "$inj" | cut -c1-160)"; break; }
    [ $(( now - tk )) -ge 100 ] && { echo "note: no injection hit on test1 within 100s (another survivor may hold the election)"; break; }
    sleep 5
done
sleep 30    # let the reap re-arm and retry at least once
D=$(mktemp -d)
for i in $(seq 1 "$NODES"); do
    [ "test$i" = "$VICTIM" ] || [ "test$i" = "$JOINER" ] && continue
    ( timeout 20 $SSH "test$i" "dmesg | sed -n '/$MARK/,\$p' | grep -ac 'P-DBG-FR-FAIL-REPLAY slot $VSLOT'; dmesg | sed -n '/$MARK/,\$p' | grep -ac \"released heartbeat slot $VSLOT \\|P163-RECOVERY-COMPLETE slot=$VSLOT\\|foreign replay of slot $VSLOT complete\\|P241-RECOV-TERMINAL slot=$VSLOT\"" 2>/dev/null | filt | tr '\n' ' ' > "$D/s$i" ) &
done; wait
inj_total=0; pub_total=0
for i in $(seq 1 "$NODES"); do
    [ "test$i" = "$VICTIM" ] || [ "test$i" = "$JOINER" ] && continue
    read -r a b < "$D/s$i" 2>/dev/null || continue
    inj_total=$(( inj_total + ${a:-0} )); pub_total=$(( pub_total + ${b:-0} ))
    echo "test$i inj=${a:-?} pub=${b:-?}" >> "$OUT/survivor_counts.txt"
done
echo "survivors during refusal window: injection_hits=$inj_total publish_lines=$pub_total"

# 3. the joiner mounts INTO the failure (its own knob is still set)
jm=$(timeout 150 $SSH "$JOINER" "echo '$MARK' > /dev/kmsg; timeout 130 mount -t mxfs $DEV $MNT > /tmp/frmb_mount.log 2>&1; echo MOUNT_RC=\$?; grep -c ' mxfs ' /proc/mounts" 2>/dev/null | filt | tr '\n' ' ')
echo "joiner mount attempt (knob still set): $jm"
timeout 20 $SSH "$JOINER" "dmesg | sed -n '/$MARK/,\$p' | grep -a 'P-DBG-FR-FAIL-REPLAY\|replay FAILED\|stays unpublished\|MXFS mount recovery'" 2>/dev/null | filt > "$OUT/joiner_barrier.txt"
jinj=$(grep -ac "P-DBG-FR-FAIL-REPLAY slot $VSLOT" "$OUT/joiner_barrier.txt")
jfailmsg=$(grep -ac "stays unpublished" "$OUT/joiner_barrier.txt")
echo "joiner barrier: injection_hits=$jinj unpublished_alerts=$jfailmsg  first: $(grep -a -m1 'stays unpublished' "$OUT/joiner_barrier.txt" | cut -c1-200)"

# 4. clear the knob everywhere; the retry must replay + publish
tests/fleet_set_params.sh "dbg_fr_fail_replay=0" "$NODES" "$OUT/knob_off.txt" > /dev/null 2>&1
# the joiner may be mid-mount-retry or unmounted-failed; give the cluster the
# recovery window (reap re-arm cadence + replay <=95s)
tr0=$(date +%s); done_line=""
while :; do
    now=$(date +%s)
    for i in 1 2 3 4; do
        done_line=$(timeout 15 $SSH "test$i" "dmesg | sed -n '/$MARK/,\$p' | grep -a -m1 'foreign replay of slot $VSLOT complete\|foreign replay of dead slot $VSLOT .* complete\|released heartbeat slot $VSLOT '" 2>/dev/null | filt | tail -1)
        [ -n "$done_line" ] && break
    done
    [ -n "$done_line" ] && { echo "RETRY REPLAYED at +$(( now - tr0 ))s after knob clear: $(printf '%s' "$done_line" | cut -c1-180)"; break; }
    [ $(( now - tr0 )) -ge 120 ] && { echo "WAIT EXPIRED: no successful replay of slot $VSLOT within 120s of clearing the knob"; break; }
    sleep 5
done
# if the joiner's earlier mount failed, retry it now that the knob is clear
jm2=$(timeout 150 $SSH "$JOINER" "grep -qs ' $MNT mxfs ' /proc/mounts && echo ALREADY_MOUNTED || { timeout 130 mount -t mxfs $DEV $MNT > /tmp/frmb_mount2.log 2>&1; echo MOUNT2_RC=\$?; }; grep -c ' mxfs ' /proc/mounts" 2>/dev/null | filt | tr '\n' ' ')
echo "joiner final mount state: $jm2"

# 5. restart the victim VM for the next prep
timeout 60 sudo virsh -c qemu:///system start "$VICTIM" >/dev/null 2>&1
echo "victim VM restarted rc=$?"

# verdict
fail=0
[ "$inj_total" -ge 2 ] || { echo "FAIL: fewer than 2 injection hits on survivors ($inj_total) — the refusal/re-arm retry loop did not run"; fail=1; }
[ "$pub_total" = 0 ] || { echo "FAIL: $pub_total publish/complete/terminal lines for slot $VSLOT DURING the forced-failure window — a failed replay was published"; fail=1; }
[ "${jinj:-0}" -ge 1 ] || { echo "FAIL: the joiner's mount-cohort barrier never hit the injection (jinj=$jinj) — the mount-barrier site was not exercised"; fail=1; }
[ "${jfailmsg:-0}" -ge 1 ] || { echo "FAIL: the joiner never logged the reason-NONE 'stays unpublished' barrier alert"; fail=1; }
[ -n "$done_line" ] || { echo "FAIL: the slice was never replayed after the knob cleared — the refusal lost the slice"; fail=1; }
case "$jm2" in *ALREADY_MOUNTED*|*"MOUNT2_RC=0"*) ;; *) echo "FAIL: joiner is not mounted at the end ($jm2)"; fail=1;; esac
if [ $fail = 0 ]; then echo "VERDICT PASS: both call sites refused to publish under forced failure, and the cleared knob's retry replayed slot $VSLOT"; else echo "VERDICT FAIL"; fi
echo "=== done label=$LABEL total=$(( $(date +%s) - t0 ))s out=$OUT ==="
exit $fail
