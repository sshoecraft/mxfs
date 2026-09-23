#!/bin/bash
# d0977_opener_death.sh — the opener dies while holding the unlinked file
# (D-0977 verification, the fence-strip face of the open-holder marks).
#
#   A creates F (16 KiB of 'V', fsync).  B opens F, reads 4 KiB and HOLDS the
#   fd.  A unlinks F and creates 20 files: the number is NOT reused (B's mark
#   on the ledger record deferred A's free).  B is then virsh-destroyed with
#   the fd open.  Required:
#     - A completes B's recovery (P163-RECOVERY-COMPLETE on A) inside
#       RECOVERY_BOUND;
#     - the number IS reused by A afterwards, inside REUSE_BOUND of the
#       recovery completion (the purge stripped B's mark from the record, or
#       the retired tenancy left its slot unoccupied and the guard's
#       occupancy mask dropped it; the reaper's next retry then freed the
#       zombie) — and NOT before the recovery completed;
#     - every 'G' file A created is intact;
#     - B boots, re-preps, remounts and reads a file A wrote after the fence.
#   Kernel evidence: P87-OPEN-DEFER and P88-REAP-RETRY on A for the number.
#
# the budget rule (derived): create + hold 8 s + unlink and 20 creates 10 s +
# kill 2 s + recovery ≤ RECOVERY_BOUND 240 s + reap poll ≤ REUSE_BOUND 90 s
# (first retry 5 s, then every 30 s, after the purge) + VM boot to ssh ≤
# BOOT_BOUND 180 s + prep ≤ 150 s + checks 15 s ⇒ ~700 s.  Bound 700 s.
#
# Usage: tests/d0977_opener_death.sh <label> [nodeA] [nodeB]  (default test1 test2;
#        B is the node destroyed)
set -u
LABEL=${1:?label}; A=${2:-test1}; B=${3:-test2}
cd "$(dirname "$0")/.." || exit 2
SSH=tools/mxfs_sshpass.sh
VIRSH="virsh -c qemu:///system"
MNT=${MXFS_MNT:-/mnt/shared}
RECOVERY_BOUND=${RECOVERY_BOUND:-240}; REUSE_BOUND=${REUSE_BOUND:-90}
BOOT_BOUND=${BOOT_BOUND:-180}
OUT=${D0977_OUT:-tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_d0977death}
mkdir -p "$OUT"
fails=0
. "$(dirname "$0")/lib/rig.sh"

D="$MNT/.d0977d_$LABEL"
F="$D/victim.dat"
echo "=== d0977_opener_death label=$LABEL A=$A B=$B (B is destroyed) out=$OUT $(date -u +%FT%TZ) ==="
want=$(modinfo mxfs.ko | awk '/^srcversion:/{print $2}')
for n in $A $B; do
  nsv=$(rs 15 "$n" "cat /sys/module/mxfs/srcversion" | tr -dc 'A-F0-9')
  [ "$nsv" = "$want" ] || { echo "RESULT: ABORT label=$LABEL stage=srcgate node=$n got=$nsv want=$want"; exit 2; }
  rs 15 "$n" "grep -q ' $MNT mxfs ' /proc/mounts && echo mounted" | grep -q mounted || { echo "RESULT: ABORT label=$LABEL stage=mounted node=$n"; exit 2; }
done
$VIRSH domstate "$B" 2>/dev/null | grep -q running || { echo "RESULT: ABORT label=$LABEL stage=domstate node=$B"; exit 2; }
mxfs_dev_resolve "$A"
DEV=$MXFS_DEV_RESOLVED
echo "  INFO device=$DEV (from $A's live mount)"
MARK="D0977D-$LABEL-$$"
for n in $A $B; do rs 15 "$n" "echo '$MARK' > /dev/kmsg" >/dev/null; done
g16md5=$(dd if=/dev/zero bs=4096 count=4 2>/dev/null | tr '\0' 'G' | md5sum | cut -d' ' -f1)

value_now_into vline "$A" 25 "$OUT/a_setup.txt" '^VINO=[0-9]+$' "A's victim create" \
  "mkdir -p '$D' && dd if=/dev/zero bs=4096 count=4 2>/dev/null | tr '\\0' 'V' > '$F' && sync -f '$F' && echo VINO=\$(stat -c %i '$F')"
vino=${vline#VINO=}
echo "victim ino=$vino"

# B holds the fd until it is destroyed; the client runs in its own session so
# it can be killed the moment B is (waiting on the corpse's ssh blocks ~90 s)
setsid bash -c "$SSH $B 'exec 7<\"$F\" || { echo BOPEN=fail; exit 1; }; head -c 4096 <&7 >/dev/null 2>&1 && echo BREAD1=ok || echo BREAD1=fail; sleep 600' > '$OUT/b_holder.txt' 2> '$OUT/b_holder.err'" &
bpid=$!
sleep 2
capture_require_bg "$OUT/b_holder.txt" "$OUT/b_holder.err" '^BREAD1=' "B's holder open and first read" || { echo "ABORT: B's holder has not reported its first read 2 s after launch"; echo "RESULT: ABORT label=$LABEL stage=capture evidence=$OUT"; kill -- -"$bpid" 2>/dev/null; exit 2; }
ck "B first read ok" "$(grep -ac 'BREAD1=ok' "$OUT/b_holder.txt")" "1"

value_now_into r1 "$A" 60 "$OUT/a_arm1.txt" '^ARM_D1_REUSED=' "A's unlink + 20 creates" "
    rm -f '$F'
    reused=none; i=0
    while [ \$i -lt 20 ]; do
        i=\$((i+1)); g=\"$D/d1_\$i.dat\"
        dd if=/dev/zero bs=4096 count=4 2>/dev/null | tr '\\0' 'G' > \"\$g\"; sync -f \"\$g\"
        [ \"\$(stat -c %i \"\$g\")\" = \"$vino\" ] && reused=\$g
    done
    echo ARM_D1_REUSED=\$reused"
ck "ino NOT reused while B holds the fd" "${r1#ARM_D1_REUSED=}" "none"

# kill B with the fd open
TK=$(date +%s)
$VIRSH destroy "$B" >/dev/null 2>&1 || { echo "RESULT: ABORT label=$LABEL stage=destroy node=$B"; exit 2; }
kill -- -"$bpid" 2>/dev/null; wait "$bpid" 2>/dev/null
echo "  INFO $B destroyed at $(date -u +%FT%TZ)"

# A must complete B's recovery
wait_for_into trec "$A" "$RECOVERY_BOUND" "$MARK" 'P163-RECOVERY-COMPLETE'
echo "  INFO recovery complete on $A after ${trec}s"
ck "A completed B's recovery inside ${RECOVERY_BOUND}s (P163-RECOVERY-COMPLETE)" "$([ "$trec" != timeout ] && echo yes || echo no)" "yes"
TR=$(date +%s)

# the number becomes reusable after the recovery
value_now_into r2 "$A" $((REUSE_BOUND + 30)) "$OUT/a_arm2.txt" '^ARM_D2_REUSED=' "A's creates until reuse after the fence" "
    reused=none; t=0; n=0
    while [ \$t -lt $REUSE_BOUND ] && [ \$reused = none ]; do
        k=0
        while [ \$k -lt 5 ]; do
            k=\$((k+1)); n=\$((n+1)); g=\"$D/d2_\$n.dat\"
            dd if=/dev/zero bs=4096 count=4 2>/dev/null | tr '\\0' 'G' > \"\$g\"; sync -f \"\$g\"
            [ \"\$(stat -c %i \"\$g\")\" = \"$vino\" ] && reused=\$g
        done
        [ \$reused = none ] || break
        sleep 5; t=\$((t+5))
    done
    echo ARM_D2_REUSED=\$reused ARM_D2_T=\$t ARM_D2_N=\$n"
echo "  $r2"
r2v=$(echo "$r2" | grep -ao 'ARM_D2_REUSED=[^ ]*' | cut -d= -f2)
ck "ino reused after B's death and recovery (the mark was stripped or masked, the reaper freed the zombie)" "$([ -n "$r2v" ] && [ "$r2v" != none ] && echo yes || echo no)" "yes"
echo "  INFO reuse observed $(( $(date +%s) - TR ))s after the recovery completed, $(( $(date +%s) - TK ))s after the kill"

value_now_into gi "$A" 60 "$OUT/a_integrity.txt" '^GFILES=' "A's integrity sweep of the G files" "
    bad=0; n=0
    for g in $D/d1_*.dat $D/d2_*.dat; do
        n=\$((n+1))
        [ \"\$(md5sum < \"\$g\" | cut -d' ' -f1)\" = \"$g16md5\" ] || bad=\$((bad+1))
    done
    echo GFILES=\$n BAD=\$bad"
echo "  $gi"
ck "every G file on A intact" "$(echo "$gi" | grep -ao 'BAD=[0-9]*' | cut -d= -f2)" "0"

measure "$A" 25 "$OUT/a_dmesg.txt" '^DMESG_END$' "the kernel log on $A from the lap marker" "dmesg | sed -n \"/$MARK/,\\\$p\"; echo DMESG_END"
ckge "A's guard deferred on B's mark (P87-OPEN-DEFER ino=$vino)" "$(grep -ac "P87-OPEN-DEFER ino=$vino " "$OUT/a_dmesg.txt")" 1
ckge "A's reaper retried the zombie (P88-REAP-RETRY ino=$vino)" "$(grep -ac "P88-REAP-RETRY ino=$vino " "$OUT/a_dmesg.txt")" 1
echo "  INFO P977-OPEN-RESIDUE lines on A for the number: $(grep -ac "P977-OPEN-RESIDUE ino=$vino " "$OUT/a_dmesg.txt")"
ck "zero splats on A" "$(grep -aEc 'BUG:|Oops|WARNING:.*lockdep' "$OUT/a_dmesg.txt")" "0"
ck "no shutdown on A" "$(grep -ac 'Filesystem has been shut down\|force_shutdown' "$OUT/a_dmesg.txt")" "0"

# B comes back, re-preps, remounts and reads A's write
$VIRSH start "$B" >/dev/null 2>&1 || { echo "  FAIL virsh start $B"; fails=$((fails+1)); }
T0=$SECONDS; up=0
while [ $((SECONDS - T0)) -lt "$BOOT_BOUND" ]; do
  rs 10 "$B" "echo up" | grep -q up && { up=1; break; }
  sleep 5
done
echo "  INFO $B ssh $([ $up = 1 ] && echo "up after $((SECONDS - T0)) s" || echo "NOT up after $BOOT_BOUND s")"
ck "$B rebooted and answers ssh inside ${BOOT_BOUND}s" "$up" "1"
if [ $up = 1 ]; then
  measure "$B" 200 "$OUT/b_prep.txt" '^NODE_PREP_(OK|FAIL)' "the re-prep and remount of $B" "for try in 1 2 3 4 5 6; do mountpoint -q /src && break; mkdir -p /src; timeout 12 mount -t nfs 192.168.1.4:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null; sleep 4; done; mountpoint -q /src || echo SRC_NOT_MOUNTED; MXFS_DEV=$DEV timeout 150 /src/mxfs/tests/setup/prep_node.sh tcp 2>&1 | tail -3"
  prep_require "$OUT/b_prep.txt" "the node preparation on $B"
  ck "$B re-prepped and mounted (NODE_PREP_OK)" "$(grep -ac NODE_PREP_OK "$OUT/b_prep.txt")" "1"
  rs 20 "$A" "echo $LABEL-$$ > $D/after_fence.txt && sync -f $D/after_fence.txt && echo w" | grep -q w || { echo "  FAIL write on $A"; fails=$((fails+1)); }
  measure "$B" 20 "$OUT/b_read.txt" '^READ_RC=[0-9]+$' "B's read of A's post-fence write" "cat $D/after_fence.txt; printf '\nREAD_RC=%s\n' \$?"
  ck "$B reads $A's post-fence write" "$(grep -av '^READ_RC=' "$OUT/b_read.txt" | tr -dc 'A-Za-z0-9_-')" "$LABEL-$$"
fi

rs 40 "$A" "rm -rf '$D'" >/dev/null
if [ "$fails" -eq 0 ]; then echo "VERDICT PASS: d0977 opener death"; echo "RESULT: PASS label=$LABEL evidence=$OUT"; exit 0; fi
echo "VERDICT FAIL: $fails assertion(s)"; echo "RESULT: FAIL label=$LABEL fails=$fails evidence=$OUT"; exit 1
