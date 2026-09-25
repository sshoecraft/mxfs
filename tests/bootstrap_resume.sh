#!/bin/bash
# bootstrap_resume.sh — D-WHOLE-CLUSTER-CRASH-RESTART-REQUIRES-OPERATOR-437
# item 5e, the SAME-BOOT RESUME (docs/whole-cluster-restart.md §6.7; sess442
# Design-consult review S2/S4): the bootstrap owner's mount fails at a chosen durable
# point (mxfs.bootstrap_inject, TEST ONLY, one-shot) and the NEXT mount of
# the same kernel boot must RESUME the term — same term, same provisional
# identity, no new claim, no fence — and finish it: 31 foreign replays, K as
# own log, RECOVERY_COMPLETE, payload intact, peers admitted, clean umount,
# chk clean.
#
# Fail points (the durable shape the resume must handle):
#   1  after phase 3: record RECOVERING, escrow NONE       -> resume adopts K fresh
#   2  after escrow PREPARED, before the claim CAW: K guard -> re-prepare + claim
#   3  after K claimed (K_CLAIMED, our ACTIVE|PENDING record) -> re-take K
#
# the budget rule (derived): crash 10 s; boot <= 120 s; attempt 1 = two dead-window
# scans + 32 fences ~150 s (bound 300); attempt 2 = no scan: phase-3 re-lease
# + K own replay + 31 foreign replays at ~5 s/slice + completion ~ 200-300 s
# (bound 420); peers 300; payload/umount/chk ~270.  Total ~1100 s, caller
# bound 1260 s.
#
# Usage: tests/bootstrap_resume.sh <label> <point 1|2|3> [N=32] [remounter=test1]
set -u
LABEL=${1:?label}
POINT=${2:?fail point 1|2|3}
N=${3:-32}
RM=${4:-test1}
cd "$(dirname "$0")/.." || exit 2
SSH=tools/mxfs_sshpass.sh
VIRSH="sudo virsh -c qemu:///system"
MNT=${MXFS_MNT:-/mnt/shared}
# the device under test by identity, not by path: the LUN this rig declares
# (data/rigs.json), verified by its WWID on the node, and the node's live mxfs
# mount when it has one; MXFS_DEV names a candidate that must be that LUN.
# mxfs_dev_resolve (tests/lib/rig.sh) ABORTs on anything else, never defaults
. "$(dirname "$0")/lib/rig.sh"
mxfs_dev_resolve "$RM"; DEV=$MXFS_DEV_RESOLVED
IMG=$(tools/mxfs_host_image.sh) || { echo "$IMG"; exit 2; }
ATTEMPT1_BOUND=300
ATTEMPT2_BOUND=420
PEER_BOUND=300
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_bootresume${POINT}
mkdir -p "$OUT"
TREE_SV=$(modinfo mxfs.ko 2>/dev/null | awk '/srcversion/{print $2}')
KO_MD5=$(md5sum mxfs.ko | awk '{print $1}')
fails=0
pass() { echo "  PASS $1"; }
fail() { echo "  FAIL $1"; fails=$((fails+1)); }
info() { echo "  INFO $1"; }
sshq() { timeout "$1" "$SSH" "$2" "$3" 2>/dev/null | grep -av '^Unauthorized\|^Warning\|^If you'; }
bringup() {
    local h=$1 a
    sshq 90 "$h" "mountpoint -q /src || { mkdir -p /src; mount -t nfs 192.168.1.4:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null; }
        iscsiadm -m discovery -t st -p 192.168.120.1:3260 >/dev/null 2>&1; iscsiadm -m discovery -t st -p 192.168.120.2:3260 >/dev/null 2>&1
        iscsiadm -m node --login >/dev/null 2>&1; iscsiadm -m session --rescan >/dev/null 2>&1; multipath >/dev/null 2>&1" >/dev/null
    for a in $(seq 1 20); do
        sshq 8 "$h" "[ -e $DEV ] && mountpoint -q /src && echo DEV_UP" | grep -q DEV_UP && return 0
        sshq 20 "$h" "mountpoint -q /src || { mkdir -p /src; timeout 12 mount -t nfs 192.168.1.4:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null; }; multipath >/dev/null 2>&1" >/dev/null
        sleep 3
    done
    return 1
}
case "$POINT" in
    1) EXP_ESCROW=NONE;;
    2) EXP_ESCROW=PREPARED;;
    3) EXP_ESCROW=K_CLAIMED;;
    *) echo "bad point $POINT"; exit 2;;
esac
echo "=== bootstrap_resume label=$LABEL point=$POINT N=$N remounter=$RM out=$OUT $(date -u +%FT%TZ) ==="
T0=$(date +%s)

# 1. srcgate
for i in $(seq 1 "$N"); do
    sshq 20 "test$i" "cat /sys/module/mxfs/srcversion; mountpoint -q $MNT && echo MOUNTED" > "$OUT/test$i.gate" &
done; wait
for i in $(seq 1 "$N"); do
    if grep -q "^$TREE_SV" "$OUT/test$i.gate" && grep -q MOUNTED "$OUT/test$i.gate"; then :; else fail "srcgate test$i: $(tr '\n' ' ' < "$OUT/test$i.gate")"; fi
done
[ $fails -eq 0 ] && pass "srcgate: $N nodes run $TREE_SV and are mounted"
[ $fails -eq 0 ] || { echo "=== bootstrap_resume $LABEL: fails=$fails (setup) out=$OUT ==="; exit 1; }

# 2. payload
for i in $(seq 1 "$N"); do
    sshq 30 "test$i" "d=$MNT/bootres_$LABEL; mkdir -p \$d; f=\$d/test$i.bin; head -c 65536 /dev/urandom > \$f && sync -f \$f && md5sum \$f | awk '{print \$1}'" > "$OUT/test$i.md5" &
done; wait
np=0
for i in $(seq 1 "$N"); do
    m=$(tr -d '[:space:]' < "$OUT/test$i.md5")
    case "$m" in [0-9a-f]??????????????????????????????? ) np=$((np+1));; *) fail "payload test$i: md5='$m'";; esac
done
[ "$np" -eq "$N" ] && pass "payload written + fsynced on $N/$N nodes" || fail "payload on $np/$N nodes only"
[ $fails -eq 0 ] || { echo "=== bootstrap_resume $LABEL: fails=$fails (payload) out=$OUT ==="; exit 1; }

# 3. whole-cluster crash
TK=$(date +%s)
for i in $(seq 1 "$N"); do ( $VIRSH destroy "test$i" >/dev/null 2>&1; echo "test$i rc=$?" ) >> "$OUT/destroy.txt" & done; wait
info "destroyed $N VMs in $(( $(date +%s) - TK ))s: $(grep -c 'rc=0' "$OUT/destroy.txt")/$N rc=0"

# 4. the remounter alone: attempt 1 with the fail point armed
$VIRSH start "$RM" >/dev/null 2>&1 || { fail "virsh start $RM"; echo "=== bootstrap_resume $LABEL: fails=$fails out=$OUT ==="; exit 1; }
booted=0
for a in $(seq 1 24); do sleep 5; sshq 8 "$RM" "echo SSH_UP" | grep -q SSH_UP && { booted=1; break; }; done
[ $booted -eq 1 ] && info "$RM ssh up at +$(( $(date +%s) - TK ))s" || { fail "$RM never came back on ssh"; echo "=== bootstrap_resume $LABEL: fails=$fails out=$OUT ==="; exit 1; }
bringup "$RM" || { fail "$DEV / /src never came up on $RM"; echo "=== bootstrap_resume $LABEL: fails=$fails out=$OUT ==="; exit 1; }
TM=$(date +%s)
sshq $((ATTEMPT1_BOUND+60)) "$RM" "echo 3 > /proc/sys/vm/drop_caches; cp /src/mxfs/mxfs.ko /tmp/mxfs.ko; m=\$(md5sum /tmp/mxfs.ko | awk '{print \$1}'); [ \"\$m\" = '$KO_MD5' ] || { echo KO_MD5_MISMATCH \$m; exit 1; }
    modprobe libcrc32c 2>/dev/null || true; insmod /tmp/mxfs.ko dyndbg=+p; cat /sys/module/mxfs/srcversion
    echo 1 > /sys/module/mxfs/parameters/target_cache_protected; echo 1 > /sys/module/mxfs/parameters/foreign_replay_token_enforce
    echo $POINT > /sys/module/mxfs/parameters/bootstrap_inject
    echo BOOTRES-A1-$LABEL > /dev/kmsg; mkdir -p $MNT; timeout $ATTEMPT1_BOUND mount -t mxfs $DEV $MNT; echo MOUNT_RC=\$?; cat /sys/module/mxfs/parameters/bootstrap_inject" > "$OUT/attempt1.txt" 2>&1
W1=$(( $(date +%s) - TM ))
grep -q "^$TREE_SV" "$OUT/attempt1.txt" && pass "$RM loaded $TREE_SV" || fail "$RM module: $(tr '\n' ' ' < "$OUT/attempt1.txt")"
mrc=$(grep -ao 'MOUNT_RC=[0-9]*' "$OUT/attempt1.txt" | cut -d= -f2)
info "attempt 1 (inject=$POINT) rc=${mrc:-?} wall=${W1}s"
sshq 60 "$RM" "dmesg | sed -n '/BOOTRES-A1-$LABEL/,\$p'" > "$OUT/attempt1_dmesg.txt"
[ "${mrc:-0}" -ne 0 ] && pass "attempt 1 refused as injected (rc=$mrc)" || fail "attempt 1 mounted despite inject=$POINT"
[ "$W1" -le "$ATTEMPT1_BOUND" ] && pass "attempt 1 wall ${W1}s <= ${ATTEMPT1_BOUND}s" || fail "attempt 1 wall ${W1}s > ${ATTEMPT1_BOUND}s (budget)"
grep -aq "P-BOOT-INJECT point=$POINT" "$OUT/attempt1_dmesg.txt" && pass "fail point $POINT fired" || fail "no P-BOOT-INJECT point=$POINT"
tail -1 "$OUT/attempt1.txt" | grep -q '^0$' && pass "fail point self-cleared" || fail "bootstrap_inject still set: $(tail -1 "$OUT/attempt1.txt")"
grep -aq "P-BOOT-PHASE3-COMPLETE certs=$N" "$OUT/attempt1_dmesg.txt" && pass "attempt 1: phase 3 certified $N" || fail "attempt 1 phase 3: $(grep -ao 'P-BOOT-PHASE3-[A-Z]*.*' "$OUT/attempt1_dmesg.txt" | cut -c1-120)"
c=$(grep -ac 'released heartbeat slot' "$OUT/attempt1_dmesg.txt"); [ "$c" -eq 0 ] && pass "attempt 1: no clean slot release (K kept for the resume)" || fail "attempt 1 released a slot x$c"
c=$(grep -ac 'P-BOOT-REFUS' "$OUT/attempt1_dmesg.txt"); [ "$c" -eq 0 ] && pass "attempt 1: term not REFUSED by the unwind" || fail "attempt 1 refused the term: $(grep -ao 'P-BOOT-REFUS.*' "$OUT/attempt1_dmesg.txt" | head -1 | cut -c1-120)"
timeout 120 tools/chk_mxfs -v "$IMG" > "$OUT/chk_between.txt" 2>&1
grep -a 'bootstrap' "$OUT/chk_between.txt" | head -3
grep -aq 'bootstrap: RECOVERING' "$OUT/chk_between.txt" && pass "between attempts: record RECOVERING" || fail "between attempts: $(grep -ao 'bootstrap: .*' "$OUT/chk_between.txt" | head -1 | cut -c1-100)"
if [ "$EXP_ESCROW" = NONE ]; then
    grep -aq 'bootstrap escrow:' "$OUT/chk_between.txt" && fail "between attempts: unexpected escrow $(grep -ao 'bootstrap escrow: [A-Z_]*' "$OUT/chk_between.txt")" || pass "between attempts: escrow NONE"
else
    grep -aq "bootstrap escrow: $EXP_ESCROW" "$OUT/chk_between.txt" && pass "between attempts: escrow $EXP_ESCROW" || fail "between attempts escrow: $(grep -ao 'bootstrap escrow: .*' "$OUT/chk_between.txt" | head -1 | cut -c1-100)"
fi

# 5. attempt 2 — same boot, must RESUME
TM=$(date +%s)
sshq $((ATTEMPT2_BOUND+60)) "$RM" "echo BOOTRES-A2-$LABEL > /dev/kmsg; timeout $ATTEMPT2_BOUND mount -t mxfs $DEV $MNT; echo MOUNT_RC=\$?" > "$OUT/attempt2.txt" 2>&1
W2=$(( $(date +%s) - TM ))
mrc=$(grep -ao 'MOUNT_RC=[0-9]*' "$OUT/attempt2.txt" | cut -d= -f2)
info "attempt 2 (resume) rc=${mrc:-?} wall=${W2}s (+$(( $(date +%s) - TK ))s after the crash)"
sshq 60 "$RM" "dmesg | sed -n '/BOOTRES-A2-$LABEL/,\$p'" > "$OUT/attempt2_dmesg.txt"
D=$OUT/attempt2_dmesg.txt
grep -a 'P-BOOT-\|P238-RECOV-LEASE\|foreign replay of\|P163-RECOVERY-COMPLETE\|barrier complete\|P226-ICENSUS' "$D" | cut -c1-200 > "$OUT/timeline2.txt"
[ "${mrc:-1}" -eq 0 ] && pass "$RM MOUNTED on the resume (rc=0)" || fail "attempt 2 rc=${mrc:-?}: $(grep -ao 'P-BOOT-MOUNT-REFUSED.*\|P-BOOT-[A-Z-]*REFUSED.*\|P-BOOT-[A-Z-]*FAILED.*\|P-BOOT-RESUME-[A-Z-]*.*\|MXFS mount ABORTED.*' "$D" | head -2 | cut -c1-160 | tr '\n' ' ')"
[ "$W2" -le "$ATTEMPT2_BOUND" ] && pass "attempt 2 wall ${W2}s <= ${ATTEMPT2_BOUND}s" || fail "attempt 2 wall ${W2}s > ${ATTEMPT2_BOUND}s (budget)"
grep -aq 'P-BOOT-RESUME-CANDIDATE' "$D" && pass "peek: this boot's claim recognised" || fail "no P-BOOT-RESUME-CANDIDATE"
grep -aq 'P-BOOT-RESUME-IDENTITY' "$D" && pass "provisional identity adopted before REGISTER" || fail "no P-BOOT-RESUME-IDENTITY"
grep -aq 'P-BOOT-RESUMED term=1' "$D" && pass "term 1 RESUMED (no new claim)" || fail "no P-BOOT-RESUMED: $(grep -ao 'P-BOOT-RESUME.*' "$D" | head -1 | cut -c1-140)"
c=$(grep -ac 'P-BOOT-CLAIM term=\|P-BOOT-SCAN-FROZEN' "$D"); [ "$c" -eq 0 ] && pass "no scan, no new claim on the resume" || fail "resume scanned/claimed x$c"
c=$(grep -ac 'P305-PR-SAME-BOOT-DIRTY-PREDECESSOR' "$D"); [ "$c" -eq 0 ] && pass "own K not mistaken for a dirty predecessor" || fail "P305 same-boot dirty x$c"
case "$POINT" in
    3) grep -aq 'P-BOOT-RECLAIMED slot' "$D" && pass "K re-taken (P-BOOT-RECLAIMED)" || fail "no P-BOOT-RECLAIMED: $(grep -ao 'P-BOOT-RECLAIM.*\|P-BOOT-ADOPT.*' "$D" | head -1 | cut -c1-140)";;
    2) grep -aq 'P-BOOT-ESCROW-REPREPARE' "$D" && pass "PREPARED escrow re-prepared" || fail "no P-BOOT-ESCROW-REPREPARE"
       grep -aq 'P-BOOT-ADOPTED slot' "$D" && pass "K claimed on the resume" || fail "no P-BOOT-ADOPTED";;
    1) grep -aq 'P-BOOT-ESCROW-READBACK.*rc=0' "$D" && pass "escrow prepared on the resume" || fail "no escrow readback"
       grep -aq 'P-BOOT-ADOPTED slot' "$D" && pass "K claimed on the resume" || fail "no P-BOOT-ADOPTED";;
esac
grep -aq 'P-BOOT-ADOPT slot=' "$D" && pass "P-BOOT-ADOPT on the resume" || fail "no P-BOOT-ADOPT"
grep -aq 'P-BOOT-ADOPTED-LOG' "$D" && pass "K mounted as own log" || fail "no P-BOOT-ADOPTED-LOG"
c=$(grep -ac 'P-BOOT-ADOPTED-REFUSED' "$D"); [ "$c" -eq 0 ] && pass "K replay refused nothing" || fail "P-BOOT-ADOPTED-REFUSED x$c"
frc=$(grep -ac 'foreign replay of slot .* complete' "$D"); frf=$(grep -ac 'foreign replay of slot .* failed' "$D")
[ "$frc" -eq $((N-1)) ] && pass "$frc foreign slices replayed complete" || fail "foreign replays complete=$frc failed=$frf (want $((N-1)))"
[ "$frf" -eq 0 ] && pass "0 failed foreign replays" || fail "$frf failed foreign replays"
c=$(grep -ac 'P163-RECOVERY-COMPLETE' "$D"); [ "$c" -ge $((N-1)) ] && pass "$c slot recoveries published" || fail "P163-RECOVERY-COMPLETE x$c (want >= $((N-1)))"
c=$(grep -ac 'P-BOOT-COMPLETE-CASFAIL' "$D"); [ "$c" -eq 0 ] && pass "every completion bit landed" || fail "P-BOOT-COMPLETE-CASFAIL x$c"
grep -aq 'P-BOOT-RECOVERY-COMPLETE' "$D" && pass "RECOVERY_COMPLETE: admission open" || fail "no P-BOOT-RECOVERY-COMPLETE: $(grep -ao 'P-BOOT-FINISH.*\|P-BOOT-RECONCILE.*\|P-BOOT-TERMINAL.*' "$D" | head -2 | cut -c1-140 | tr '\n' ' ')"
for pat in 'BUG:' 'Oops' 'P-RMAN-FSWIDE-HALT' 'P240-QUAR-IMPORT' 'POLICY-REFUSED' 'P-BOOT-HB-LOST' 'P-BOOT-UNWIND'; do
    c=$(grep -ac "$pat" "$D"); [ "$c" -eq 0 ] && pass "no $pat" || fail "$pat x$c on $RM (attempt 2)"
done
ok=0
for i in $(seq 1 "$N"); do
    want=$(tr -d '[:space:]' < "$OUT/test$i.md5")
    got=$(sshq 20 "$RM" "md5sum $MNT/bootres_$LABEL/test$i.bin 2>/dev/null | awk '{print \$1}'" | tr -d '[:space:]')
    if [ "$got" = "$want" ]; then ok=$((ok+1)); else echo "    payload test$i.bin want=$want got='${got:-MISSING}'" >> "$OUT/payload_mismatch_owner.txt"; fi
done
[ "$ok" -eq "$N" ] && pass "payload on the owner: $N/$N intact" || { fail "payload on the owner: $ok/$N intact"; head -3 "$OUT/payload_mismatch_owner.txt"; }

# 6. admit the other N-1 nodes
TP=$(date +%s)
for i in $(seq 1 "$N"); do [ "test$i" = "$RM" ] || $VIRSH start "test$i" >/dev/null 2>&1 & done; wait
for i in $(seq 1 "$N"); do
    [ "test$i" = "$RM" ] && continue
    (
        up=0; for a in $(seq 1 24); do sleep 5; sshq 8 "test$i" "echo SSH_UP" | grep -q SSH_UP && { up=1; break; }; done
        [ $up -eq 1 ] || { echo "NO_SSH"; exit 1; }
        bringup "test$i" || { echo "NO_DEV"; exit 1; }
        sshq 120 "test$i" "cp /src/mxfs/mxfs.ko /tmp/mxfs.ko; m=\$(md5sum /tmp/mxfs.ko | awk '{print \$1}'); [ \"\$m\" = '$KO_MD5' ] || { echo KO_MD5_MISMATCH; exit 1; }
            modprobe libcrc32c 2>/dev/null || true; insmod /tmp/mxfs.ko dyndbg=+p; echo 1 > /sys/module/mxfs/parameters/target_cache_protected; echo 1 > /sys/module/mxfs/parameters/foreign_replay_token_enforce
            mkdir -p $MNT; timeout 120 mount -t mxfs $DEV $MNT && echo MOUNT_OK; dmesg | grep -a 'P-BOOT-STATE\|P-BOOT-ADMISSION' | tail -2"
    ) > "$OUT/test$i.peer" 2>&1 &
done; wait
pm=0
for i in $(seq 1 "$N"); do [ "test$i" = "$RM" ] && continue; grep -q MOUNT_OK "$OUT/test$i.peer" && pm=$((pm+1)) || echo "    test$i: $(tr '\n' ' ' < "$OUT/test$i.peer" | cut -c1-160)" >> "$OUT/peer_fail.txt"; done
PW=$(( $(date +%s) - TP ))
[ "$pm" -eq $((N-1)) ] && pass "$pm/$((N-1)) peers admitted after RECOVERY_COMPLETE (${PW}s)" || { fail "$pm/$((N-1)) peers mounted (${PW}s)"; head -3 "$OUT/peer_fail.txt"; }
[ "$PW" -le "$PEER_BOUND" ] && pass "peer admission wall ${PW}s <= ${PEER_BOUND}s" || fail "peer admission wall ${PW}s > ${PEER_BOUND}s (budget)"
PEER=test2; [ "$PEER" = "$RM" ] && PEER=test3
ok=0
for i in $(seq 1 "$N"); do
    want=$(tr -d '[:space:]' < "$OUT/test$i.md5")
    got=$(sshq 20 "$PEER" "md5sum $MNT/bootres_$LABEL/test$i.bin 2>/dev/null | awk '{print \$1}'" | tr -d '[:space:]')
    [ "$got" = "$want" ] && ok=$((ok+1)) || echo "    payload test$i.bin want=$want got='${got:-MISSING}'" >> "$OUT/payload_mismatch_peer.txt"
done
[ "$ok" -eq "$N" ] && pass "payload from peer $PEER: $N/$N" || { fail "payload from peer $PEER: $ok/$N"; head -3 "$OUT/payload_mismatch_peer.txt"; }

# 7. clean umount everywhere + chk
for i in $(seq 1 "$N"); do sshq 90 "test$i" "timeout 80 umount $MNT && echo UMOUNT_OK" > "$OUT/test$i.umount" 2>&1 & done; wait
um=0; for i in $(seq 1 "$N"); do grep -q UMOUNT_OK "$OUT/test$i.umount" && um=$((um+1)); done
[ "$um" -eq "$N" ] && pass "clean umount on $N/$N nodes" || fail "clean umount on $um/$N nodes"
timeout 240 tools/chk_mxfs -v "$IMG" > "$OUT/chk.txt" 2>&1; chkrc=$?
chk_err=$(grep -c 'ERROR' "$OUT/chk.txt"); chk_sb=$(grep -c 'ERROR.*\(icount\|ifree\)' "$OUT/chk.txt")
[ $(( chk_err - chk_sb )) -eq 0 ] && pass "chk_mxfs non-SB errors 0 (rc=$chkrc)" || fail "chk_mxfs non-SB errors=$(( chk_err - chk_sb )) rc=$chkrc (see $OUT/chk.txt)"
grep -a 'bootstrap' "$OUT/chk.txt" | head -3
grep -aq 'bootstrap: RECOVERY_COMPLETE' "$OUT/chk.txt" && pass "chk_mxfs: record RECOVERY_COMPLETE" || fail "chk_mxfs bootstrap: $(grep -ao 'bootstrap: .*' "$OUT/chk.txt" | head -1 | cut -c1-120)"
grep -aq 'bootstrap escrow: K_REPLAY_OK' "$OUT/chk.txt" && pass "chk_mxfs: escrow K_REPLAY_OK" || fail "chk_mxfs escrow: $(grep -ao 'bootstrap escrow: .*' "$OUT/chk.txt" | head -1 | cut -c1-120)"
info "wall=$(( $(date +%s) - T0 ))s"
echo "=== bootstrap_resume $LABEL point=$POINT: fails=$fails out=$OUT $(date -u +%FT%TZ) ==="
[ $fails -eq 0 ]
