#!/bin/bash
# no_survivor_crash_replay.sh — D-OWN-CRASH-RECLAIM-PATH-UNREACHABLE item 2:
# the NO-SURVIVOR whole-cluster crash, measured directly.
#
# Claim under test.  The pass-1 "own-stamp reclaim" can never match (node_id is
# random per mount), so every mount is a pass-2 fresh claim and a node's OWN
# previous slice is never replayed by itself as "own crash recovery".  The
# sess180 ruling made the SURVIVOR engine the one replayer (claim-triggered or
# monitor-triggered); the sess182 landing makes a fresh claim skip GUARD /
# WITHDRAWN records and claim only non-ACTIVE slots.  So after ALL nodes crash
# with fsync-acknowledged payload outstanding in their journal slices, the
# first node back must: claim an EMPTY slot (its old record is stale-ACTIVE),
# then, as the only survivor, expire + fence + foreign-replay all N stale
# slices — its own previous incarnation's included — before the payload is
# visible.  Nothing has ever measured that path; this harness does.
#
# Shape (fleet prepped 32/caw by the caller):
#   1. srcgate: every node runs the tree build.
#   2. Every node writes a private 64 KiB random file + fsync; md5 recorded
#      on the writer.  (Metadata for the file lives only in that node's slice.)
#   3. virsh destroy ALL N nodes in parallel (whole-cluster crash).
#   4. Start ONE node (REMOUNTER); wait for ssh, /src, the LUN; copy + md5-check
#      the tree's mxfs.ko; insmod; ARM target_cache_protected=1 +
#      foreign_replay_token_enforce=1 BEFORE mount (unarmed = the designed
#      blanket refusal, ledger #1); mount.
#   5. Wait for N 'foreign replay of slot ... complete' lines on the remounter
#      (bounded), then assert: every payload file present with the recorded
#      md5; 0 'failed' replays; no FSWIDE-HALT / QUAR-IMPORT / POLICY-REFUSED /
#      P53 / P-AGIFC-MISMATCH; clean umount; chk_mxfs -v non-SB errors 0.
#   6. Start the other N-1 VMs (the caller must prep_cluster afterwards).
#
# the budget rule (derived, FIRST MEASUREMENT — record the wall): payload 32 x 64 KiB
# private files ~5 s; destroy fan-out ~10 s; VM boot to ssh 40-120 s (24 x 5 s
# poll as closure_hb_slot_reuse.sh); LUN/NFS assembly <= 60 s; insmod+mount
# ~10 s; HB expiry 62 s (dead window) after the monitor starts; then N
# sequential fence+replay episodes — a node_death_replay lap replays 4 slices
# in ~111 s incl. prep, so budget 8 s/slice => 256 s.  RECOV_WAIT=420 s.
# Total ~ 5 + 10 + 120 + 60 + 10 + 420 + harvest 60 + chk 120 => ~800 s.
# Caller bound 840 s.
#
# Usage: tests/no_survivor_crash_replay.sh <label> [N=32] [remounter=test1]
set -u
LABEL=${1:?label}
N=${2:-32}
RM=${3:-test1}
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
P=/sys/module/mxfs/parameters
RECOV_WAIT=420
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_nosurv
mkdir -p "$OUT"
TREE_SV=$(modinfo mxfs.ko 2>/dev/null | awk '/srcversion/{print $2}')
KO_MD5=$(md5sum mxfs.ko | awk '{print $1}')
fails=0
pass() { echo "  PASS $1"; }
fail() { echo "  FAIL $1"; fails=$((fails+1)); }
info() { echo "  INFO $1"; }
sshq() { timeout "$1" "$SSH" "$2" "$3" 2>/dev/null | grep -av '^Unauthorized\|^Warning\|^If you'; }
echo "=== no_survivor_crash_replay label=$LABEL N=$N remounter=$RM out=$OUT $(date -u +%FT%TZ) ==="
T0=$(date +%s)

# 1. srcgate (parallel, per-node evidence)
for i in $(seq 1 "$N"); do
    sshq 20 "test$i" "cat /sys/module/mxfs/srcversion; mountpoint -q $MNT && echo MOUNTED" > "$OUT/test$i.gate" &
done; wait
for i in $(seq 1 "$N"); do
    if grep -q "^$TREE_SV" "$OUT/test$i.gate" && grep -q MOUNTED "$OUT/test$i.gate"; then :; else fail "srcgate test$i: $(tr '\n' ' ' < "$OUT/test$i.gate")"; fi
done
[ $fails -eq 0 ] && pass "srcgate: $N nodes run $TREE_SV and are mounted"
[ $fails -eq 0 ] || { echo "=== no_survivor_crash_replay $LABEL: fails=$fails (setup) out=$OUT ==="; exit 1; }

# 2. payload: one private fsync'd file per node, md5 recorded on the writer
for i in $(seq 1 "$N"); do
    sshq 30 "test$i" "d=$MNT/nosurv_$LABEL; mkdir -p \$d; f=\$d/test$i.bin; head -c 65536 /dev/urandom > \$f && sync -f \$f && md5sum \$f | awk '{print \$1}'" > "$OUT/test$i.md5" &
done; wait
np=0
for i in $(seq 1 "$N"); do
    m=$(tr -d '[:space:]' < "$OUT/test$i.md5")
    case "$m" in
        [0-9a-f]??????????????????????????????? ) np=$((np+1)) ;;
        *) fail "payload test$i: md5='$m'" ;;
    esac
done
[ "$np" -eq "$N" ] && pass "payload written + fsynced on $N/$N nodes" || fail "payload on $np/$N nodes only"
[ $fails -eq 0 ] || { echo "=== no_survivor_crash_replay $LABEL: fails=$fails (payload) out=$OUT ==="; exit 1; }

# 3. whole-cluster crash
TK=$(date +%s)
for i in $(seq 1 "$N"); do ( $VIRSH destroy "test$i" >/dev/null 2>&1; echo "test$i rc=$?" ) >> "$OUT/destroy.txt" & done; wait
info "destroyed $N VMs in $(( $(date +%s) - TK ))s at $(date -u +%T): $(grep -c 'rc=0' "$OUT/destroy.txt")/$N rc=0"

# 4. bring the remounter back alone
$VIRSH start "$RM" >/dev/null 2>&1 || { fail "virsh start $RM"; echo "=== no_survivor_crash_replay $LABEL: fails=$fails out=$OUT ==="; exit 1; }
booted=0
for a in $(seq 1 24); do sleep 5; sshq 8 "$RM" "echo SSH_UP" | grep -q SSH_UP && { booted=1; break; }; done
[ $booted -eq 1 ] && info "$RM ssh up at +$(( $(date +%s) - TK ))s after the crash" || { fail "$RM never came back on ssh"; echo "=== no_survivor_crash_replay $LABEL: fails=$fails out=$OUT ==="; exit 1; }
sshq 90 "$RM" "mountpoint -q /src || { mkdir -p /src; mount -t nfs 192.168.120.1:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null; }
    iscsiadm -m discovery -t st -p 192.168.120.1:3260 >/dev/null 2>&1; iscsiadm -m discovery -t st -p 192.168.120.2:3260 >/dev/null 2>&1
    iscsiadm -m node --login >/dev/null 2>&1; iscsiadm -m session --rescan >/dev/null 2>&1; multipath >/dev/null 2>&1" >/dev/null
devup=0
for a in $(seq 1 20); do
    sshq 8 "$RM" "[ -e $DEV ] && mountpoint -q /src && echo DEV_UP" | grep -q DEV_UP && { devup=1; break; }
    sshq 20 "$RM" "mountpoint -q /src || { mkdir -p /src; timeout 12 mount -t nfs 192.168.120.1:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null; }; multipath >/dev/null 2>&1" >/dev/null
    sleep 3
done
[ $devup -eq 1 ] || { fail "$DEV / /src never came up on $RM"; echo "=== no_survivor_crash_replay $LABEL: fails=$fails out=$OUT ==="; exit 1; }
# insmod the TREE build (md5-checked local copy), ARM enforcement, mount.
TM=$(date +%s)
# sess446: since item 5 (0.46.0+) the FIRST node back runs the whole-cluster
# BOOTSTRAP inside its mount (scan 64 s + claim + seal + 32 fences + K own-log
# replay + 31 foreign replays): measured 203 s on 0.53.0 (chain 43), 545 s on
# 0.51.0.  The original 120 s ssh bound killed the session mid-mount (lap 1,
# tests/evidence/20260829T115402Z_nosurv).  The mount now runs detached and is
# polled to MOUNT_BOUND (derived: 203 s measured + 60 s slack = 270; bootstrap
# harness bound 540 kept as the hard ceiling).
MOUNT_BOUND=${MOUNT_BOUND:-540}
sshq 120 "$RM" "set -e; echo 3 > /proc/sys/vm/drop_caches; cp /src/mxfs/mxfs.ko /tmp/mxfs.ko; m=\$(md5sum /tmp/mxfs.ko | awk '{print \$1}'); [ \"\$m\" = '$KO_MD5' ] || { echo KO_MD5_MISMATCH \$m; exit 1; }
    modprobe libcrc32c 2>/dev/null || true; insmod /tmp/mxfs.ko dyndbg=+p; cat /sys/module/mxfs/srcversion
    echo 1 > $P/target_cache_protected; echo 1 > $P/foreign_replay_token_enforce; echo armed=\$(cat $P/target_cache_protected)\$(cat $P/foreign_replay_token_enforce)
    echo NOSURV-MOUNT-$LABEL > /dev/kmsg; mkdir -p $MNT; rm -f /tmp/nosurv_mount_rc; (setsid nohup sh -c 'timeout $MOUNT_BOUND mount -t mxfs $DEV $MNT; echo MOUNT_RC=\$? > /tmp/nosurv_mount_rc' >/dev/null 2>&1 &); echo LAUNCHED" > "$OUT/remount.txt" 2>&1
for a in $(seq 1 $((MOUNT_BOUND/5 + 2))); do
    sleep 5
    r=$(sshq 15 "$RM" "cat /tmp/nosurv_mount_rc 2>/dev/null")
    [ -n "$r" ] && { echo "$r" >> "$OUT/remount.txt"; break; }
done
grep -q 'MOUNT_RC=0' "$OUT/remount.txt" && echo MOUNT_OK >> "$OUT/remount.txt"
grep -q "^$TREE_SV" "$OUT/remount.txt" && pass "$RM loaded $TREE_SV" || fail "$RM module: $(tr '\n' ' ' < "$OUT/remount.txt")"
grep -q 'armed=11' "$OUT/remount.txt" && pass "$RM armed (tcp=1, enforce=1) before mount" || fail "$RM not armed: $(grep armed "$OUT/remount.txt")"
grep -q MOUNT_OK "$OUT/remount.txt" && info "$RM mounted in $(( $(date +%s) - TM ))s (+$(( $(date +%s) - TK ))s after the crash)" || { fail "$RM mount: $(tail -3 "$OUT/remount.txt" | tr '\n' ' ')"; echo "=== no_survivor_crash_replay $LABEL: fails=$fails out=$OUT ==="; exit 1; }

# 5. wait for the N stale slices to be replayed by the lone survivor
TR=$(date +%s); frc=0; frf=0
while [ $(( $(date +%s) - TR )) -lt $RECOV_WAIT ]; do
    sleep 10
    # sess446: the rebooter's OWN predecessor slice K is replayed as its own
    # log under the bootstrap term (P-BOOT-ADOPTED-LOG), not as a 'foreign
    # replay of slot' — it counts as the N-th replay.
    c=$(sshq 15 "$RM" "dmesg | grep -ac 'foreign replay of slot .* complete'"); f=$(sshq 15 "$RM" "dmesg | grep -ac 'foreign replay of slot .* failed'"); k=$(sshq 15 "$RM" "dmesg | grep -ac 'P-BOOT-ADOPTED-LOG'")
    frc=$(( ${c:-0} + ( ${k:-0} > 0 ? 1 : 0 ) )); frf=${f:-0}
    [ $((frc+frf)) -ge "$N" ] && break
done
info "replays complete=$frc failed=$frf after $(( $(date +%s) - TR ))s (+$(( $(date +%s) - TK ))s after the crash)"
sshq 40 "$RM" "dmesg | sed -n '/NOSURV-MOUNT-$LABEL/,\$p'" > "$OUT/remounter_dmesg.txt"
# per-slice timeline for the budget rule record
grep -a 'foreign replay of slot\|P163-RECOVERY-COMPLETE\|heartbeat expired\|P238-RECOV-LEASE\|claimed heartbeat slot\|P-BOOT-\|SELF_SUCCESSION\|P236-FENCEKIND' "$OUT/remounter_dmesg.txt" | cut -c1-160 > "$OUT/timeline.txt"
info "own predecessor: $(grep -ao 'P236-FENCEKIND.*SELF_SUCCESSION_DONE.*' "$OUT/timeline.txt" | head -1 | cut -c1-120) / $(grep -ao 'P-BOOT-ADOPTED-LOG.*' "$OUT/timeline.txt" | head -1 | cut -c1-80)"
grep -aq 'SELF_SUCCESSION_DONE' "$OUT/remounter_dmesg.txt" && grep -aq 'P-BOOT-ADOPTED-LOG' "$OUT/remounter_dmesg.txt" && pass "own previous incarnation fenced by SELF_SUCCESSION_DONE and its slice replayed as K" || fail "own predecessor slice not replayed under a SELF_SUCCESSION_DONE certificate"
info "claim: $(grep -ao 'claimed heartbeat slot.*' "$OUT/timeline.txt" | head -1)"
[ "$frc" -ge "$N" ] && pass "all $N stale slices replayed complete" || fail "only $frc/$N slices replayed complete (failed=$frf) within ${RECOV_WAIT}s"
[ "$frf" -eq 0 ] && pass "0 failed replays" || fail "$frf failed replays"
for pat in 'P-RMAN-FSWIDE-HALT' 'P240-QUAR-IMPORT' 'POLICY-REFUSED' 'P53' 'P-AGIFC-MISMATCH' 'P-IUNL-INSFAIL' 'BUG:' 'Oops'; do
    c=$(grep -ac "$pat" "$OUT/remounter_dmesg.txt"); [ "$c" -eq 0 ] && pass "no $pat" || fail "$pat x$c on $RM"
done
# payload
ok=0
for i in $(seq 1 "$N"); do
    want=$(tr -d '[:space:]' < "$OUT/test$i.md5")
    got=$(sshq 20 "$RM" "md5sum $MNT/nosurv_$LABEL/test$i.bin 2>/dev/null | awk '{print \$1}'" | tr -d '[:space:]')
    if [ "$got" = "$want" ]; then ok=$((ok+1)); else echo "    payload test$i.bin want=$want got='${got:-MISSING}'" >> "$OUT/payload_mismatch.txt"; fi
done
[ "$ok" -eq "$N" ] && pass "payload: $N/$N fsync-acknowledged files present with the recorded md5" || { fail "payload: $ok/$N files intact (see $OUT/payload_mismatch.txt)"; head -5 "$OUT/payload_mismatch.txt"; }
# clean umount + chk
u=$(sshq 90 "$RM" "timeout 80 umount $MNT && echo UMOUNT_OK")
echo "$u" | grep -q UMOUNT_OK && pass "$RM clean umount" || fail "$RM umount: $u"
timeout 240 tools/chk_mxfs -v "$IMG" > "$OUT/chk.txt" 2>&1; chkrc=$?
chk_err=$(grep -c 'ERROR' "$OUT/chk.txt"); chk_sb=$(grep -c 'ERROR.*\(icount\|ifree\)' "$OUT/chk.txt")	# same oracle split as tmpfile_churn_kill.sh
[ $(( chk_err - chk_sb )) -eq 0 ] && pass "chk_mxfs non-SB errors 0 (rc=$chkrc)" || fail "chk_mxfs non-SB errors=$(( chk_err - chk_sb )) rc=$chkrc (see $OUT/chk.txt)"

# 6. restore the fleet's VMs (caller preps)
for i in $(seq 1 "$N"); do [ "test$i" = "$RM" ] || $VIRSH start "test$i" >/dev/null 2>&1 & done; wait
info "wall=$(( $(date +%s) - T0 ))s; other VMs started — caller must prep_cluster"
echo "=== no_survivor_crash_replay $LABEL: fails=$fails out=$OUT $(date -u +%FT%TZ) ==="
[ $fails -eq 0 ]
