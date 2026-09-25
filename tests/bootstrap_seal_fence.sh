#!/bin/bash
# bootstrap_seal_fence.sh — D-WHOLE-CLUSTER-CRASH-RESTART-REQUIRES-OPERATOR-437
# item 5b (docs/whole-cluster-restart.md §6.1-6.4): the whole-cluster bootstrap
# OWNER path up to the end of phase 3, measured directly.
#
# Claim under test.  After ALL N nodes crash, the first node back must NOT
# claim an ACTIVE slot: its survivor scan sees N member records frozen for a
# full dead window, it CLAIMs the bootstrap record under a provisional
# identity, re-scans, classifies every registered key, writes the manifest,
# SEALs, goes RECOVERING, and fences EVERY manifest entry through the
# certified pipeline (intent → PREEMPT AND ABORT → certificate → execution
# lease).  Phase 4 (replay) is build item 5d; this build refuses the mount
# after phase 3 with the record left RECOVERING (P-BOOT-REPLAY-UNBUILT).
#
# Shape (fleet prepped 32/caw by the caller), same crash choreography as
# no_survivor_crash_replay.sh:
#   1. srcgate: every node runs the tree build.
#   2. every node writes + fsyncs a private file (the slices are dirty).
#   3. virsh destroy ALL N nodes.
#   4. start ONE node (REMOUNTER); insmod the tree build; mount.
#   5. assert on the remounter's dmesg: P-BOOT-SCAN-FROZEN x2 with N victims,
#      P-BOOT-CLAIMED, P-BOOT-SEALED entries=N victims=N bits registrants=0,
#      N x P238-RECOV-LEASE (certified lease per victim), P-BOOT-PHASE3-
#      COMPLETE certs=N, P-BOOT-REPLAY-UNBUILT, mount FAILED, no
#      'claimed heartbeat slot', no BUG/Oops; the LU holds 0 keys once the
#      refused mount unregistered its own (every victim key preempted);
#      chk_mxfs shows the record RECOVERING with victims=N bits.
#   6. start the other N-1 VMs (the caller must prep_cluster afterwards —
#      mkfs rewrites the record IDLE).
#
# the budget rule (derived, first measurement): payload ~5 s; destroy ~10 s; boot to
# ssh 40-120 s; LUN/NFS <= 60 s; insmod ~5 s; TWO survivor scans of one dead
# window each (62 s + 2.5 s poll) = 129 s; N sequential fence episodes
# (intent CAW + P&A + certify + snapshot) measured ~2-3 s each on
# node_death_replay => 96 s; refusal unwind ~5 s.  Mount attempt bound 300 s.
# Total ~ 5+10+120+60+5+300+harvest 60+chk 120 => ~680 s.  Caller bound 720.
#
# Usage: tests/bootstrap_seal_fence.sh <label> [N=32] [remounter=test1]
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
MOUNT_BOUND=300
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_bootseal
mkdir -p "$OUT"
TREE_SV=$(modinfo mxfs.ko 2>/dev/null | awk '/srcversion/{print $2}')
KO_MD5=$(md5sum mxfs.ko | awk '{print $1}')
fails=0
pass() { echo "  PASS $1"; }
fail() { echo "  FAIL $1"; fails=$((fails+1)); }
info() { echo "  INFO $1"; }
sshq() { timeout "$1" "$SSH" "$2" "$3" 2>/dev/null | grep -av '^Unauthorized\|^Warning\|^If you'; }
echo "=== bootstrap_seal_fence label=$LABEL N=$N remounter=$RM out=$OUT $(date -u +%FT%TZ) ==="
T0=$(date +%s)

# 1. srcgate
for i in $(seq 1 "$N"); do
    sshq 20 "test$i" "cat /sys/module/mxfs/srcversion; mountpoint -q $MNT && echo MOUNTED" > "$OUT/test$i.gate" &
done; wait
for i in $(seq 1 "$N"); do
    if grep -q "^$TREE_SV" "$OUT/test$i.gate" && grep -q MOUNTED "$OUT/test$i.gate"; then :; else fail "srcgate test$i: $(tr '\n' ' ' < "$OUT/test$i.gate")"; fi
done
[ $fails -eq 0 ] && pass "srcgate: $N nodes run $TREE_SV and are mounted"
[ $fails -eq 0 ] || { echo "=== bootstrap_seal_fence $LABEL: fails=$fails (setup) out=$OUT ==="; exit 1; }

# 2. dirty every slice
for i in $(seq 1 "$N"); do
    sshq 30 "test$i" "d=$MNT/bootseal_$LABEL; mkdir -p \$d; f=\$d/test$i.bin; head -c 65536 /dev/urandom > \$f && sync -f \$f && md5sum \$f | awk '{print \$1}'" > "$OUT/test$i.md5" &
done; wait
np=0
for i in $(seq 1 "$N"); do
    m=$(tr -d '[:space:]' < "$OUT/test$i.md5")
    case "$m" in [0-9a-f]??????????????????????????????? ) np=$((np+1));; *) fail "payload test$i: md5='$m'";; esac
done
[ "$np" -eq "$N" ] && pass "payload written + fsynced on $N/$N nodes" || fail "payload on $np/$N nodes only"
[ $fails -eq 0 ] || { echo "=== bootstrap_seal_fence $LABEL: fails=$fails (payload) out=$OUT ==="; exit 1; }

# 3. whole-cluster crash
TK=$(date +%s)
for i in $(seq 1 "$N"); do ( $VIRSH destroy "test$i" >/dev/null 2>&1; echo "test$i rc=$?" ) >> "$OUT/destroy.txt" & done; wait
info "destroyed $N VMs in $(( $(date +%s) - TK ))s: $(grep -c 'rc=0' "$OUT/destroy.txt")/$N rc=0"

# 4. the remounter alone
$VIRSH start "$RM" >/dev/null 2>&1 || { fail "virsh start $RM"; echo "=== bootstrap_seal_fence $LABEL: fails=$fails out=$OUT ==="; exit 1; }
booted=0
for a in $(seq 1 24); do sleep 5; sshq 8 "$RM" "echo SSH_UP" | grep -q SSH_UP && { booted=1; break; }; done
[ $booted -eq 1 ] && info "$RM ssh up at +$(( $(date +%s) - TK ))s" || { fail "$RM never came back on ssh"; echo "=== bootstrap_seal_fence $LABEL: fails=$fails out=$OUT ==="; exit 1; }
sshq 90 "$RM" "mountpoint -q /src || { mkdir -p /src; mount -t nfs 192.168.1.4:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null; }
    iscsiadm -m discovery -t st -p 192.168.120.1:3260 >/dev/null 2>&1; iscsiadm -m discovery -t st -p 192.168.120.2:3260 >/dev/null 2>&1
    iscsiadm -m node --login >/dev/null 2>&1; iscsiadm -m session --rescan >/dev/null 2>&1; multipath >/dev/null 2>&1" >/dev/null
devup=0
for a in $(seq 1 20); do
    sshq 8 "$RM" "[ -e $DEV ] && mountpoint -q /src && echo DEV_UP" | grep -q DEV_UP && { devup=1; break; }
    sshq 20 "$RM" "mountpoint -q /src || { mkdir -p /src; timeout 12 mount -t nfs 192.168.1.4:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null; }; multipath >/dev/null 2>&1" >/dev/null
    sleep 3
done
[ $devup -eq 1 ] || { fail "$DEV / /src never came up on $RM"; echo "=== bootstrap_seal_fence $LABEL: fails=$fails out=$OUT ==="; exit 1; }
TM=$(date +%s)
sshq $((MOUNT_BOUND+60)) "$RM" "echo 3 > /proc/sys/vm/drop_caches; cp /src/mxfs/mxfs.ko /tmp/mxfs.ko; m=\$(md5sum /tmp/mxfs.ko | awk '{print \$1}'); [ \"\$m\" = '$KO_MD5' ] || { echo KO_MD5_MISMATCH \$m; exit 1; }
    modprobe libcrc32c 2>/dev/null || true; insmod /tmp/mxfs.ko dyndbg=+p; cat /sys/module/mxfs/srcversion
    echo BOOTSEAL-MOUNT-$LABEL > /dev/kmsg; mkdir -p $MNT; timeout $MOUNT_BOUND mount -t mxfs $DEV $MNT; echo MOUNT_RC=\$?
    sg_persist -i -k $DEV 2>&1 | tail -3" > "$OUT/remount.txt" 2>&1
MW=$(( $(date +%s) - TM ))
grep -q "^$TREE_SV" "$OUT/remount.txt" && pass "$RM loaded $TREE_SV" || fail "$RM module: $(tr '\n' ' ' < "$OUT/remount.txt")"
mrc=$(grep -ao 'MOUNT_RC=[0-9]*' "$OUT/remount.txt" | cut -d= -f2)
info "mount attempt rc=${mrc:-?} wall=${MW}s (+$(( $(date +%s) - TK ))s after the crash)"

# 5. the owner path, from the remounter's kernel log
sshq 40 "$RM" "dmesg | sed -n '/BOOTSEAL-MOUNT-$LABEL/,\$p'" > "$OUT/remounter_dmesg.txt"
grep -a 'P-BOOT-\|P238-RECOV-LEASE\|P238-FENCE\|P236-FENCEKIND\|P163-RECOVERY-PENDING\|claimed heartbeat slot\|P-PRKEY' "$OUT/remounter_dmesg.txt" | cut -c1-200 > "$OUT/timeline.txt"
[ "${mrc:-0}" -ne 0 ] && pass "mount REFUSED (rc=$mrc) — no ACTIVE admission over an unreplayed sealed set" || fail "mount SUCCEEDED (rc=$mrc): the bootstrap owner became ACTIVE without replay"
[ "$MW" -le "$MOUNT_BOUND" ] && pass "mount attempt wall ${MW}s <= ${MOUNT_BOUND}s" || fail "mount attempt wall ${MW}s > ${MOUNT_BOUND}s (budget)"
c=$(grep -ac 'P-BOOT-SCAN-FROZEN' "$OUT/remounter_dmesg.txt"); [ "$c" -eq 2 ] && pass "two frozen survivor scans (pre-claim + fresh post-claim)" || fail "P-BOOT-SCAN-FROZEN x$c (want 2)"
grep -aq "P-BOOT-SCAN-FROZEN.*TOTAL OUTAGE: $N victim" "$OUT/remounter_dmesg.txt" && pass "scan saw $N victims" || fail "scan victims: $(grep -ao 'TOTAL OUTAGE: [0-9]* victim' "$OUT/remounter_dmesg.txt" | tr '\n' ' ')"
grep -aq 'P-BOOT-CLAIMED' "$OUT/remounter_dmesg.txt" && pass "record CLAIMED under the provisional identity" || fail "no P-BOOT-CLAIMED"
grep -aq "P-BOOT-SEALED entries=$N .*registrants=0" "$OUT/remounter_dmesg.txt" && pass "manifest sealed: $N entries, 0 slotless registrants" || fail "seal: $(grep -ao 'P-BOOT-SEALED.*' "$OUT/remounter_dmesg.txt" | cut -c1-160)"
c=$(grep -ac 'P-BOOT-KEY-UNCLASSIFIED' "$OUT/remounter_dmesg.txt"); [ "$c" -eq 0 ] && pass "every key classified" || fail "P-BOOT-KEY-UNCLASSIFIED x$c"
c=$(grep -ac 'P-BOOT-VICTIM-FROZEN' "$OUT/remounter_dmesg.txt"); [ "$c" -eq "$N" ] && pass "$N victim identities frozen from the manifest" || fail "P-BOOT-VICTIM-FROZEN x$c (want $N)"
c=$(grep -ac 'P238-RECOV-LEASE' "$OUT/remounter_dmesg.txt"); [ "$c" -eq "$N" ] && pass "$N certified execution leases (one per victim)" || fail "P238-RECOV-LEASE x$c (want $N)"
# The remounter's OWN previous boot is one of the victims: its new boot
# replaced that key by self-succession (REGISTER rk=old), so that one slot
# certifies SELF_SUCCESSION_DONE (class-4 rule), every other one by our P&A.
cpa=$(grep -ac 'P236-FENCEKIND.*kind=PREEMPT_ABORT_DONE' "$OUT/remounter_dmesg.txt"); css=$(grep -ac 'P236-FENCEKIND.*kind=SELF_SUCCESSION_DONE' "$OUT/remounter_dmesg.txt")
[ $((cpa+css)) -eq "$N" ] && [ "$cpa" -ge $((N-1)) ] && pass "$N exclusion certificates: $cpa PREEMPT_ABORT_DONE + $css SELF_SUCCESSION_DONE (own previous boot)" || fail "certificates: PREEMPT_ABORT_DONE x$cpa SELF_SUCCESSION_DONE x$css (want $N total, >= $((N-1)) P&A): $(grep -ao 'P236-FENCEKIND.*kind=[A-Z_]*' "$OUT/remounter_dmesg.txt" | awk '{print $NF}' | sort | uniq -c | tr '\n' ' ')"
grep -aq "P-BOOT-PHASE3-COMPLETE certs=$N" "$OUT/remounter_dmesg.txt" && pass "phase 3 complete with $N certificates" || fail "phase 3: $(grep -ao 'P-BOOT-PHASE3-[A-Z]*.*' "$OUT/remounter_dmesg.txt" | cut -c1-120)"
grep -aq 'P-BOOT-REPLAY-UNBUILT' "$OUT/remounter_dmesg.txt" && pass "refusal is the designed phase-4 gate (P-BOOT-REPLAY-UNBUILT)" || fail "no P-BOOT-REPLAY-UNBUILT: $(grep -ao 'P-BOOT-MOUNT-REFUSED.*\|P-BOOT-[A-Z-]*FAILED.*\|P-BOOT-ABORTED.*' "$OUT/remounter_dmesg.txt" | head -2 | cut -c1-140 | tr '\n' ' ')"
c=$(grep -ac 'claimed heartbeat slot' "$OUT/remounter_dmesg.txt"); [ "$c" -eq 0 ] && pass "no ACTIVE slot claimed by the owner" || fail "'claimed heartbeat slot' x$c"
c=$(grep -ac 'P-BOOT-HB-LOST' "$OUT/remounter_dmesg.txt"); [ "$c" -eq 0 ] && pass "owner heartbeat never lost the record" || fail "P-BOOT-HB-LOST x$c"
for pat in 'BUG:' 'Oops' 'P-BOOT-CAS-LOST' 'P-BOOT-FENCE-UNPROVEN'; do
    c=$(grep -ac "$pat" "$OUT/remounter_dmesg.txt"); [ "$c" -eq 0 ] && pass "no $pat" || fail "$pat x$c on $RM"
done
# DISTINCT keys: sg_persist lists one entry per I_T nexus, and the LUN has
# two multipath paths, so one retained key prints twice (chain 26c s441c).
nk=$(grep -ao '^ *0x[0-9a-f]*' "$OUT/remount.txt" | tr -d ' ' | sort -u | grep -c .)
# Design-consult review SS-1 (sess441): the owner's key is EVIDENCE the record names —
# the refused mount must RETAIN it (P302), never unregister it.
case "${nk:-x}" in
    1) pass "LU holds exactly 1 key after the refusal: every victim key preempted, owner key retained";;
    0) fail "LU holds 0 keys after the refusal: the owner key was unregistered (evidence erased, review SS-1)";;
    *) fail "LU holds '${nk:-?}' keys after the refusal: $(grep -a 'reservation key\|0x' "$OUT/remount.txt" | tail -4 | tr '\n' ' ')";;
esac
grep -aq 'P302-PR-KEY-RETAINED-ON-REFUSAL' "$OUT/remounter_dmesg.txt" && pass "owner key retention logged (P302)" || fail "no P302-PR-KEY-RETAINED-ON-REFUSAL on the owner"
timeout 240 tools/chk_mxfs -v "$IMG" > "$OUT/chk.txt" 2>&1; chkrc=$?
grep -a 'bootstrap:' "$OUT/chk.txt" | head -3
grep -aq 'bootstrap: RECOVERING .*victims=0x' "$OUT/chk.txt" && pass "chk_mxfs: record RECOVERING (rc=$chkrc)" || fail "chk_mxfs bootstrap: $(grep -ao 'bootstrap: .*' "$OUT/chk.txt" | head -1 | cut -c1-120) rc=$chkrc"
vb=$(grep -ao 'bootstrap: RECOVERING .*victims=0x[0-9a-f]*' "$OUT/chk.txt" | grep -ao 'victims=0x[0-9a-f]*' | cut -d= -f2)
if [ -n "$vb" ]; then
    nb=$(python3 -c "print(bin(int('$vb',16)).count('1'))")
    [ "$nb" -eq "$N" ] && pass "sealed victim bitmap has $N bits" || fail "sealed victim bitmap $vb has $nb bits (want $N)"
fi
c=$(grep -ac 'RECOVERY_GUARD.*stage=' "$OUT/chk.txt"); info "chk_mxfs: $c guard/descriptor lines"

# 6. restore the fleet's VMs (caller preps; mkfs resets the record)
for i in $(seq 1 "$N"); do [ "test$i" = "$RM" ] || $VIRSH start "test$i" >/dev/null 2>&1 & done; wait
info "wall=$(( $(date +%s) - T0 ))s; other VMs started — caller must prep_cluster"
echo "=== bootstrap_seal_fence $LABEL: fails=$fails out=$OUT $(date -u +%FT%TZ) ==="
[ $fails -eq 0 ]
