#!/bin/bash
# bootstrap_full_restart.sh — D-WHOLE-CLUSTER-CRASH-RESTART-REQUIRES-OPERATOR-437
# item 5d end to end (docs/whole-cluster-restart.md §6, shape B): after ALL N
# nodes crash with fsync-acknowledged payload in every slice, the FIRST node
# back — with NO operator action — must bootstrap the cluster: survivor scan,
# CLAIM, seal, fence + certify every victim (5b, measured by
# bootstrap_seal_fence.sh), then ADOPT one certified victim slot K as its own
# log (FULL, authority-evaluated replay), replay the other N-1 slices through
# the mount-cohort barrier, reconcile READ KEYS, CAS RECOVERY_COMPLETE, and
# come up MOUNTED with every payload byte visible.  Only then may the other
# N-1 nodes be admitted — they boot, load the same build and mount without
# a mkfs in between.
#
# Shape (fleet prepped 32/caw by the caller):
#   1. srcgate; 2. payload (64 KiB fsync'd private file per node, md5 kept);
#   3. virsh destroy all N; 4. start ONE node (REMOUNTER), insmod the tree
#   build, mount (expect MOUNT_OK); 5. assert on its dmesg: P-BOOT-SEALED
#   entries=N, PHASE3-COMPLETE certs=N, P-BOOT-ADOPT slot=K, P-BOOT-ADOPTED-
#   LOG, no P-BOOT-ADOPTED-REFUSED, N-1 'foreign replay of slot .. complete',
#   0 failed, P-BOOT-RECOVERY-COMPLETE, no BUG/Oops/FSWIDE; payload N/N md5
#   on the remounter; 6. start the other N-1 VMs, insmod, mount — every one
#   MOUNT_OK (admission open, record RECOVERY_COMPLETE); payload N/N md5
#   from a PEER; 7. clean umount on all N; chk_mxfs -v non-SB errors 0 and
#   the record RECOVERY_COMPLETE.
#
# the budget rule (derived, FIRST MEASUREMENT): crash 10 s; boot 26-120 s; LUN/NFS
# <= 60 s; mount attempt = two dead-window scans 129 s (measured 133 s incl.
# 32 fences, chain 26c) + K own-log replay ~10 s + 31 foreign replays at the
# node_death_replay pace (~8 s/slice => 248 s) + completion ~10 s => ~400 s,
# bound 540 s.  Peers: 31 boots to ssh ~120 s + mounts (+2.5 s scan poll
# each) ~60 s, bound 300 s.  Payload 60 s; umount 90 s; chk 120 s.  Total
# ~1000 s; caller bound 1080 s.
#
# NEGATIVE ARM (sess444, D-ICREATE-REPLAY-REINIT-CLOBBERS-PEER-INODES-0510):
# MXFS_ICREATE_CORRUPT=<node> (not the remounter).  After the crash the
# payload file's dinode on that node's slice is corrupted ON THE IMAGE (magic
# zeroed, offline, via chk_mxfs --ino-offset) so the SYNCINIT chunk the
# victim's create logged no longer verifies.  Expected: the bootstrap REFUSES
# that slice (P-ICREATE-VERIFY-FAIL why=magic ino=<ino>, P-ICREATE-REFUSE,
# 'foreign replay of slot <s> ... failed', term REFUSED, mount rc != 0) and
# the corrupted sector is byte-identical afterwards — the replay wrote
# NOTHING (never a blind re-init).  Steps 6-7 are skipped; the sector is
# restored at the end (the next prep re-mkfs's anyway).
#
# Usage: tests/bootstrap_full_restart.sh <label> [N=32] [remounter=test1]
set -u
LABEL=${1:?label}
N=${2:-32}
RM=${3:-test1}
NEG=${MXFS_ICREATE_CORRUPT:-}
if [ -n "$NEG" ] && [ "$NEG" = "$RM" ]; then echo "MXFS_ICREATE_CORRUPT must not be the remounter"; exit 2; fi
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
# The host-side image is a rig declaration, and the shipping 2/tcp LUN is an
# appliance that has none — the platter is only readable from a node.  The
# sequential arm and the negative arm both read it directly, so they still
# require it; the concurrent arm reads the platter through the node-side
# checker instead and runs without one.
IMG=$(tools/mxfs_host_image.sh 2>/dev/null) || IMG=""
CONC=${MXFS_CONCURRENT:-}
if [ -z "$IMG" ] && [ -z "$CONC" ]; then tools/mxfs_host_image.sh; exit 2; fi
if [ -z "$IMG" ] && [ -n "$NEG" ]; then echo "the negative arm needs a host-side image of the LUN"; exit 2; fi
MODARGS=$(mxfs_rig_modargs)
# sess446: 0.53.0 measured 203/206 s (chains 43/41); the budget rule derivation in
# tests/criteria/TIMEOUT_BUDGETS.md "Whole-cluster restart" -> 300 s.
MOUNT_BOUND=${MOUNT_BOUND:-300}
PEER_BOUND=300
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_bootfull
mkdir -p "$OUT"
TREE_SV=$(modinfo mxfs.ko 2>/dev/null | awk '/srcversion/{print $2}')
KO_MD5=$(md5sum mxfs.ko | awk '{print $1}')
fails=0
pass() { echo "  PASS $1"; }
fail() { echo "  FAIL $1"; fails=$((fails+1)); }
info() { echo "  INFO $1"; }
sshq() { timeout "$1" "$SSH" "$2" "$3" 2>/dev/null | grep -av '^Unauthorized\|^Warning\|^If you'; }
bringup() {  # $1 node: NFS + iSCSI + multipath, wait for DEV
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
echo "=== bootstrap_full_restart label=$LABEL N=$N remounter=$RM out=$OUT $(date -u +%FT%TZ) ==="
T0=$(date +%s)

# 1. srcgate
for i in $(seq 1 "$N"); do
    sshq 20 "test$i" "cat /sys/module/mxfs/srcversion; mountpoint -q $MNT && echo MOUNTED" > "$OUT/test$i.gate" &
done; wait
for i in $(seq 1 "$N"); do
    if grep -q "^$TREE_SV" "$OUT/test$i.gate" && grep -q MOUNTED "$OUT/test$i.gate"; then :; else fail "srcgate test$i: $(tr '\n' ' ' < "$OUT/test$i.gate")"; fi
done
[ $fails -eq 0 ] && pass "srcgate: $N nodes run $TREE_SV and are mounted"
[ $fails -eq 0 ] || { echo "=== bootstrap_full_restart $LABEL: fails=$fails (setup) out=$OUT ==="; exit 1; }

# 2. payload
# Negative arm (sess444 chain 33 lesson): the corrupted chunk's ICREATE must
# be IN the victim's replayable log.  With one file + `sync -f` most slices
# carried no transaction at all (syncfs pushed the AIL, the tail moved) and
# the payload inode usually landed in a chunk carved during prep.  So in
# NEG mode every node carves a fresh chunk right before the crash: a private
# per-node dir, 200 small files + the payload, each fsync'd (never syncfs),
# with log covering held off (fs/mxfs/xfssyncd_centisecs to its maximum) —
# the last file's dinode is then in a chunk this lap ICREATE'd, and every
# other slice exercises the positive (verify-and-skip) arm too.
# sess446 (chain 41 lap 3, tests/evidence/20260829T110503Z_bootfull): with
# 200 fsync'd files + payload EVERY slice held exactly the node's LAST TWO
# transactions (P273-SHADOW-EVAL buf=8 txn=2 icreate=0/0/0 on 31/31, same on
# lap 2) — mxfs_destage_kick pushes the AIL on every create, so the tail
# follows the workload within ms and the chunk's ICREATE (carved ~55 creates
# before the payload) was long gone.  (/proc/sys/fs/mxfs/xfssyncd_centisecs
# does not exist on the nodes — xfs_sysctl.o is excluded from the build — so
# that write was a silent no-op; it would not have mattered.)  Lap 4: the
# ICREATE must be in the LAST create.  XFS hands out a chunk's inodes in
# ascending order and carves a new chunk only when the AG has no free inode,
# so the create that returns ino % 64 == 0 is the one whose transaction
# carried the ICREATE.  Create 4 KiB fsync'd files until that happens, make
# THAT file the node's payload, and stop: the slice's last two txns are the
# carve+create and the write.  Bound 400 creates (a chunk is 64); lap 3
# measured ~50 ms per fsync'd create (201 in ~10 s) => 400 in 20 s, ssh bound 60.
if [ -n "$NEG" ]; then
    for i in $(seq 1 "$N"); do
        sshq 60 "test$i" "d=$MNT/bootfull_$LABEL/test$i; mkdir -p \$d; b=; for k in \$(seq 1 400); do f=\$d/f\$k.bin; head -c 4096 /dev/urandom | dd of=\$f bs=4k conv=fsync status=none || break; ino=\$(stat -c %i \$f); if [ \$((ino % 64)) -eq 0 ]; then b=\$f; break; fi; done; [ -n \"\$b\" ] && { echo \"PAYF=\$b INO=\$ino K=\$k\"; md5sum \$b | awk '{print \$1}'; } || echo NO_BOUNDARY_IN_400" > "$OUT/test$i.pay" &
    done; wait
    for i in $(seq 1 "$N"); do
        grep -o 'PAYF=[^ ]*' "$OUT/test$i.pay" | cut -d= -f2 > "$OUT/test$i.payf"
        tail -1 "$OUT/test$i.pay" > "$OUT/test$i.md5"
        [ -s "$OUT/test$i.payf" ] || fail "negative arm: test$i found no chunk boundary: $(tr '\n' ' ' < "$OUT/test$i.pay" | cut -c1-120)"
    done
    info "negative arm: chunk-boundary payloads: $(grep -ho 'K=[0-9]*' "$OUT"/test*.pay | cut -d= -f2 | sort -n | awk '{a[NR]=$1} END{print "creates-to-boundary min="a[1]" p50="a[int(NR/2)+1]" max="a[NR]" n="NR}')"
elif [ -n "$CONC" ]; then
# The concurrent arm is about whether a whole-cluster restart can REPLAY, so
# every node has to die owing a replay.  `sync -f` is syncfs: it pushes the
# whole filesystem and can leave the slice holding nothing the restart must
# recover, which would make the lap vacuous without saying so.  So the payload
# is fsync-acknowledged per file (never syncfs) and is followed by 200 fsync'd
# creates that are deliberately NOT pushed any further — the node dies with
# real transactions in its own journal slice.
for i in $(seq 1 "$N"); do
    sshq 90 "test$i" "d=$MNT/bootfull_$LABEL; mkdir -p \$d; f=\$d/test$i.bin
        head -c 65536 /dev/urandom | dd of=\$f bs=64k conv=fsync status=none || exit 1
        c=\$d/churn_test$i; mkdir -p \$c
        for k in \$(seq 1 200); do head -c 4096 /dev/urandom | dd of=\$c/f\$k.bin bs=4k conv=fsync status=none || break; done
        md5sum \$f | awk '{print \$1}'" > "$OUT/test$i.md5" &
done; wait
else
for i in $(seq 1 "$N"); do
    sshq 30 "test$i" "d=$MNT/bootfull_$LABEL; mkdir -p \$d; f=\$d/test$i.bin; head -c 65536 /dev/urandom > \$f && sync -f \$f && md5sum \$f | awk '{print \$1}'" > "$OUT/test$i.md5" &
done; wait
fi
np=0
for i in $(seq 1 "$N"); do
    m=$(tr -d '[:space:]' < "$OUT/test$i.md5")
    case "$m" in [0-9a-f]??????????????????????????????? ) np=$((np+1));; *) fail "payload test$i: md5='$m'";; esac
done
[ "$np" -eq "$N" ] && pass "payload written + fsynced on $N/$N nodes" || fail "payload on $np/$N nodes only"
[ $fails -eq 0 ] || { echo "=== bootstrap_full_restart $LABEL: fails=$fails (payload) out=$OUT ==="; exit 1; }
NEG_INO=""; NEG_SLOT=""; NEG_TGT=""
if [ -n "$NEG" ]; then
    NEG_INO=$(grep -o 'INO=[0-9]*' "$OUT/$NEG.pay" | cut -d= -f2 | tr -d '[:space:]')
    NEG_SLOT=$(sshq 20 "$NEG" "dmesg | grep -ao 'claimed heartbeat slot [0-9]*' | tail -1" | grep -o '[0-9]*$')
    case "$NEG_INO" in ''|*[!0-9]*) fail "negative arm: no inode number for $NEG's payload ('$NEG_INO')";; *) info "negative arm: $NEG payload ino=$NEG_INO slot=${NEG_SLOT:-?}";; esac
    # sess445 (chain 37 lap 2): corrupting the PAYLOAD dinode itself never
    # reaches the ICREATE verify — the victim also logged that inode as an
    # inode item, and the inode-item replay's xfs_inode_buf_verify refused
    # the cluster first (-117, fail-closed, nothing written).  Only a FREE
    # inode of the freshly carved chunk is covered by the ICREATE record
    # alone: corrupt the chunk's LAST inode (ino | 63) — the payload file is
    # the node's last create, so the rest of its 64-chunk is unallocated —
    # and fall back to the payload inode only when it IS the chunk's last.
    if [ -n "$NEG_INO" ]; then
        NEG_TGT=$(( NEG_INO | 63 ))
        [ "$NEG_TGT" -eq "$NEG_INO" ] && info "negative arm: payload ino is the chunk's last inode; corrupting it (inode-item path will refuse first)" || info "negative arm: corrupting FREE ino=$NEG_TGT (chunk of $NEG_INO; ICREATE-only coverage)"
    fi
    [ $fails -eq 0 ] || { echo "=== bootstrap_full_restart $LABEL: fails=$fails (negative setup) out=$OUT ==="; exit 1; }
fi

# 3. whole-cluster crash
TK=$(date +%s)
for i in $(seq 1 "$N"); do ( $VIRSH destroy "test$i" >/dev/null 2>&1; echo "test$i rc=$?" ) >> "$OUT/destroy.txt" & done; wait
info "destroyed $N VMs in $(( $(date +%s) - TK ))s: $(grep -c 'rc=0' "$OUT/destroy.txt")/$N rc=0"

# 3b. negative arm: corrupt the payload's dinode on the image (offline —
# every initiator is destroyed).  Whole-sector O_DIRECT read/modify/write so
# the target's page cache and the nodes' FUA reads see exactly this.
NEG_SEC=""
if [ -n "$NEG" ]; then
    timeout 30 tools/chk_mxfs --ino-offset "$NEG_TGT" "$IMG" > "$OUT/ino_offset.txt" 2>&1
    NEG_OFF=$(grep -ao 'dinode_off=[0-9]*' "$OUT/ino_offset.txt" | cut -d= -f2)
    if [ -z "$NEG_OFF" ] || [ $((NEG_OFF % 512)) -ne 0 ]; then
        fail "negative arm: chk_mxfs --ino-offset: $(tr '\n' ' ' < "$OUT/ino_offset.txt" | cut -c1-200)"
        echo "=== bootstrap_full_restart $LABEL: fails=$fails (negative setup) out=$OUT ==="; exit 1
    fi
    NEG_SEC=$((NEG_OFF / 512))
    dd if="$IMG" of="$OUT/sector.orig" bs=512 skip="$NEG_SEC" count=1 iflag=direct status=none
    python3 - "$OUT/sector.orig" "$OUT/sector.bad" <<'PY'
import sys
b = bytearray(open(sys.argv[1], 'rb').read())
assert len(b) == 512 and b[0:2] == b'IN', ('not a dinode at that sector', bytes(b[0:4]))
b[0:4] = b'\0\0\0\0'          # magic + version: the cluster can no longer verify
open(sys.argv[2], 'wb').write(bytes(b))
PY
    if [ $? -ne 0 ]; then fail "negative arm: sector $NEG_SEC is not a dinode (see $OUT/sector.orig)"; echo "=== bootstrap_full_restart $LABEL: fails=$fails (negative setup) out=$OUT ==="; exit 1; fi
    dd if="$OUT/sector.bad" of="$IMG" bs=512 seek="$NEG_SEC" count=1 conv=notrunc oflag=direct status=none && sync -f "$IMG"
    dd if="$IMG" of="$OUT/sector.check" bs=512 skip="$NEG_SEC" count=1 iflag=direct status=none
    cmp -s "$OUT/sector.bad" "$OUT/sector.check" && pass "negative arm: dinode ino=$NEG_TGT magic zeroed on the image at sector $NEG_SEC (offline)" || { fail "negative arm: corruption did not land at sector $NEG_SEC"; echo "=== bootstrap_full_restart $LABEL: fails=$fails (negative setup) out=$OUT ==="; exit 1; }
fi

# 4c. THE CONCURRENT ARM (MXFS_CONCURRENT=1).
#
# The sequential restart above brings ONE node back first, so that node is the
# only live member when it fences the dead incarnations — and the sole-survivor
# leg of the fence (dlm/v5_mount.c:9802) requires exactly that: nlive == 1 &&
# other_live < 0.  That leg carries the only production call of the witnessed
# LU-reset route, which is the one operation that retires work no registration
# names any more.  A target that purges a registration with its iSCSI session
# leaves every fence classified KEY_ABSENT_UNPROVEN, so on such a target the
# LU-reset route is the whole recovery.
#
# This arm brings every node up TOGETHER and fires their mounts off one shared
# wall-clock instant, so no mount is the only live member.  What it measures is
# which leg each mount reaches and whether either completes.
#
# It reports nlive AS THE KERNEL SAW IT — P238-FENCE-GATE-TRY and
# P238-FENCE-GATE-NOTSOLE both print nlive and other_live — never as the
# schedule intended, because two mounts that serialise anyway would answer a
# different question while looking like this one.  A lap whose mounts did not
# overlap, or in which no mount reached the absent-key leg at all, says so and
# fails as VACUOUS rather than reporting a verdict it did not earn.
if [ -n "$CONC" ]; then
    # The owner's mount budget, derived from the parts it actually pays and
    # not rounded.  Measured on lap s111a (0.89.40, 2/tcp): 190.9 s from
    # module load to the LU-reset convergence line, which already contains
    # both 62.5 s survivor-scan windows, the term claim, the seal and the
    # manifest write.  Remaining: the post-reset barrier, bounded by the
    # bootstrap record's 6 s abandon window; the rest of phase 3 for the
    # second victim, ~10 s at the first one's measured pace; the adopted
    # slot's own-log replay ~10 s and one foreign slice at the node-death
    # replay pace ~8 s; completion ~10 s.  190.9 + 6 + 10 + 10 + 8 + 10 =
    # 235 s.  A mount that exceeds this has not "nearly passed" — it is a
    # failure and the slowness is the finding.
    CB=${CONC_MOUNT_BOUND:-235}
    # A node the term election refused claimed nothing and did no I/O; its
    # retry is an ORDINARY mount into a RECOVERY_COMPLETE record, and 180 s
    # is this rig's established ordinary-mount bound.
    RB=${CONC_RETRY_BOUND:-180}
    for i in $(seq 1 "$N"); do $VIRSH start "test$i" >/dev/null 2>&1 & done; wait
    info "concurrent: started $N VMs together at +$(( $(date +%s) - TK ))s"
    for i in $(seq 1 "$N"); do
        (
            up=0; for a in $(seq 1 24); do sleep 5; sshq 8 "test$i" "echo SSH_UP" | grep -q SSH_UP && { up=1; break; }; done
            [ $up -eq 1 ] || { echo NO_SSH; exit 1; }
            bringup "test$i" || { echo NO_DEV; exit 1; }
            echo READY
        ) > "$OUT/test$i.ready" 2>&1 &
    done; wait
    nr=0
    for i in $(seq 1 "$N"); do
        grep -q READY "$OUT/test$i.ready" && nr=$((nr+1)) || fail "concurrent: test$i not ready: $(tr '\n' ' ' < "$OUT/test$i.ready" | cut -c1-120)"
    done
    [ "$nr" -eq "$N" ] && info "concurrent: $N/$N nodes have ssh, /src and $DEV at +$(( $(date +%s) - TK ))s" || { echo "=== bootstrap_full_restart $LABEL (CONCURRENT): fails=$fails out=$OUT ==="; exit 1; }
    # The gate is an absolute epoch on every node, so it only aligns the mounts
    # if the nodes agree with this host about what that epoch is.  Measured, not
    # assumed: a skew larger than the alignment we are claiming is a harness
    # defect and would make the arm vacuous without saying so.
    skewmax=0
    for i in $(seq 1 "$N"); do
        C0=$(date +%s%3N); NS=$(sshq 10 "test$i" "date +%s%3N" | tr -dc 0-9); C1=$(date +%s%3N)
        if [ -n "$NS" ]; then
            sk=$(( NS - (C0 + C1) / 2 )); [ "$sk" -lt 0 ] && sk=$(( -sk ))
            info "concurrent: test$i clock skew vs this host ${sk} ms"
            [ "$sk" -gt "$skewmax" ] && skewmax=$sk
        else
            fail "concurrent: no clock reading from test$i"
        fi
    done
    [ "$skewmax" -le 2000 ] && pass "concurrent: worst node clock skew ${skewmax} ms — the shared gate instant means the same thing on every node" || fail "concurrent: node clock skew ${skewmax} ms is larger than the alignment this arm claims"
    GATE=$(( $(date +%s) + 25 ))
    info "concurrent: mount gate at epoch $GATE ($(date -u -d "@$GATE" +%FT%TZ)); per-mount bound ${CB}s"
    for i in $(seq 1 "$N"); do
        sshq $((CB+120)) "test$i" "echo 3 > /proc/sys/vm/drop_caches; cp /src/mxfs/mxfs.ko /tmp/mxfs.ko; m=\$(md5sum /tmp/mxfs.ko | awk '{print \$1}'); [ \"\$m\" = '$KO_MD5' ] || { echo KO_MD5_MISMATCH \$m; exit 1; }
            modprobe libcrc32c 2>/dev/null || true; insmod /tmp/mxfs.ko $MODARGS || { echo INSMOD_FAILED; exit 1; }; cat /sys/module/mxfs/srcversion
            echo 1 > /sys/module/mxfs/parameters/foreign_replay_token_enforce
            mkdir -p $MNT
            while [ \$(date +%s) -lt $GATE ]; do sleep 0.2; done
            echo CONCMOUNT-$LABEL > /dev/kmsg
            echo MSTART=\$(date +%s%3N)
            timeout $CB mount -t mxfs $DEV $MNT; rc=\$?
            echo MEND=\$(date +%s%3N); echo MOUNT_RC=\$rc
            mountpoint -q $MNT && echo IS_MOUNTED=1 || echo IS_MOUNTED=0" > "$OUT/test$i.cmount" 2>&1 &
    done; wait
    for i in $(seq 1 "$N"); do
        sshq 60 "test$i" "dmesg | sed -n '/CONCMOUNT-$LABEL/,\$p'" > "$OUT/test$i.cdmesg" 2>&1 &
    done; wait
    # 4c-i. did the two mounts actually overlap?
    maxs=0; mine=0; nwin=0
    for i in $(seq 1 "$N"); do
        s=$(grep -ao 'MSTART=[0-9]*' "$OUT/test$i.cmount" | cut -d= -f2)
        e=$(grep -ao 'MEND=[0-9]*' "$OUT/test$i.cmount" | cut -d= -f2)
        r=$(grep -ao 'MOUNT_RC=[0-9]*' "$OUT/test$i.cmount" | cut -d= -f2)
        if [ -z "$s" ] || [ -z "$e" ]; then
            fail "concurrent: test$i printed no mount window: $(tr '\n' ' ' < "$OUT/test$i.cmount" | cut -c1-200)"
            continue
        fi
        nwin=$((nwin+1))
        info "concurrent: test$i mount rc=${r:-?} start=$s wall=$(( (e - s) / 1000 ))s mounted=$(grep -ao 'IS_MOUNTED=[01]' "$OUT/test$i.cmount" | cut -d= -f2)"
        [ "$s" -gt "$maxs" ] && maxs=$s
        if [ "$mine" -eq 0 ] || [ "$e" -lt "$mine" ]; then mine=$e; fi
    done
    [ "$nwin" -eq "$N" ] || { fail "concurrent: only $nwin/$N nodes reported a mount window"; echo "=== bootstrap_full_restart $LABEL (CONCURRENT): fails=$fails out=$OUT ==="; exit 1; }
    OV=$(( mine - maxs ))
    [ "$OV" -gt 0 ] && pass "concurrent: the $N mounts overlapped for $(( OV / 1000 ))s (last start to first return)" || fail "concurrent: the mounts did NOT overlap (last start $maxs, first return $mine) — VACUOUS, this lap measured a sequential restart"
    # 4c-ii. what the KERNEL saw, and which leg each mount reached
    legs=0; nsole=0; nnotsole=0; nlureset=0; ncert=0
    for i in $(seq 1 "$N"); do
        D="$OUT/test$i.cdmesg"
        grep -a 'P238-\|P236-\|P-BOOT-\|P163-RECOVERY-COMPLETE\|foreign replay of\|claimed heartbeat slot\|Shutting down filesystem' "$D" | cut -c1-220 > "$OUT/test$i.legs"
        t=$(grep -ac 'P238-FENCE-GATE-TRY' "$D"); ns=$(grep -ac 'P238-FENCE-GATE-NOTSOLE' "$D")
        lu=$(grep -ac 'P238-FENCE-LURESET ' "$D"); ce=$(grep -ac 'P236-FENCE-CERTIFIED' "$D")
        # THE VACUITY GATE MUST COUNT EVERY ROUTE THE ABSENT-KEY LEG CAN TAKE,
        # NOT THE ONE IT TOOK WHEN THIS GATE WAS WRITTEN.  Counting only the
        # GATE-TRY/GATE-NOTSOLE pair failed lap s112a as vacuous while that
        # lap had fenced and certified BOTH victims — through the witnessed
        # LU-reset route, which reports itself as FENCE-LURESET followed by
        # FENCE-CERTIFIED and never touches the sole-member gate at all.  A
        # lap that fenced nothing still has all four counters at zero, so the
        # gate keeps its teeth; what it stops doing is failing a fence that
        # worked because the fence got better.
        nsole=$((nsole+t)); nnotsole=$((nnotsole+ns)); nlureset=$((nlureset+lu)); ncert=$((ncert+ce))
        legs=$((legs+t+ns+lu+ce))
        info "concurrent: test$i legs GATE-TRY=$t GATE-NOTSOLE=$ns LURESET=$lu CERTIFIED=$ce BOOTSUCC-NO-RETIRE-BASIS=$(grep -ac 'P238-BOOTSUCC-NO-RETIRE-BASIS' "$D") GATE-NO-RETIRE-BASIS=$(grep -ac 'P238-GATE-NO-RETIRE-BASIS' "$D") SELFSUCC-NO-RETIRE-BASIS=$(grep -ac 'P238-SELFSUCC-NO-RETIRE-BASIS' "$D") FENCE-BLOCKED=$(grep -ac 'P238-FENCE-BLOCKED' "$D") BOOT-FENCE-UNPROVEN=$(grep -ac 'P-BOOT-FENCE-UNPROVEN' "$D")"
        info "concurrent: test$i nlive as the kernel saw it: [$(grep -ao 'nlive=[0-9-]* other_live=[0-9-]*' "$D" | sort | uniq -c | tr '\n' ';' | cut -c1-160)]"
    done
    [ "$legs" -gt 0 ] && pass "concurrent: the absent-key fence leg was reached $legs time(s) across $N nodes (GATE-TRY=$nsole GATE-NOTSOLE=$nnotsole LURESET=$nlureset CERTIFIED=$ncert)" || fail "concurrent: no node reached the absent-key fence leg by ANY route — VACUOUS, nothing was fenced and no leg was exercised"
    info "concurrent: totals GATE-TRY=$nsole GATE-NOTSOLE=$nnotsole LURESET=$nlureset CERTIFIED=$ncert"
    # 4c-iii-a. THE TERM LOSER IS REFUSED BY DESIGN, AND ITS RETRY IS PART OF
    # THE OUTCOME, NOT A RELAXATION OF IT.
    #
    # Exactly one concurrent mount can hold the bootstrap term.  Every other
    # node is refused at P-BOOT-CLAIM-LOST before it has claimed a slot,
    # started a journal or taken a grant, and its own kernel message tells it
    # to retry later.  Asserting that all N mounts succeed in ONE attempt
    # therefore fails a design that is working — but simply dropping the
    # assertion would stop measuring the thing that matters, which is that
    # every node ends up mounted with its data.  So the refused nodes are
    # RETRIED once, after the first round has fully returned, which is the
    # instant the owner has either completed the term or failed it.  A node
    # that needed a retry is reported as such; a node that fails the retry
    # fails the lap.
    nretry=0
    for i in $(seq 1 "$N"); do
        r=$(grep -ao 'MOUNT_RC=[0-9]*' "$OUT/test$i.cmount" | cut -d= -f2)
        [ "${r:-1}" -eq 0 ] && continue
        lost=$(grep -ac 'P-BOOT-CLAIM-LOST' "$OUT/test$i.cdmesg")
        info "concurrent: test$i was refused on the first attempt (rc=${r:-?}, P-BOOT-CLAIM-LOST x$lost); retrying once with bound ${RB}s"
        nretry=$((nretry+1))
        sshq $((RB+60)) "test$i" "echo CONCRETRY-$LABEL > /dev/kmsg
            echo RSTART=\$(date +%s%3N)
            timeout $RB mount -t mxfs $DEV $MNT; rc=\$?
            echo REND=\$(date +%s%3N); echo RETRY_RC=\$rc
            mountpoint -q $MNT && echo IS_MOUNTED=1 || echo IS_MOUNTED=0" > "$OUT/test$i.cretry" 2>&1 &
    done
    [ "$nretry" -gt 0 ] && wait
    for i in $(seq 1 "$N"); do
        [ -f "$OUT/test$i.cretry" ] || continue
        sshq 60 "test$i" "dmesg | sed -n '/CONCRETRY-$LABEL/,\$p'" > "$OUT/test$i.rdmesg" 2>&1
        rs=$(grep -ao 'RSTART=[0-9]*' "$OUT/test$i.cretry" | cut -d= -f2)
        re=$(grep -ao 'REND=[0-9]*' "$OUT/test$i.cretry" | cut -d= -f2)
        rr=$(grep -ao 'RETRY_RC=[0-9]*' "$OUT/test$i.cretry" | cut -d= -f2)
        if [ -n "$rs" ] && [ -n "$re" ]; then
            info "concurrent: test$i retry rc=${rr:-?} wall=$(( (re - rs) / 1000 ))s mounted=$(grep -ao 'IS_MOUNTED=[01]' "$OUT/test$i.cretry" | cut -d= -f2)"
        else
            fail "concurrent: test$i printed no retry window: $(tr '\n' ' ' < "$OUT/test$i.cretry" | cut -c1-200)"
        fi
    done
    # 4c-iii. the outcome the release bar is about
    cm=0
    for i in $(seq 1 "$N"); do
        r=$(grep -ao 'MOUNT_RC=[0-9]*' "$OUT/test$i.cmount" | cut -d= -f2)
        if [ "${r:-1}" -ne 0 ] && [ -f "$OUT/test$i.cretry" ]; then
            r=$(grep -ao 'RETRY_RC=[0-9]*' "$OUT/test$i.cretry" | cut -d= -f2)
        fi
        [ "${r:-1}" -eq 0 ] && cm=$((cm+1))
    done
    [ "$cm" -eq "$N" ] && pass "concurrent: $cm/$N mounts completed rc=0 ($nretry after a by-design term refusal and one retry) — the whole cluster recovered from a concurrent restart" || fail "concurrent: $cm/$N mounts completed rc=0 (with $nretry retried) — the whole-cluster restart did not recover: $(grep -ahao 'P-BOOT-FENCE-UNPROVEN.*\|P-BOOT-PHASE3-FAILED.*\|P238-BOOTSUCC-NO-RETIRE-BASIS.*\|P238-GATE-NO-RETIRE-BASIS.*' "$OUT"/test*.cdmesg | head -2 | cut -c1-200 | tr '\n' ' ')"
    for i in $(seq 1 "$N"); do
        for D in "$OUT/test$i.cdmesg" "$OUT/test$i.rdmesg"; do
            [ -f "$D" ] || continue
            for pat in 'BUG:' 'Oops' 'Shutting down filesystem' 'P-RMAN-FSWIDE-HALT'; do
                c=$(grep -ac "$pat" "$D"); [ "$c" -eq 0 ] || fail "concurrent: $pat x$c on test$i ($(basename "$D"))"
            done
        done
    done
    # 4c-iv. the payload, from every node that did come up — on the first
    # attempt or on the by-design retry; both are mounted filesystems and the
    # data has to be there either way.
    for i in $(seq 1 "$N"); do
        grep -q 'IS_MOUNTED=1' "$OUT/test$i.cmount" 2>/dev/null ||
            grep -q 'IS_MOUNTED=1' "$OUT/test$i.cretry" 2>/dev/null || continue
        ok=0
        for j in $(seq 1 "$N"); do
            want=$(tr -d '[:space:]' < "$OUT/test$j.md5")
            got=$(sshq 20 "test$i" "md5sum $MNT/bootfull_$LABEL/test$j.bin 2>/dev/null | awk '{print \$1}'" | tr -d '[:space:]')
            [ "$got" = "$want" ] && ok=$((ok+1)) || echo "    test$i sees test$j.bin want=$want got='${got:-MISSING}'" >> "$OUT/payload_mismatch_conc.txt"
        done
        [ "$ok" -eq "$N" ] && pass "concurrent: test$i reads $N/$N fsync-acknowledged payloads with the recorded md5" || fail "concurrent: test$i reads $ok/$N payloads (see $OUT/payload_mismatch_conc.txt)"
    done
    # 4c-v. leave the LUN readable: unmount what mounted, unload everywhere, and
    # read the platter from a node (this rig has no host-side image).
    for i in $(seq 1 "$N"); do sshq 120 "test$i" "timeout 90 umount $MNT >/dev/null 2>&1; echo UMOUNT_RC=\$?; rmmod mxfs >/dev/null 2>&1; echo RMMOD_RC=\$?" > "$OUT/test$i.cumount" 2>&1 & done; wait
    for i in $(seq 1 "$N"); do info "concurrent: test$i teardown $(tr '\n' ' ' < "$OUT/test$i.cumount" | cut -c1-80)"; done
    if [ -n "$IMG" ]; then
        timeout 240 tools/chk_mxfs -v "$IMG" > "$OUT/cchk.txt" 2>&1; chkrc=$?
        echo "CHK_RC=$chkrc ms=0" >> "$OUT/cchk.txt"
    else
        mxfs_chk_on_node test1 "$OUT/cchk.txt" "concurrent: offline check from test1" -v
        chkrc=$(mxfs_chk_rc "$OUT/cchk.txt")
    fi
    chk_err=$(grep -ac 'ERROR' "$OUT/cchk.txt"); chk_sb=$(grep -ac 'ERROR.*\(icount\|ifree\)' "$OUT/cchk.txt")
    [ $(( chk_err - chk_sb )) -eq 0 ] && pass "concurrent: chk_mxfs non-SB errors 0 (rc=${chkrc:-?})" || fail "concurrent: chk_mxfs non-SB errors=$(( chk_err - chk_sb )) rc=${chkrc:-?} (see $OUT/cchk.txt)"
    grep -a 'bootstrap' "$OUT/cchk.txt" | head -3
    info "wall=$(( $(date +%s) - T0 ))s — the fleet is left unmounted with the module unloaded; re-prep before the next lap"
    echo "=== bootstrap_full_restart $LABEL (CONCURRENT): fails=$fails out=$OUT $(date -u +%FT%TZ) ==="
    [ $fails -eq 0 ]; exit $?
fi

# 4. the remounter alone
$VIRSH start "$RM" >/dev/null 2>&1 || { fail "virsh start $RM"; echo "=== bootstrap_full_restart $LABEL: fails=$fails out=$OUT ==="; exit 1; }
booted=0
for a in $(seq 1 24); do sleep 5; sshq 8 "$RM" "echo SSH_UP" | grep -q SSH_UP && { booted=1; break; }; done
[ $booted -eq 1 ] && info "$RM ssh up at +$(( $(date +%s) - TK ))s" || { fail "$RM never came back on ssh"; echo "=== bootstrap_full_restart $LABEL: fails=$fails out=$OUT ==="; exit 1; }
bringup "$RM" || { fail "$DEV / /src never came up on $RM"; echo "=== bootstrap_full_restart $LABEL: fails=$fails out=$OUT ==="; exit 1; }
TM=$(date +%s)
sshq $((MOUNT_BOUND+60)) "$RM" "echo 3 > /proc/sys/vm/drop_caches; cp /src/mxfs/mxfs.ko /tmp/mxfs.ko; m=\$(md5sum /tmp/mxfs.ko | awk '{print \$1}'); [ \"\$m\" = '$KO_MD5' ] || { echo KO_MD5_MISMATCH \$m; exit 1; }
    modprobe libcrc32c 2>/dev/null || true; insmod /tmp/mxfs.ko; cat /sys/module/mxfs/srcversion
    echo 1 > /sys/module/mxfs/parameters/target_cache_protected; echo 1 > /sys/module/mxfs/parameters/foreign_replay_token_enforce
    echo BOOTFULL-MOUNT-$LABEL > /dev/kmsg; mkdir -p $MNT; timeout $MOUNT_BOUND mount -t mxfs $DEV $MNT; echo MOUNT_RC=\$?" > "$OUT/remount.txt" 2>&1
MW=$(( $(date +%s) - TM ))
grep -q "^$TREE_SV" "$OUT/remount.txt" && pass "$RM loaded $TREE_SV" || fail "$RM module: $(tr '\n' ' ' < "$OUT/remount.txt")"
mrc=$(grep -ao 'MOUNT_RC=[0-9]*' "$OUT/remount.txt" | cut -d= -f2)
info "mount attempt rc=${mrc:-?} wall=${MW}s (+$(( $(date +%s) - TK ))s after the crash)"
sshq 60 "$RM" "dmesg | sed -n '/BOOTFULL-MOUNT-$LABEL/,\$p'" > "$OUT/remounter_dmesg.txt"
grep -a 'P-BOOT-\|P238-RECOV-LEASE\|P236-FENCEKIND\|foreign replay of\|P163-RECOVERY-COMPLETE\|claimed heartbeat slot\|P-BOOT-ADOPTED\|barrier complete\|P226-ICENSUS\|P273-SHADOW-CAP' "$OUT/remounter_dmesg.txt" | cut -c1-200 > "$OUT/timeline.txt"

# 5n. negative arm verdict — the replay must REFUSE the corrupted slice and write nothing
if [ -n "$NEG" ]; then
    D="$OUT/remounter_dmesg.txt"
    grep -a 'P-ICREATE-\|P133-ICLUSTER' "$D" | cut -c1-220 > "$OUT/icreate_lines.txt"
    [ "${mrc:-0}" -ne 0 ] && pass "negative arm: mount rc=${mrc:-?} (the corrupted slice must refuse the term)" || fail "negative arm: mount rc=0 — the corrupted SYNCINIT chunk was accepted"
    grep -aq "P-ICREATE-VERIFY-FAIL .*ino=$NEG_TGT why=magic" "$D" && pass "negative arm: P-ICREATE-VERIFY-FAIL ino=$NEG_TGT why=magic" || fail "negative arm: no P-ICREATE-VERIFY-FAIL for ino=$NEG_TGT: $(grep -ao 'P-ICREATE-VERIFY-FAIL.*' "$D" | head -1 | cut -c1-160)"
    grep -aq 'P-ICREATE-REFUSE' "$D" && pass "negative arm: P-ICREATE-REFUSE" || fail "negative arm: no P-ICREATE-REFUSE"
    if [ -n "$NEG_SLOT" ]; then grep -aq "foreign replay of slot $NEG_SLOT .*failed" "$D" && pass "negative arm: foreign replay of slot $NEG_SLOT failed (refused, not applied)" || fail "negative arm: slot $NEG_SLOT replay not reported failed: $(grep -ao "foreign replay of slot $NEG_SLOT .*" "$D" | head -1 | cut -c1-160)"; fi
    c=$(grep -ac 'P-ICREATE-VERIFIED' "$D"); [ "$c" -ge 1 ] && pass "negative arm: $c other SYNCINIT chunks VERIFIED and skipped in the same lap" || fail "negative arm: no P-ICREATE-VERIFIED at all (positive arm did not run)"
    dd if="$IMG" of="$OUT/sector.after" bs=512 skip="$NEG_SEC" count=1 iflag=direct status=none
    cmp -s "$OUT/sector.bad" "$OUT/sector.after" && pass "negative arm: sector $NEG_SEC byte-identical after the replay — NOTHING was written over the non-verifying cluster" || fail "negative arm: sector $NEG_SEC CHANGED after the replay (the replay wrote over a non-verifying cluster): $(cmp "$OUT/sector.bad" "$OUT/sector.after" | head -1)"
    for pat in 'BUG:' 'Oops' 'P-RMAN-FSWIDE-HALT' 'P133-ICLUSTER-SYNCINIT-FAIL'; do
        c=$(grep -ac "$pat" "$D"); [ "$c" -eq 0 ] && pass "no $pat" || fail "$pat x$c on $RM"
    done
    dd if="$OUT/sector.orig" of="$IMG" bs=512 seek="$NEG_SEC" count=1 conv=notrunc oflag=direct status=none && sync -f "$IMG" && info "negative arm: sector $NEG_SEC restored"
    info "wall=$(( $(date +%s) - T0 ))s"
    echo "=== bootstrap_full_restart $LABEL (NEGATIVE ARM): fails=$fails out=$OUT $(date -u +%FT%TZ) ==="
    [ $fails -eq 0 ]; exit $?
fi

# 5. the owner path
[ "${mrc:-1}" -eq 0 ] && pass "$RM MOUNTED with no operator action (rc=0)" || fail "$RM mount rc=${mrc:-?}: $(grep -ao 'P-BOOT-MOUNT-REFUSED.*\|P-BOOT-[A-Z-]*REFUSED.*\|P-BOOT-[A-Z-]*FAILED.*\|MXFS mount ABORTED.*' "$OUT/remounter_dmesg.txt" | head -2 | cut -c1-160 | tr '\n' ' ')"
[ "$MW" -le "$MOUNT_BOUND" ] && pass "mount wall ${MW}s <= ${MOUNT_BOUND}s" || fail "mount wall ${MW}s > ${MOUNT_BOUND}s (budget)"
grep -aq "P-BOOT-SEALED entries=$N " "$OUT/remounter_dmesg.txt" && pass "manifest sealed with $N entries" || fail "seal: $(grep -ao 'P-BOOT-SEALED.*' "$OUT/remounter_dmesg.txt" | cut -c1-120)"
grep -aq "P-BOOT-PHASE3-COMPLETE certs=$N" "$OUT/remounter_dmesg.txt" && pass "phase 3: $N certificates" || fail "phase 3: $(grep -ao 'P-BOOT-PHASE3-[A-Z]*.*' "$OUT/remounter_dmesg.txt" | cut -c1-120)"
K=$(grep -ao 'P-BOOT-ADOPT slot=[0-9]*' "$OUT/remounter_dmesg.txt" | head -1 | grep -o '[0-9]*$')
[ -n "$K" ] && pass "adopted victim slot K=$K (escrow + P-BOOT-ADOPTED)" || fail "no P-BOOT-ADOPT: $(grep -ao 'P-BOOT-ADOPT[A-Z-]*.*' "$OUT/remounter_dmesg.txt" | head -2 | cut -c1-140 | tr '\n' ' ')"
grep -aq 'P-BOOT-ESCROW-READBACK.*rc=0' "$OUT/remounter_dmesg.txt" && pass "escrow read back before the claim" || fail "escrow: $(grep -ao 'P-BOOT-ESCROW.*' "$OUT/remounter_dmesg.txt" | head -1 | cut -c1-140)"
grep -aq 'P-BOOT-ADOPTED-LOG' "$OUT/remounter_dmesg.txt" && pass "K mounted as own log: FULL authority-evaluated replay" || fail "no P-BOOT-ADOPTED-LOG"
c=$(grep -ac 'P-BOOT-ADOPTED-REFUSED' "$OUT/remounter_dmesg.txt"); [ "$c" -eq 0 ] && pass "K replay refused nothing" || fail "P-BOOT-ADOPTED-REFUSED x$c: $(grep -ao 'P-BOOT-ADOPTED-REFUSED.*' "$OUT/remounter_dmesg.txt" | head -1 | cut -c1-160)"
frc=$(grep -ac 'foreign replay of slot .* complete' "$OUT/remounter_dmesg.txt"); frf=$(grep -ac 'foreign replay of slot .* failed' "$OUT/remounter_dmesg.txt")
[ "$frc" -eq $((N-1)) ] && pass "$frc foreign slices replayed complete (N-1; K is our own log)" || fail "foreign replays complete=$frc failed=$frf (want $((N-1)))"
[ "$frf" -eq 0 ] && pass "0 failed foreign replays" || fail "$frf failed foreign replays"
c=$(grep -ac 'P163-RECOVERY-COMPLETE' "$OUT/remounter_dmesg.txt"); [ "$c" -ge $((N-1)) ] && pass "$c slot recoveries published" || fail "P163-RECOVERY-COMPLETE x$c (want >= $((N-1)))"
c=$(grep -ac 'P-BOOT-COMPLETE-CASFAIL' "$OUT/remounter_dmesg.txt"); [ "$c" -eq 0 ] && pass "every completion bit landed before its zero" || fail "P-BOOT-COMPLETE-CASFAIL x$c"
grep -aq 'P-BOOT-RECOVERY-COMPLETE' "$OUT/remounter_dmesg.txt" && pass "RECOVERY_COMPLETE: admission open" || fail "no P-BOOT-RECOVERY-COMPLETE: $(grep -ao 'P-BOOT-FINISH.*\|P-BOOT-RECONCILE.*\|P-BOOT-TERMINAL.*' "$OUT/remounter_dmesg.txt" | head -2 | cut -c1-140 | tr '\n' ' ')"
c=$(grep -ac 'P-BOOT-UNWIND' "$OUT/remounter_dmesg.txt"); [ "$c" -eq 0 ] && pass "no bootstrap unwind" || fail "P-BOOT-UNWIND x$c"
for pat in 'BUG:' 'Oops' 'P-RMAN-FSWIDE-HALT' 'P240-QUAR-IMPORT' 'POLICY-REFUSED' 'P-AGIFC-MISMATCH' 'P-BOOT-HB-LOST' 'P-BOOT-CAS-LOST'; do
    c=$(grep -ac "$pat" "$OUT/remounter_dmesg.txt"); [ "$c" -eq 0 ] && pass "no $pat" || fail "$pat x$c on $RM"
done
ok=0
for i in $(seq 1 "$N"); do
    want=$(tr -d '[:space:]' < "$OUT/test$i.md5")
    pf=$MNT/bootfull_$LABEL/test$i.bin; [ -s "$OUT/test$i.payf" ] && pf=$(cat "$OUT/test$i.payf")
    got=$(sshq 20 "$RM" "md5sum $pf 2>/dev/null | awk '{print \$1}'" | tr -d '[:space:]')
    if [ "$got" = "$want" ]; then ok=$((ok+1)); else echo "    payload test$i.bin want=$want got='${got:-MISSING}'" >> "$OUT/payload_mismatch_owner.txt"; fi
done
[ "$ok" -eq "$N" ] && pass "payload on the owner: $N/$N fsync-acknowledged files present with the recorded md5" || { fail "payload on the owner: $ok/$N intact (see $OUT/payload_mismatch_owner.txt)"; head -3 "$OUT/payload_mismatch_owner.txt"; }

# 6. admit the other N-1 nodes — no mkfs, same build
TP=$(date +%s)
for i in $(seq 1 "$N"); do [ "test$i" = "$RM" ] || $VIRSH start "test$i" >/dev/null 2>&1 & done; wait
for i in $(seq 1 "$N"); do
    [ "test$i" = "$RM" ] && continue
    (
        up=0; for a in $(seq 1 24); do sleep 5; sshq 8 "test$i" "echo SSH_UP" | grep -q SSH_UP && { up=1; break; }; done
        [ $up -eq 1 ] || { echo "NO_SSH"; exit 1; }
        bringup "test$i" || { echo "NO_DEV"; exit 1; }
        sshq 120 "test$i" "cp /src/mxfs/mxfs.ko /tmp/mxfs.ko; m=\$(md5sum /tmp/mxfs.ko | awk '{print \$1}'); [ \"\$m\" = '$KO_MD5' ] || { echo KO_MD5_MISMATCH; exit 1; }
            modprobe libcrc32c 2>/dev/null || true; insmod /tmp/mxfs.ko; echo 1 > /sys/module/mxfs/parameters/target_cache_protected; echo 1 > /sys/module/mxfs/parameters/foreign_replay_token_enforce
            mkdir -p $MNT; timeout 120 mount -t mxfs $DEV $MNT && echo MOUNT_OK; dmesg | grep -a 'P-BOOT-STATE\|P-BOOT-ADMISSION' | tail -2"
    ) > "$OUT/test$i.peer" 2>&1 &
done; wait
pm=0
for i in $(seq 1 "$N"); do [ "test$i" = "$RM" ] && continue; grep -q MOUNT_OK "$OUT/test$i.peer" && pm=$((pm+1)) || echo "    test$i: $(tr '\n' ' ' < "$OUT/test$i.peer" | cut -c1-160)" >> "$OUT/peer_fail.txt"; done
PW=$(( $(date +%s) - TP ))
[ "$pm" -eq $((N-1)) ] && pass "$pm/$((N-1)) peers admitted and mounted after RECOVERY_COMPLETE (${PW}s)" || { fail "$pm/$((N-1)) peers mounted (${PW}s; see $OUT/peer_fail.txt)"; head -3 "$OUT/peer_fail.txt"; }
[ "$PW" -le "$PEER_BOUND" ] && pass "peer admission wall ${PW}s <= ${PEER_BOUND}s" || fail "peer admission wall ${PW}s > ${PEER_BOUND}s (budget)"
PEER=test2; [ "$PEER" = "$RM" ] && PEER=test3
ok=0
for i in $(seq 1 "$N"); do
    want=$(tr -d '[:space:]' < "$OUT/test$i.md5")
    pf=$MNT/bootfull_$LABEL/test$i.bin; [ -s "$OUT/test$i.payf" ] && pf=$(cat "$OUT/test$i.payf")
    got=$(sshq 20 "$PEER" "md5sum $pf 2>/dev/null | awk '{print \$1}'" | tr -d '[:space:]')
    [ "$got" = "$want" ] && ok=$((ok+1)) || echo "    payload test$i.bin want=$want got='${got:-MISSING}'" >> "$OUT/payload_mismatch_peer.txt"
done
[ "$ok" -eq "$N" ] && pass "payload from peer $PEER: $N/$N files with the recorded md5" || { fail "payload from peer $PEER: $ok/$N (see $OUT/payload_mismatch_peer.txt)"; head -3 "$OUT/payload_mismatch_peer.txt"; }

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
echo "=== bootstrap_full_restart $LABEL: fails=$fails out=$OUT $(date -u +%FT%TZ) ==="
[ $fails -eq 0 ]
