#!/bin/bash
#
# crash_mid_umount_remount.sh — a node that dies in the middle of its own
# unmount, after its peer has already unmounted cleanly, must be able to mount
# again and recover its previous incarnation.
#
# 0.89.84 packaged round: test4 unmounted cleanly, test3 oopsed mid-unmount.
# test3's next mount then refused its own fence for ~60 rounds with
# P306-LURESET-ADMIT admitted=0 reason=another-initiator-is-registered
# victim_present=0 — its old key already gone, one foreign key registered —
# and was admitted only when test4's own mount retired test4's key.  A clean
# clustered departure can leave its key registered (retire-pending) for a
# peer to retire, so the question is whether the crashed node can recover
# with that peer absent.
#
#   1. a fresh 2/tcp cluster (./run.sh 2 tcp prep_cluster), 500 files written
#      on the victim so its slice is dirty
#   2. the peer unmounts cleanly
#   3. the victim starts its unmount and is destroyed 1 s into it
#      (virsh destroy: a power loss mid-unmount, as the oops was)
#   4. the victim boots; ARM=alone mounts it with the peer still unmounted,
#      ARM=together mounts both at once
#   5. PASS when every mount returns within MOUNT_S, the victim's files are
#      all there, and chk_mxfs is clean after both unmount
#
# Budgets: an idle 2-node TCP mount measured ~5 s, and recovering one slice
# adds a fence (~2 s by LU reset) and the stability proof (2 x 2 s) plus the
# replay; doubled and rounded -> MOUNT_S=60, the packaged round's mount
# budget.  prep_node.sh gets its own 180 s cap so a stuck mount is measured,
# not waited out.  A rig node boots in ~30 s -> BOOT_S=120.
#
# Usage: ARM=alone|together tests/crash_mid_umount_remount.sh [victim] [peer]
#   Evidence: tests/evidence/crash_mid_umount_remount/<arm>_<stamp>/.
#
set -u

V="${1:-test1}"
P="${2:-test2}"
ARM="${ARM:-alone}"
case "$ARM" in alone|together) ;; *) echo "ARM must be alone|together" >&2; exit 2 ;; esac
MOUNT_S=60
BOOT_S=120
MNT=/mnt/shared
HERE="$(cd "$(dirname "$0")/.." && pwd)"
SSH="$HERE/tools/mxfs_sshpass.sh"
VIRSH="virsh -c qemu:///system"
EV="$HERE/tests/evidence/crash_mid_umount_remount/${ARM}_$(date +%Y%m%dT%H%M%S)"
mkdir -p "$EV"
exec > >(tee -a "$EV/run.log") 2>&1
say() { echo "[$(date +%T)] $*"; }
fail() { say "FAIL: $*"; say "RESULT FAIL"; exit 1; }
on() { local h=$1 t=$2; shift 2; timeout "$t" "$SSH" "$h" "$@" 2>&1 | grep --line-buffered -v -E "^Warning: Permanently|^$|Unauthorized access|authorized user, disconnect|System is booting up"; return "${PIPESTATUS[0]}"; }
KO_MD5=$(md5sum "$HERE/mxfs.ko" | cut -c1-32)
MARK="MXFS_CMUR_$(date +%s)"

# mount NODE LOGNAME — the fleet's own per-node join (no format); prints
# prep_rc, the mount's wall and whether it is mounted
join() {
    on $1 200 "mountpoint -q /src || { mkdir -p /src; mount -t nfs 192.168.120.1:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp; }
        echo '$MARK' > /dev/kmsg
        t=\$(date +%s%N); MXFS_DEV=$MXFS_DEV MXFS_KO_MD5=$KO_MD5 timeout 180 bash /src/mxfs/tests/setup/prep_node.sh tcp > /tmp/prep_node_cmur.log 2>&1; rc=\$?
        echo prep_rc=\$rc mount_ms=\$(( (\$(date +%s%N)-t)/1000000 )) mounted=\$(grep -c ' $MNT mxfs ' /proc/mounts)
        tail -3 /tmp/prep_node_cmur.log" > "$EV/$2.log" 2>&1
}
mount_ok() { grep -q "prep_rc=0" "$EV/$1.log" && grep -q "mounted=1" "$EV/$1.log"; }
mount_ms() { grep -o "mount_ms=[0-9]*" "$EV/$1.log" | cut -d= -f2; }

say "arm=$ARM victim=$V peer=$P build=$(modinfo -F srcversion "$HERE/mxfs.ko") evidence=$EV"

# --- 1. fresh cluster, the victim's slice dirty
(cd "$HERE" && ./run.sh 2 tcp prep_cluster) > "$EV/prep_cluster.log" 2>&1 || { tail -20 "$EV/prep_cluster.log"; fail "prep_cluster"; }
on $V 60 "mkdir -p $MNT/cmur && for i in \$(seq 1 500); do echo \$i > $MNT/cmur/f\$i; done; ls $MNT/cmur | wc -l" > "$EV/write_$V.log"
[ "$(tail -1 "$EV/write_$V.log")" = 500 ] || fail "writing 500 files on $V"
# the device is whatever prep_cluster mounted, never assumed: the rig's
# nodes carry more than one LUN (sda is a separate bench target)
# by its wwn link, which survives the victim's reboot re-enumerating sdX
MXFS_DEV=$(on $V 10 "d=\$(findmnt -n -o SOURCE $MNT); for l in \$(udevadm info -q symlink \$d); do case \$l in disk/by-id/wwn-*) echo /dev/\$l; break ;; esac; done" | tail -1)
case "$MXFS_DEV" in /dev/*) ;; *) fail "cannot read the device under $MNT on $V: '$MXFS_DEV'" ;; esac
say "the cluster's device: $MXFS_DEV"
on $V 10 "sync -f $MNT/cmur" >/dev/null

# --- 2. the peer leaves cleanly
on $P 160 "timeout 150 umount $MNT; echo umount_rc=\$?; grep -c ' $MNT mxfs ' /proc/mounts" > "$EV/umount_$P.log"
grep -q "umount_rc=0" "$EV/umount_$P.log" || fail "$P did not unmount cleanly: $(tr '\n' ' ' < "$EV/umount_$P.log")"
say "$P unmounted cleanly"
on $P 20 "sg_persist --in --read-keys $MXFS_DEV" > "$EV/keys_after_peer_umount.log"
say "PR keys after $P's clean unmount: $(tr -s ' \n' ' ' < "$EV/keys_after_peer_umount.log" | cut -c1-200)"

# --- 3. the victim dies 1 s into its unmount (CRASH_AT=mounted: while
# still mounted and idle, the control)
if [ "${CRASH_AT:-umount}" = umount ]; then
    on $V 10 "nohup setsid umount $MNT > /dev/null 2>&1 < /dev/null &" >/dev/null
    sleep 1
fi
$VIRSH destroy $V > /dev/null || fail "virsh destroy $V"
say "$V destroyed (CRASH_AT=${CRASH_AT:-umount})"
sleep 3
$VIRSH start $V > /dev/null || fail "virsh start $V"
t0=$(date +%s); up=0
while [ $(( $(date +%s) - t0 )) -lt $BOOT_S ]; do
    on $V 10 "test ! -e /run/nologin && echo up" | grep -q up && { up=1; break; }
    sleep 3
done
[ $up = 1 ] || fail "$V did not finish booting within ${BOOT_S} s"
say "$V booted in $(( $(date +%s) - t0 )) s"
on $P 20 "sg_persist --in --read-keys $MXFS_DEV" > "$EV/keys_before_remount.log"
say "PR keys before the remount: $(tr -s ' \n' ' ' < "$EV/keys_before_remount.log" | cut -c1-200)"
# what the platter holds before any recovery runs: the peer is unmounted, so
# a read-only chk from it sees the crashed node's written-back state
census() {
    on $P 90 "/src/mxfs/tools/chk_mxfs $MXFS_DEV; echo chk_rc=\$?" > "$EV/census_$1.log" 2>&1
    say "platter $1: $(grep -E 'Allocated inodes|Superblock icount|chk_rc' "$EV/census_$1.log" | tr -s ' \n' ' ')"
}
census before_recovery

# --- 4. remount
v=PASS
if [ "$ARM" = alone ]; then
    join $V remount_$V
    say "$V alone: $(tr '\n' ' ' < "$EV/remount_$V.log" | cut -c1-200)"
    mount_ok remount_$V || v=FAIL
    [ "$(mount_ms remount_$V)" -le $((MOUNT_S * 1000)) ] 2>/dev/null || { say "$V's mount took $(mount_ms remount_$V) ms, over ${MOUNT_S} s"; v=FAIL; }
    join $P remount_$P
    say "$P after: $(tr '\n' ' ' < "$EV/remount_$P.log" | cut -c1-200)"
    mount_ok remount_$P || v=FAIL
else
    join $V remount_$V & jv=$!
    join $P remount_$P & jp=$!
    wait $jv; wait $jp
    for h in $V $P; do
        say "$h together: $(tr '\n' ' ' < "$EV/remount_$h.log" | cut -c1-200)"
        mount_ok remount_$h || v=FAIL
        [ "$(mount_ms remount_$h)" -le $((MOUNT_S * 1000)) ] 2>/dev/null || { say "$h's mount took $(mount_ms remount_$h) ms, over ${MOUNT_S} s"; v=FAIL; }
    done
fi

# --- 5. the victim's data, then a clean check
for h in $V $P; do
    on $h 30 "dmesg | sed -n '/$MARK/,\$p'" > "$EV/dmesg_$h.log"
    grep -a -h -E "P306-LURESET-ADMIT|P308-LURESET-FENCE|foreign replay|RECOVERY-COMPLETE|P-BOOT-MOUNT-REFUSED|P-BOOT-RESCAN|Ending clean mount|P-FRSTAB|BUG:|Oops" "$EV/dmesg_$h.log" | cut -c1-200 | awk -v h=$h '{print "  " h ": " $0}' | tail -12
done
n=$(on $P 30 "ls $MNT/cmur 2>/dev/null | wc -l")
say "files seen on $P after recovery: $n"
[ "$n" = 500 ] || v=FAIL
for h in $V $P; do on $h 160 "timeout 150 umount $MNT; echo umount_rc=\$?" > "$EV/final_umount_$h.log"; done
census after_recovery
grep -q "chk_rc=0" "$EV/census_after_recovery.log" || v=FAIL
grep -a -q -E "BUG:|Oops" "$EV"/dmesg_*.log && v=FAIL
say "RESULT $v"
[ $v = PASS ]
