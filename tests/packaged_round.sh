#!/bin/bash
#
# packaged_round.sh — install a release build on a platform's verification
# pair as a user would, and run the checks its platform record lists.
#
# A release may only claim a platform the exact build was verified on
# (tools/platforms.py check).  The rig loads mxfs.ko by insmod from the source
# tree; a user installs a package whose DKMS hook compiles the module against
# their own kernel.  This round is the second path, end to end:
#
#   1. install     the package(s) from dist/<version>/; DKMS builds the module
#                  on the node's kernel; the loaded module must be that build
#   2. format      free the QNAP LUN (rig nodes unmounted), clear stale PR
#                  keys, mkfs.mxfs from node A
#   3. mount       no options, both nodes (multicast discovery)
#   4. checksums   64 MiB written on each node, md5 read on the other
#   5. create/rm   500 files created on A, counted and removed on B, 0 on A
#   6. chk_mxfs    both unmounted, chk_mxfs on A exits 0
#   7. peer=       multicast dropped on both, mount -o peer=<the other>,
#                  cross-node checksum, multicast restored
#  7b. pve         peers=A/B on both, checksums; a DKMS build for every kernel
#                  in /lib/modules; pvesm add/status/remove holds one mount
#   8. dio        an O_DIRECT read on a stable-writes device
#                  (tests/dio_stable_writes_read.sh)
#   9. selinux     (alma) SELinux enforcing: labels on new files, restorecon,
#                  no AVC denials since boot
#  10. reboot      a marker written and unmounted, both nodes rebooted: module
#                  auto-loaded, iSCSI back, mount, marker md5 intact
#
# Pairs: ubuntu = test3/test4 (Ubuntu 24.04), pve = pve9-1/pve9-2 (PVE 9),
# alma = alma9-1/alma9-2 (AlmaLinux 9.8, firewalld on, SELinux enforcing).
#
# Budgets (a step over budget FAILS the round):
#   INSTALL_S  DKMS compiles the whole module on the node.  The same compile
#              takes 48 s wall on the 56-core rig host, at most 45 core-minutes;
#              on a 4-vCPU guest that is 11 min, the ceiling -> 660 s.
#   MOUNT_S    an idle 2-node TCP mount measured ~5 s on the QNAP; x2 plus the
#              mount-time peer wait -> 60 s per mount.
#   IO_S       64 MiB each way plus 500 creates (7.5 s measured on alma) -> 60 s.
#   CHK_S      chk_mxfs of the 50 GiB LUN -> 60 s.
#   REBOOT_S   Ubuntu 24.04 logged in to the LUN takes ~3 min to reboot whether
#              or not mxfs is loaded (lvm2-monitor, platforms.json note) -> 420 s.
#
# Usage: [KERNEL=<krel>] tests/packaged_round.sh <ubuntu|pve|alma> [version]
#   version defaults to VERSION; the packages come from dist/<version>/.
#   KERNEL (pve only): pin that installed kernel with proxmox-boot-tool, reboot
#   into it, and run the round there, its reboot step included; unpinned when
#   the round ends.  A release claims kernels, so each claimed kernel is a round.
#   Evidence: tests/evidence/packaged_round/<platform>_<version>_<stamp>/.
#   Exit 0 only if every step passed.  The pair is left unmounted.
#
set -u

PLAT="${1:?usage: packaged_round.sh <ubuntu|pve|alma> [version]}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
V="${2:-$(cat "$HERE/VERSION")}"
KERNEL="${KERNEL:-}"
DIST="$HERE/dist/$V"
SSH="$HERE/tools/mxfs_sshpass.sh"
VIRSH="virsh -c qemu:///system"
MNT=/mnt/mxfs
QNAP_PORTAL=192.168.1.4
QNAP_TGT="iqn.2004-04.com.qnap:ts-453pro:iscsi.target-0.f35772"
LUN=/dev/disk/by-id/wwn-0x6e843b6393a5a6ed918bd4f4fdb8e7d6
INSTALL_S=660
MOUNT_S=60
IO_S=60
CHK_S=60
REBOOT_S=420

case "$PLAT" in
    ubuntu) A=test3;   B=test4;   PKGS="mxfs_${V}_amd64.deb" ;;
    pve)    A=pve9-1;  B=pve9-2;  PKGS="mxfs_${V}_amd64.deb pve-storage-mxfs_${V}_all.deb" ;;
    alma)   A=alma9-1; B=alma9-2; PKGS="mxfs-${V}-1.el8.x86_64.rpm" ;;
    *) echo "platform must be ubuntu|pve|alma" >&2; exit 2 ;;
esac

EV="$HERE/tests/evidence/packaged_round/${PLAT}_${V}_$(date +%Y%m%dT%H%M%S)"
mkdir -p "$EV"
exec > >(tee -a "$EV/run.log") 2>&1
say() { echo "[$(date +%T)] $*"; }
FAILS=0
pass() { say "PASS: $*"; }
fail() { say "FAIL: $*"; FAILS=$((FAILS + 1)); }
die() { say "FAIL: $* — round stopped"; say "RESULT FAIL ($((FAILS + 1)) failed)"; exit 1; }

# A node's IPv4 address: peer= and peers= take addresses only, never names
# (the mount refuses "'test4' is not a unicast IPv4 address").
addr() { local a
         case $1 in pve9-1) echo 192.168.120.194 ;; pve9-2) echo 192.168.120.138 ;;
                    alma9-1) echo 192.168.120.100 ;; alma9-2) echo 192.168.120.157 ;;
                    *) a=$(getent ahostsv4 "$1" | awk 'NR == 1 {print $1}'); echo "${a:-$1}" ;; esac; }
# on HOST SECONDS CMD — output to stdout, rc of the remote command (124 = over budget)
# (pam_nologin's banner prefixes every reply while a node is still booting)
on() { local h t=$2; h=$(addr "$1"); shift 2; timeout "$t" "$SSH" "$h" "$@" 2>&1 | grep --line-buffered -v -E "^Warning: Permanently|^$|Unauthorized access|authorized user, disconnect|System is booting up\. Unprivileged users"; return "${PIPESTATUS[0]}"; }
# both CMD-NAME SECONDS CMD — run on A and B in parallel, each into its own file
both() {
    local name=$1 t=$2 cmd=$3 pa pb ra rb
    on $A "$t" "$cmd" > "$EV/${name}_$A.log" 2>&1 & pa=$!
    on $B "$t" "$cmd" > "$EV/${name}_$B.log" 2>&1 & pb=$!
    wait $pa; ra=$?; wait $pb; rb=$?
    echo "rc=$ra" >> "$EV/${name}_$A.log"; echo "rc=$rb" >> "$EV/${name}_$B.log"
    [ $ra = 0 ] && [ $rb = 0 ]
}
now() { date +%s.%N; }
since() { awk -v a="$1" -v b="$(now)" 'BEGIN{printf "%.1f", b - a}'; }
reboot_pair() {  # reboot A and B and wait until both answer again
    local t0 h ok
    t0=$(now)
    both reboot 15 "systemctl reboot" || true
    sleep 20
    for h in $A $B; do
        ok=0
        while [ "$(awk -v a="$t0" -v b="$(now)" 'BEGIN{print int(b - a)}')" -lt $REBOOT_S ]; do
            on $h 10 true >/dev/null 2>&1 && { ok=1; break; }
            sleep 5
        done
        [ $ok = 1 ] || die "$h did not come back within ${REBOOT_S} s"
        say "$h answering $(since $t0) s after reboot"
        # sshd answering is not boot finished: until systemd clears
        # /run/nologin, every ssh command's output starts with its banner
        # ("System is booting up..."), which read as a wrong marker md5
        ok=0
        while [ "$(awk -v a="$t0" -v b="$(now)" 'BEGIN{print int(b - a)}')" -lt $REBOOT_S ]; do
            on $h 10 "test ! -e /run/nologin" >/dev/null 2>&1 && { ok=1; break; }
            sleep 3
        done
        [ $ok = 1 ] || die "$h did not finish booting (/run/nologin) within ${REBOOT_S} s"
        say "$h booted $(since $t0) s after reboot"
    done
}

# What the round changes on the nodes is undone on every exit, die included: a
# multicast block left behind made the NEXT round's no-option mount fail to
# find its peer, and a kernel pin would keep the nodes off their default kernel.
MCAST_BLOCKED=0
PINNED=0
cleanup() {
    [ $MCAST_BLOCKED = 1 ] && { both mcast_unblock 20 "$unblk" || say "WARN: restoring multicast failed"; }
    [ $PINNED = 1 ] && { both unpin 30 "proxmox-boot-tool kernel unpin" || say "WARN: unpinning $KERNEL failed"; }
}
trap cleanup EXIT

say "platform=$PLAT pair=$A/$B version=$V evidence=$EV"
say "host load: $(cat /proc/loadavg)"
for p in $PKGS; do [ -f "$DIST/$p" ] || die "missing $DIST/$p"; done
(cd "$DIST" && sha256sum -c --ignore-missing SHA256SUMS) > "$EV/sha256_clyde.log" 2>&1 || die "dist/$V does not match its SHA256SUMS"
for p in $PKGS; do grep -q "$p: OK" "$EV/sha256_clyde.log" || die "$p is not covered by SHA256SUMS"; done
pass "packages match SHA256SUMS: $PKGS"

# --- 0. both nodes answering and done booting, on KERNEL when one is named
for h in $A $B; do
    t0=$(now); ok=0
    while [ "$(awk -v a="$t0" -v b="$(now)" 'BEGIN{print int(b - a)}')" -lt $REBOOT_S ]; do
        on $h 10 "test ! -e /run/nologin" >/dev/null 2>&1 && { ok=1; break; }
        sleep 3
    done
    [ $ok = 1 ] || die "$h is not answering, or did not finish booting within ${REBOOT_S} s"
done
for h in $A $B; do
    on $h 15 "uname -r; cat /etc/os-release | grep PRETTY_NAME" > "$EV/os_$h.log" || die "$h is not answering over ssh"
    say "$h: $(tr '\n' ' ' < "$EV/os_$h.log")"
done
if [ -n "$KERNEL" ] && ! { grep -qx "$KERNEL" "$EV/os_$A.log" && grep -qx "$KERNEL" "$EV/os_$B.log"; }; then
    [ "$PLAT" = pve ] || die "KERNEL= selects a kernel only on pve (proxmox-boot-tool)"
    PINNED=1
    both pin 30 "proxmox-boot-tool kernel pin $KERNEL" || die "pinning $KERNEL"
    reboot_pair
    for h in $A $B; do
        on $h 15 "uname -r; cat /etc/os-release | grep PRETTY_NAME" > "$EV/os_$h.log" || die "$h is not answering over ssh"
        grep -qx "$KERNEL" "$EV/os_$h.log" || die "$h booted $(head -1 "$EV/os_$h.log"), not $KERNEL"
        say "$h: $(tr '\n' ' ' < "$EV/os_$h.log")"
    done
fi
pass "both nodes on kernel $(head -1 "$EV/os_$A.log")"

# --- 1. install
for h in $A $B; do
    for p in $PKGS; do "$SSH" "$(addr $h)" SCP "$DIST/$p" /root/ > /dev/null 2>&1 || die "scp $p to $h"; done
done
files=""; for p in $PKGS; do files="$files /root/$p"; done
case "$PLAT" in
    alma) inst="dnf install -y $files" ;;
    *)    inst="DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-downgrades $files" ;;
esac
t0=$(now)
if both install $INSTALL_S "grep -q ' mxfs ' /proc/mounts && umount $MNT; modprobe -r mxfs 2>/dev/null; $inst"; then
    pass "install on both ($(since $t0) s)"
else
    die "install (see $EV/install_*.log; rc 124 = over the ${INSTALL_S} s budget)"
fi
# The module declares no MODULE_VERSION, so which build is loaded is read by
# srcversion: the loaded module's must be the installed file's, and that must
# be the one DKMS built for $V on the running kernel.
MODID="echo path=\$(modinfo -n mxfs)
    echo srcversion=\$(cat /sys/module/mxfs/srcversion 2>/dev/null)
    echo modinfo_srcversion=\$(modinfo -F srcversion mxfs)
    echo dkms_srcversion=\$(modinfo -F srcversion /var/lib/dkms/mxfs/$V/\$(uname -r)/\$(uname -m)/module/mxfs.ko* 2>/dev/null)
    echo dkms=\$(dkms status mxfs/$V -k \$(uname -r) 2>&1)"
# the loaded module on HOST (from LOG) is the DKMS build of $V
is_dkms_build() {
    local s1 s2 s3
    s1=$(sed -n 's/^srcversion=//p' "$2"); s2=$(sed -n 's/^modinfo_srcversion=//p' "$2")
    s3=$(sed -n 's/^dkms_srcversion=//p' "$2")
    [ -n "$s1" ] && [ "$s1" = "$s2" ] && [ "$s1" = "$s3" ] && grep -q "^dkms=.*: installed" "$2" \
        || { say "$1: loaded srcversion '$s1', installed '$s2', DKMS $V '$s3'; $(grep '^dkms=' "$2")"; return 1; }
    say "$1: $(grep path= "$2") srcversion=$s1"
}
both modload 30 "modprobe mxfs; $MODID" || die "modprobe mxfs"
for h in $A $B; do is_dkms_build $h "$EV/modload_$h.log" || die "$h did not load the DKMS build of $V"; done
pass "the DKMS-built module is loaded on both"

# --- 2. free the LUN and format
for h in test1 test2 test3 test4 pve9-1 pve9-2 alma9-1 alma9-2; do
    case " $A $B " in *" $h "*) continue ;; esac
    if [ "${h#test}" != "$h" ] || [ "${h#pve9}" != "$h" ]; then
        $VIRSH domstate $h 2>/dev/null | grep -q running || continue
    else
        on $h 5 true >/dev/null 2>&1 || continue
    fi
    on $h 60 "for m in \$(awk '\$3 == \"mxfs\" {print \$2}' /proc/mounts); do timeout 30 umount \$m; done; grep -c ' mxfs ' /proc/mounts; true" > "$EV/free_lun_$h.log"
    [ "$(tail -1 "$EV/free_lun_$h.log")" = 0 ] || die "$h still has MXFS mounted; the LUN is not free"
done
both lun 60 "
    iscsiadm -m session 2>/dev/null | grep -q f35772 || iscsiadm -m node -T $QNAP_TGT -p $QNAP_PORTAL --login >/dev/null 2>&1 || { iscsiadm -m discovery -t st -p $QNAP_PORTAL >/dev/null && iscsiadm -m node -T $QNAP_TGT -p $QNAP_PORTAL --login >/dev/null; }
    # log in again at boot, as a host with a persistent shared LUN is set up;
    # a discovered node record defaults to manual on Debian and Proxmox
    iscsiadm -m node -T $QNAP_TGT -p $QNAP_PORTAL -o update -n node.startup -v automatic
    echo startup=\$(iscsiadm -m node -T $QNAP_TGT -p $QNAP_PORTAL | sed -n 's/^node.startup = //p')
    for i in \$(seq 1 10); do [ -b $LUN ] && break; sleep 1; done
    [ -b $LUN ] && echo lun_ok; mkdir -p $MNT" || die "QNAP LUN not present on both"
for h in $A $B; do grep -q "^startup=automatic" "$EV/lun_$h.log" || die "$h: the QNAP target is not set to log in at boot"; done
on $A 30 "sg_persist --in --read-keys $LUN; sg_persist --out --register --param-sark=0x4d58465352455431 $LUN >/dev/null 2>&1; sg_persist --out --clear --param-rk=0x4d58465352455431 $LUN >/dev/null 2>&1; sg_persist --in --read-keys $LUN" > "$EV/pr_clear_$A.log" 2>&1
grep -q "NO registered reservation keys" "$EV/pr_clear_$A.log" || die "stale PR keys remain on the LUN (see pr_clear_$A.log)"
on $A 120 "mkfs.mxfs -f $LUN; echo mkfs_rc=\$?" > "$EV/mkfs_$A.log" 2>&1
grep -q "mkfs_rc=0" "$EV/mkfs_$A.log" && pass "mkfs.mxfs" || die "mkfs.mxfs (see mkfs_$A.log)"

# --- 3. mount with no options
mount_pair() {  # label opts-for-A opts-for-B
    local t0 lbl=$1
    t0=$(now)
    on $A $MOUNT_S "mount -t mxfs ${2:+-o $2} $LUN $MNT; echo mount_rc=\$?" > "$EV/${lbl}_mount_$A.log" 2>&1
    on $B $MOUNT_S "mount -t mxfs ${3:+-o $3} $LUN $MNT; echo mount_rc=\$?" > "$EV/${lbl}_mount_$B.log" 2>&1
    if grep -q mount_rc=0 "$EV/${lbl}_mount_$A.log" && grep -q mount_rc=0 "$EV/${lbl}_mount_$B.log"; then
        pass "$lbl: both mounted ($(since $t0) s)"
    else
        die "$lbl mount (see ${lbl}_mount_*.log)"
    fi
}
umount_pair() {
    both "$1_umount" 60 "timeout 30 umount $MNT; grep -c ' $MNT mxfs ' /proc/mounts; true" || fail "$1: umount"
    for h in $A $B; do grep -qx 0 "$EV/$1_umount_$h.log" || fail "$1: $h still mounted"; done
}
xsum() {  # label: 64 MiB written on each node, md5 compared from the other
    local lbl=$1 x y ok=1 t0
    t0=$(now)
    for pair in "$A $B" "$B $A"; do
        set -- $pair
        x=$(on $1 $IO_S "head -c 67108864 /dev/urandom > $MNT/$lbl.$1 && sync && md5sum < $MNT/$lbl.$1 | cut -d' ' -f1")
        y=$(on $2 $IO_S "md5sum < $MNT/$lbl.$1 | cut -d' ' -f1")
        echo "$lbl written on $1: $x read on $2: $y" >> "$EV/${lbl}_xsum.log"
        [ -n "$x" ] && [ "$x" = "$y" ] || ok=0
    done
    [ $ok = 1 ] && pass "$lbl: cross-node checksums match ($(since $t0) s)" || fail "$lbl: cross-node checksum (see ${lbl}_xsum.log)"
}
mount_pair plain "" ""
dmesg_line=$(on $A 10 "dmesg | grep -E 'MXFS-MEMBERSHIP|members=' | tail -1"); echo "$dmesg_line" > "$EV/plain_membership_$A.log"

# --- 4/5. checksums, create and remote delete
xsum plain
t0=$(now)
on $A $IO_S "mkdir $MNT/many && for i in \$(seq 1 500); do echo \$i > $MNT/many/f\$i; done; sync; ls $MNT/many | wc -l" > "$EV/create_$A.log" 2>&1
nb=$(on $B $IO_S "ls $MNT/many | wc -l; rm -f $MNT/many/f*; ls $MNT/many | wc -l" 2>&1 | tr '\n' ' ')
na=$(on $A $IO_S "ls $MNT/many | wc -l")
echo "created on $A: $(tail -1 "$EV/create_$A.log"); on $B before/after rm: $nb; on $A after: $na" | tee "$EV/create_rm.log"
[ "$(tail -1 "$EV/create_$A.log")" = 500 ] && [ "$nb" = "500 0 " ] && [ "$na" = 0 ] \
    && pass "500 created on $A, removed on $B, 0 left on $A ($(since $t0) s)" || fail "create/remote delete (see create_rm.log)"

# --- 6. chk_mxfs
umount_pair plain
on $A $CHK_S "chk_mxfs $LUN; echo chk_rc=\$?" > "$EV/chk_$A.log" 2>&1
grep -q "chk_rc=0" "$EV/chk_$A.log" && pass "chk_mxfs clean" || fail "chk_mxfs (see chk_$A.log)"

# --- 7. peer= with multicast dropped
case "$PLAT" in
    alma) blk="firewall-cmd --direct --add-rule ipv4 filter INPUT 0 -d 224.0.0.0/4 -j DROP && firewall-cmd --direct --add-rule ipv4 filter OUTPUT 0 -d 224.0.0.0/4 -j DROP"
          unblk="firewall-cmd --direct --remove-rule ipv4 filter INPUT 0 -d 224.0.0.0/4 -j DROP; firewall-cmd --direct --remove-rule ipv4 filter OUTPUT 0 -d 224.0.0.0/4 -j DROP" ;;
    *)    blk="iptables -I INPUT -d 224.0.0.0/4 -j DROP && iptables -I OUTPUT -d 224.0.0.0/4 -j DROP"
          unblk="iptables -D INPUT -d 224.0.0.0/4 -j DROP; iptables -D OUTPUT -d 224.0.0.0/4 -j DROP" ;;
esac
MCAST_BLOCKED=1
both mcast_block 20 "$blk" || die "blocking multicast"
mount_pair peer "peer=$(addr $B)" "peer=$(addr $A)"
xsum peer
umount_pair peer
both mcast_unblock 20 "$unblk" && MCAST_BLOCKED=0 || fail "restoring multicast"

# --- 7b. Proxmox: peers=, the storage plugin, DKMS on every installed kernel
if [ "$PLAT" = pve ]; then
    mount_pair peers "peers=$(addr $A)/$(addr $B)" "peers=$(addr $A)/$(addr $B)"
    xsum peers
    umount_pair peers
    both dkms 30 "dkms status mxfs; ls /lib/modules" || fail "dkms status"
    for h in $A $B; do
        for k in $(on $h 10 "ls /lib/modules"); do
            grep -q "mxfs/$V, $k, x86_64: installed" "$EV/dkms_$h.log" || fail "$h: no DKMS build of $V for installed kernel $k"
        done
    done
    SNAME=mxfs-round
    on $A 60 "pvesm add mxfs $SNAME --blockdevice $LUN --path /mnt/pve/$SNAME --shared 1 --content images,rootdir; echo add_rc=\$?
        pvesm status --storage $SNAME; echo status_rc=\$?
        echo after_add=\$(grep -c ' /mnt/pve/$SNAME mxfs ' /proc/mounts)
        pvesm remove $SNAME; echo remove_rc=\$?
        grep -q ' /mnt/pve/$SNAME mxfs ' /proc/mounts && timeout 30 umount /mnt/pve/$SNAME
        echo after_remove=\$(grep -c ' /mnt/pve/$SNAME mxfs ' /proc/mounts)" > "$EV/pvesm_$A.log" 2>&1
    grep -q "add_rc=0" "$EV/pvesm_$A.log" && grep -q "status_rc=0" "$EV/pvesm_$A.log" && grep -q "remove_rc=0" "$EV/pvesm_$A.log" \
        || fail "pvesm add/status/remove (see pvesm_$A.log)"
    grep -q "after_add=1" "$EV/pvesm_$A.log" || fail "pvesm add did not hold exactly one mount (see pvesm_$A.log)"
    grep -q "after_remove=0" "$EV/pvesm_$A.log" || fail "a mount is left after pvesm remove (see pvesm_$A.log)"
    pass "Proxmox checks ran (failures above, if any)"
fi

# --- 8. O_DIRECT read on a stable-writes device
mount_pair dio "" ""
"$HERE/tests/dio_stable_writes_read.sh" "$(addr $A)" $MNT 64 > "$EV/dio_stable_writes_$A.log" 2>&1
grep -q "RESULT PASS" "$EV/dio_stable_writes_$A.log" && pass "O_DIRECT read with stable writes" || die "O_DIRECT read with stable writes (see dio_stable_writes_$A.log)"

# --- 9. SELinux
if [ "$PLAT" = alma ]; then
    # A new filesystem's root carries no label until restorecon gives it one,
    # exactly as on XFS; new files then inherit from their directory.  Both
    # nodes remount after the relabel so neither holds the root's old label.
    on $A 30 "echo root_before=\$(stat -c %C $MNT); restorecon -v $MNT; echo root_after=\$(stat -c %C $MNT)" > "$EV/selinux_root_$A.log" 2>&1
    umount_pair dio
    mount_pair selinux "" ""
    both selinux 60 "
        echo enforce=\$(getenforce)
        echo module=\$(semodule -l | grep -x mxfs)
        echo root=\$(stat -c %C $MNT)
        f=$MNT/selinux.\$(hostname -s); echo x > \$f
        echo new_file=\$(stat -c %C \$f)
        chcon -t virt_image_t \$f && echo chcon=\$(stat -c %C \$f)
        echo avc=\$(ausearch -m avc,user_avc,selinux_err -ts boot 2>&1 | grep -c 'type=AVC')" || fail "selinux commands"
    for h in $A $B; do
        grep -q "enforce=Enforcing" "$EV/selinux_$h.log" || fail "$h: SELinux is not enforcing"
        grep -q "module=mxfs" "$EV/selinux_$h.log" || fail "$h: the mxfs SELinux module is not installed"
        grep -q "root=.*unlabeled_t" "$EV/selinux_$h.log" && fail "$h: the relabeled root reads unlabeled_t"
        grep -q "new_file=.*unlabeled_t" "$EV/selinux_$h.log" && fail "$h: a new file is unlabeled_t"
        grep -q "chcon=.*virt_image_t" "$EV/selinux_$h.log" || fail "$h: chcon to virt_image_t did not stick"
        grep -q "avc=0" "$EV/selinux_$h.log" || fail "$h: AVC denials since boot"
    done
    # A's relabel as B sees it: at once, and after B drops its caches
    fa=$MNT/selinux.$(on $A 5 'hostname -s')
    lb1=$(on $B 20 "stat -c %C $fa")
    lb2=$(on $B 20 "echo 3 > /proc/sys/vm/drop_caches; stat -c %C $fa")
    echo "$A's virt_image_t file as seen from $B: at once $lb1, after drop_caches $lb2" | tee "$EV/selinux_cross.log"
    say "SELinux: $(tr '\n' ' ' < "$EV/selinux_root_$A.log") $(grep -h 'root=\|new_file=' "$EV/selinux_$A.log" | tr '\n' ' ')"
    case "$lb2" in *virt_image_t*) ;; *) fail "$B does not read $A's label from the platter" ;; esac
    pass "SELinux checks ran (failures above, if any)"
    DIO_OR_SELINUX=selinux
else
    DIO_OR_SELINUX=dio
fi

# --- 10. reboot
x=$(on $A $IO_S "head -c 16777216 /dev/urandom > $MNT/marker && sync && md5sum < $MNT/marker | cut -d' ' -f1")
[ -n "$x" ] || fail "writing the marker"
umount_pair $DIO_OR_SELINUX
reboot_pair
both postboot 60 "
    echo kernel=\$(uname -r)
    echo module=\$(lsmod | grep -c '^mxfs ')
    $MODID
    for i in \$(seq 1 30); do [ -b $LUN ] && break; sleep 1; done; [ -b $LUN ] && echo lun=ok
    command -v firewall-cmd >/dev/null && echo firewalld=\$(systemctl is-active firewalld) ports=\$(firewall-cmd --list-ports | tr ' ' ,)
    true" || fail "postboot checks"
for h in $A $B; do
    [ -z "$KERNEL" ] || grep -qx "kernel=$KERNEL" "$EV/postboot_$h.log" || fail "$h did not boot back into $KERNEL"
    grep -q "module=1" "$EV/postboot_$h.log" || fail "$h: module not auto-loaded"
    is_dkms_build $h "$EV/postboot_$h.log" || fail "$h: the module auto-loaded at boot is not the DKMS build of $V"
    grep -q "lun=ok" "$EV/postboot_$h.log" || fail "$h: LUN not back after boot"
done
mount_pair postboot "" ""
ya=$(on $A $IO_S "md5sum < $MNT/marker | cut -d' ' -f1"); yb=$(on $B $IO_S "md5sum < $MNT/marker | cut -d' ' -f1")
echo "marker before reboot $x, after: $A $ya $B $yb" | tee "$EV/marker.log"
[ "$x" = "$ya" ] && [ "$x" = "$yb" ] && pass "data intact across the reboot" || fail "marker md5 after reboot"
umount_pair postboot

if [ $FAILS = 0 ]; then say "RESULT PASS"; exit 0; fi
say "RESULT FAIL ($FAILS failed)"
exit 1
