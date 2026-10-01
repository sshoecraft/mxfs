#!/bin/bash
#
# packaged_round.sh — install a release build on a platform's verification
# nodes as a user would, and run the checks its platform record lists.
#
# A release may only claim a platform the exact build was verified on
# (tools/platforms.py check).  The rig loads mxfs.ko by insmod from the source
# tree; a user installs a package whose DKMS hook compiles the module against
# their own kernel.  This round is the second path, end to end, on every node
# of the platform's verification set (the lab file's `nodes` line; a `pair`
# line is a set of two).  A is the set's first node, B its second:
#
#   1. install     the package(s) from dist/<version>/ on every node; DKMS
#                  builds the module on the node's kernel; the loaded module
#                  must be that build
#   2. format      free the shared LUN (every other node on it unmounted), clear stale PR
#                  keys, mkfs.mxfs from node A
#   3. mount       no options, every node (multicast discovery), A first
#   4. checksums   64 MiB written on each node, md5 read on every other node
#   5. create/rm   500 files created on A, counted and removed on B, 0 on
#                  every node afterwards
#   6. chk_mxfs    all unmounted, chk_mxfs on A exits 0
#   7. peer=       multicast dropped on every node; two nodes mount with
#                  -o peer=<the other>, a larger set with -o peers=<all>;
#                  cross-node checksums, multicast restored
#  7b. pve         peers=<all> on every node, checksums; a DKMS build for every
#                  kernel in /lib/modules; pvesm add/status/remove holds one mount
#   8. dio        an O_DIRECT read on a stable-writes device
#                  (tests/dio_stable_writes_read.sh)
#   9. selinux     (rhel*) SELinux enforcing: labels on new files, restorecon,
#                  no AVC denials since boot, A's label read from every peer
#  10. reboot      a marker written and unmounted, every node rebooted: module
#                  auto-loaded, iSCSI back, mount, marker md5 intact everywhere
#
# The platform is a data/platforms.json key.  Which nodes verify it, their
# addresses and the shared LUN are this site's own, read from the lab file
# (tools/mxfs_lab.sh); how to build the nodes is in lab/README.md.  The
# package family follows the key: pve* installs the .deb and the Proxmox
# plugin, rhel* the .rpm (firewalld on, SELinux enforcing), debian*/ubuntu*
# the .deb.
#
# Budgets (a step over budget FAILS the round; each is per operation, so a
# larger set runs more operations, never a looser one):
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
# CONFIG names the configuration the round verifies, <N>/<class>/<method>/<attach>
# (tools/configuration.py).  N must be the size of the platform's verification
# set, since that is how many nodes the round runs on, and the attachment must
# be direct: the round logs every node into the platform's own target by
# in-guest iSCSI, one path, and builds nothing else.  A disk/caw configuration
# runs the round on the CAW transport, configured the way the
# README tells a user to: after the install, force_transport=1 in the
# package's /etc/modprobe.d/mxfs.conf becomes force_transport=0, so the module
# forms the cluster on CAW, and it keeps doing so after the reboot.  Every
# mount must then announce transport=CAW (P-DOMAIN-ADMITTED) on every node, and
# the loaded module must carry force_transport=0.  The file is put back on
# every exit.  The LUN must implement COMPARE AND WRITE (clyde's SCST
# vdisk_fileio targets do).
#
# Usage: CONFIG=<configuration> [KERNEL=<krel>] tests/packaged_round.sh <platform> [version]
#   e.g. CONFIG=8/disk/caw/direct tests/packaged_round.sh rhel9
#   version defaults to VERSION; the packages come from dist/<version>/.
#   KERNEL (pve only): pin that installed kernel with proxmox-boot-tool, reboot
#   into it, and run the round there, its reboot step included; unpinned when
#   the round ends.  A release claims kernels, so each claimed kernel is a round.
#   Evidence: tests/evidence/packaged_round/<platform>_<version>_<class-method-attach>_<stamp>/.
#   Exit 0 only if every step passed.  The nodes are left unmounted.
#
set -u

PLAT="${1:?usage: packaged_round.sh <platform> [version]}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
V="${2:-$(cat "$HERE/VERSION")}"
KERNEL="${KERNEL:-}"
CONFIG=$(python3 "$HERE/tools/configuration.py" parse "${CONFIG:?CONFIG must name the configuration, e.g. CONFIG=8/net/mesh/direct}") || exit 2
eval "$(python3 "$HERE/tools/configuration.py" shell "$CONFIG")"
[ "$CFG_ATTACH" = direct ] || { echo "$CONFIG: the packaged round attaches by in-guest iSCSI (direct); it does not build $CFG_ATTACH" >&2; exit 2; }
TRANSPORT=$CFG_TRANSPORT                      # what the module takes: tcp | caw
case "$TRANSPORT" in
    tcp) FT=1; TNAME=TCP ;;
    caw) FT=0; TNAME=CAW ;;
esac
DIST="$HERE/dist/$V"
SSH="$HERE/tools/mxfs_sshpass.sh"
MNT=/mnt/mxfs
. "$HERE/tools/mxfs_lab.sh"
PORTAL=$(lab_need storage portal) || exit 2
TGT=$(lab_need storage target) || exit 2
LUN=$(lab_need storage lun) || exit 2
NODES=$(lab_nodes "$PLAT") || exit 2
set -- $NODES
A=$1; B=$2; NN=$#
[ "$NN" = "$CFG_NODES" ] || { echo "$CONFIG names $CFG_NODES nodes; $PLAT's verification set is $NN ($NODES)" >&2; exit 2; }
INSTALL_S=660
MOUNT_S=60
IO_S=60
CHK_S=60
REBOOT_S=420

case "$PLAT" in
    pve*)             FAM=pve; PKGS="mxfs_${V}_amd64.deb pve-storage-mxfs_${V}_all.deb" ;;
    rhel*)            FAM=rpm; PKGS="mxfs-${V}-1.el8.x86_64.rpm" ;;
    debian*|ubuntu*)  FAM=deb; PKGS="mxfs_${V}_amd64.deb" ;;
    *) echo "no package family for platform '$PLAT'" >&2; exit 2 ;;
esac

EV="$HERE/tests/evidence/packaged_round/${PLAT}_${V}_${CFG_SHAPE}_$(date +%Y%m%dT%H%M%S)"
mkdir -p "$EV"
exec > >(tee -a "$EV/run.log") 2>&1
say() { echo "[$(date +%T)] $*"; }
FAILS=0
pass() { say "PASS: $*"; }
fail() { say "FAIL: $*"; FAILS=$((FAILS + 1)); }
die() { say "FAIL: $* — round stopped"; say "RESULT FAIL ($((FAILS + 1)) failed)"; exit 1; }

# A node's IPv4 address: peer= and peers= take addresses only, never names
# (the mount refuses "'test4' is not a unicast IPv4 address").
addr() { lab_addr "$1"; }
others() { local x r=""; for x in $NODES; do [ "$x" = "$1" ] || r="$r $x"; done; echo $r; }
all_addrs() { local x r=""; for x in $NODES; do r="$r${r:+/}$(addr $x)"; done; echo "$r"; }
# the mount option that names a node's peers when multicast cannot: two nodes
# name each other (peer=), a larger set names every member (peers=)
peer_opt() {
    local x r=""
    if [ $NN = 2 ]; then
        for x in $(others "$1"); do r="peer=$(addr $x)"; done
    else
        r="peers=$(all_addrs)"
    fi
    echo "$r"
}
# on HOST SECONDS CMD — output to stdout, rc of the remote command (124 = over budget)
# (pam_nologin's banner prefixes every reply while a node is still booting)
on() { local h t=$2; h=$(addr "$1"); shift 2; timeout "$t" "$SSH" "$h" "$@" 2>&1 | grep --line-buffered -v -E "^Warning: Permanently|^$|Unauthorized access|authorized user, disconnect|System is booting up\. Unprivileged users"; return "${PIPESTATUS[0]}"; }
# every CMD-NAME SECONDS CMD — run on every node in parallel, each into its own file
every() {
    local name=$1 t=$2 cmd=$3 h p pids="" r rc=0
    for h in $NODES; do
        on $h "$t" "$cmd" > "$EV/${name}_$h.log" 2>&1 & pids="$pids $h:$!"
    done
    for p in $pids; do
        h=${p%%:*}; wait ${p#*:}; r=$?
        echo "rc=$r" >> "$EV/${name}_$h.log"
        [ $r = 0 ] || rc=1
    done
    return $rc
}
now() { date +%s.%N; }
since() { awk -v a="$1" -v b="$(now)" 'BEGIN{printf "%.1f", b - a}'; }
reboot_all() {  # reboot every node and wait until each answers again
    local t0 h ok
    t0=$(now)
    every reboot 15 "systemctl reboot" || true
    sleep 20
    for h in $NODES; do
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
CONF_CAW=0
MODCONF=/etc/modprobe.d/mxfs.conf
cleanup() {
    [ $MCAST_BLOCKED = 1 ] && { every mcast_unblock 20 "$unblk" || say "WARN: restoring multicast failed"; }
    [ $CONF_CAW = 1 ] && { every conf_restore 20 "sed -i 's/^options mxfs force_transport=0\$/options mxfs force_transport=1/' $MODCONF" || say "WARN: restoring force_transport=1 in $MODCONF failed"; }
    [ $PINNED = 1 ] && { every unpin 30 "proxmox-boot-tool kernel unpin" || say "WARN: unpinning $KERNEL failed"; }
}
trap cleanup EXIT

say "platform=$PLAT nodes=$NODES version=$V configuration=$CONFIG transport=$TRANSPORT evidence=$EV"
say "host load: $(cat /proc/loadavg)"
for p in $PKGS; do [ -f "$DIST/$p" ] || die "missing $DIST/$p"; done
(cd "$DIST" && sha256sum -c --ignore-missing SHA256SUMS) > "$EV/sha256_clyde.log" 2>&1 || die "dist/$V does not match its SHA256SUMS"
for p in $PKGS; do grep -q "$p: OK" "$EV/sha256_clyde.log" || die "$p is not covered by SHA256SUMS"; done
pass "packages match SHA256SUMS: $PKGS"

# --- 0. every node answering and done booting, on KERNEL when one is named
for h in $NODES; do
    t0=$(now); ok=0
    while [ "$(awk -v a="$t0" -v b="$(now)" 'BEGIN{print int(b - a)}')" -lt $REBOOT_S ]; do
        on $h 10 "test ! -e /run/nologin" >/dev/null 2>&1 && { ok=1; break; }
        sleep 3
    done
    [ $ok = 1 ] || die "$h is not answering, or did not finish booting within ${REBOOT_S} s"
done
for h in $NODES; do
    on $h 15 "uname -r; cat /etc/os-release | grep PRETTY_NAME" > "$EV/os_$h.log" || die "$h is not answering over ssh"
    say "$h: $(tr '\n' ' ' < "$EV/os_$h.log")"
done
# A named kernel is pinned for the whole round even when the nodes already run
# it: the round reboots again later, and an unpinned node comes back on its
# default kernel.  Measured 0.90.6: the 6.17 TCP round pinned, unpinned at its
# exit and left both nodes on 6.17, so the 6.17 CAW round skipped the pin and
# its reboot check found both on 7.0.
if [ -n "$KERNEL" ]; then
    [ $FAM = pve ] || die "KERNEL= selects a kernel only on Proxmox (proxmox-boot-tool)"
    PINNED=1
    every pin 30 "proxmox-boot-tool kernel pin $KERNEL" || die "pinning $KERNEL"
fi
on_kernel=1
if [ -n "$KERNEL" ]; then
    for h in $NODES; do grep -qx "$KERNEL" "$EV/os_$h.log" || on_kernel=0; done
fi
if [ -n "$KERNEL" ] && [ $on_kernel = 0 ]; then
    reboot_all
    for h in $NODES; do
        on $h 15 "uname -r; cat /etc/os-release | grep PRETTY_NAME" > "$EV/os_$h.log" || die "$h is not answering over ssh"
        grep -qx "$KERNEL" "$EV/os_$h.log" || die "$h booted $(head -1 "$EV/os_$h.log"), not $KERNEL"
        say "$h: $(tr '\n' ' ' < "$EV/os_$h.log")"
    done
fi
for h in $NODES; do
    [ "$(head -1 "$EV/os_$h.log")" = "$(head -1 "$EV/os_$A.log")" ] || die "$h runs $(head -1 "$EV/os_$h.log") while $A runs $(head -1 "$EV/os_$A.log"): a round verifies one kernel"
done
pass "all $NN nodes on kernel $(head -1 "$EV/os_$A.log")"

# --- 1. install
for h in $NODES; do
    for p in $PKGS; do "$SSH" "$(addr $h)" SCP "$DIST/$p" /root/ > /dev/null 2>&1 || die "scp $p to $h"; done
done
files=""; for p in $PKGS; do files="$files /root/$p"; done
# A rebuilt candidate can carry a version the node already has.  Then apt and
# dnf would call it installed and do nothing, and DKMS would keep the module it
# built from the earlier source under the same version, so the round would test
# that one.  The DKMS registration of $V goes first and the install is forced.
case $FAM in
    rpm) inst="dnf reinstall -y $files 2>/dev/null || dnf install -y $files" ;;
    *)    inst="DEBIAN_FRONTEND=noninteractive apt-get install -y --reinstall --allow-downgrades $files" ;;
esac
t0=$(now)
# The old module must really be gone before the install: a modprobe -r that
# failed silently left the previous build loaded, the install then succeeded,
# and the round stopped at "did not load the DKMS build" with the new build
# installed but not running (rhel9 0.89.93, alma9-2).  Retried for 10 s, and
# the outcome is printed either way.
UNLOAD="for i in 1 2 3 4 5 6 7 8 9 10; do lsmod | grep -q '^mxfs ' || break; modprobe -r mxfs 2>/dev/null && break; sleep 1; done
        lsmod | grep -q '^mxfs ' && { echo \"UNLOAD_FAILED refcnt=\$(cat /sys/module/mxfs/refcnt) mounts=\$(grep -c ' mxfs ' /proc/mounts)\"; exit 1; }; echo UNLOADED"
if every install $INSTALL_S "grep -q ' mxfs ' /proc/mounts && umount $MNT; $UNLOAD; dkms remove mxfs/$V --all >/dev/null 2>&1; $inst"; then
    pass "install on all $NN ($(since $t0) s)"
else
    die "install (see $EV/install_*.log; rc 124 = over the ${INSTALL_S} s budget)"
fi
# Which build is loaded is read by srcversion, which tells two builds of one
# version apart: the loaded module's must be the installed file's, and that
# must be the one DKMS built for $V on the running kernel.
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
if [ $TRANSPORT = caw ]; then
    CONF_CAW=1
    every conf_caw 20 "sed -i 's/^options mxfs force_transport=1\$/options mxfs force_transport=0/' $MODCONF && grep -x 'options mxfs force_transport=0' $MODCONF" \
        || die "setting force_transport=0 in $MODCONF (see conf_caw_*.log)"
    pass "force_transport=0 set in $MODCONF on all $NN"
fi
MODID="$MODID
    echo force_transport=\$(cat /sys/module/mxfs/parameters/force_transport 2>/dev/null)"
# A CAW round switches the transport the way the README tells a user to: edit
# the file, then reload.  A plain modprobe is a no-op on a module the package
# already loaded, and the RPM's install leaves it loaded with the file's old
# value (measured on alma9: force_transport=1 after the edit).
if [ $TRANSPORT = caw ]; then
    every modload 30 "modprobe -r mxfs; modprobe mxfs; $MODID" || die "modprobe -r mxfs && modprobe mxfs"
else
    every modload 30 "modprobe mxfs; $MODID" || die "modprobe mxfs"
fi
for h in $NODES; do is_dkms_build $h "$EV/modload_$h.log" || die "$h did not load the DKMS build of $V"; done
for h in $NODES; do grep -qx "force_transport=$FT" "$EV/modload_$h.log" || die "$h loaded mxfs with $(grep '^force_transport=' "$EV/modload_$h.log"), not force_transport=$FT"; done
pass "the DKMS-built module is loaded on all $NN (force_transport=$FT)"

# --- 2. free the LUN and format
# a node that does not answer is not running, so it holds nothing
for h in $(lab_lun_nodes); do
    case " $NODES " in *" $h "*) continue ;; esac
    on $h 5 true >/dev/null 2>&1 || continue
    on $h 60 "for m in \$(awk '\$3 == \"mxfs\" {print \$2}' /proc/mounts); do timeout 30 umount \$m; done; grep -c ' mxfs ' /proc/mounts; true" > "$EV/free_lun_$h.log"
    [ "$(tail -1 "$EV/free_lun_$h.log")" = 0 ] || die "$h still has MXFS mounted; the LUN is not free"
done
every lun 60 "
    iscsiadm -m session 2>/dev/null | grep -qF $TGT || iscsiadm -m node -T $TGT -p $PORTAL --login >/dev/null 2>&1 || { iscsiadm -m discovery -t st -p $PORTAL >/dev/null && iscsiadm -m node -T $TGT -p $PORTAL --login >/dev/null; }
    # log in again at boot, as a host with a persistent shared LUN is set up;
    # a discovered node record defaults to manual on Debian and Proxmox
    iscsiadm -m node -T $TGT -p $PORTAL -o update -n node.startup -v automatic
    echo startup=\$(iscsiadm -m node -T $TGT -p $PORTAL | sed -n 's/^node.startup = //p')
    for i in \$(seq 1 10); do [ -b $LUN ] && break; sleep 1; done
    [ -b $LUN ] && echo lun_ok; mkdir -p $MNT" || die "the shared LUN is not present on every node"
for h in $NODES; do grep -q "^startup=automatic" "$EV/lun_$h.log" || die "$h: the storage target is not set to log in at boot"; done
on $A 30 "sg_persist --in --read-keys $LUN; sg_persist --out --register --param-sark=0x4d58465352455431 $LUN >/dev/null 2>&1; sg_persist --out --clear --param-rk=0x4d58465352455431 $LUN >/dev/null 2>&1; sg_persist --in --read-keys $LUN" > "$EV/pr_clear_$A.log" 2>&1
grep -q "NO registered reservation keys" "$EV/pr_clear_$A.log" || die "stale PR keys remain on the LUN (see pr_clear_$A.log)"
on $A 120 "mkfs.mxfs -f $LUN; echo mkfs_rc=\$?" > "$EV/mkfs_$A.log" 2>&1
grep -q "mkfs_rc=0" "$EV/mkfs_$A.log" && pass "mkfs.mxfs" || die "mkfs.mxfs (see mkfs_$A.log)"

# --- 3. mount with no options
mount_all() {  # label mode — mode: none (no options), peer (peer=/peers= by address), peers (peers=<all>)
    local t0 lbl=$1 mode=$2 h o ok=1
    t0=$(now)
    # A first: the first mount forms the cluster the others join
    for h in $NODES; do
        case $mode in
            none)  o="" ;;
            peer)  o=$(peer_opt $h) ;;
            peers) o="peers=$(all_addrs)" ;;
        esac
        on $h $MOUNT_S "mount -t mxfs ${o:+-o $o} $LUN $MNT; echo mount_rc=\$?" > "$EV/${lbl}_mount_$h.log" 2>&1
    done
    for h in $NODES; do grep -q mount_rc=0 "$EV/${lbl}_mount_$h.log" || ok=0; done
    if [ $ok = 1 ]; then
        pass "$lbl: all $NN mounted ($(since $t0) s)"
        # the transport each node actually runs, from this mount's own line
        every "${lbl}_transport" 15 "dmesg | grep 'P-DOMAIN-ADMITTED' | tail -1 | grep -o 'transport=[A-Z]*'" || true
        for h in $NODES; do
            grep -qx "transport=$TNAME" "$EV/${lbl}_transport_$h.log" || fail "$lbl: $h mounted on $(grep -o 'transport=[A-Z]*' "$EV/${lbl}_transport_$h.log" || echo 'no P-DOMAIN-ADMITTED line'), not transport=$TNAME"
        done
    else
        die "$lbl mount (see ${lbl}_mount_*.log)"
    fi
}
umount_all() {
    every "$1_umount" 60 "timeout 30 umount $MNT; grep -c ' $MNT mxfs ' /proc/mounts; true" || fail "$1: umount"
    for h in $NODES; do grep -qx 0 "$EV/$1_umount_$h.log" || fail "$1: $h still mounted"; done
}
xsum() {  # label: 64 MiB written on each node, md5 compared from every other node
    local lbl=$1 w r x y ok=1 t0
    t0=$(now)
    for w in $NODES; do
        x=$(on $w $IO_S "head -c 67108864 /dev/urandom > $MNT/$lbl.$w && sync && md5sum < $MNT/$lbl.$w | cut -d' ' -f1")
        for r in $(others $w); do
            y=$(on $r $IO_S "md5sum < $MNT/$lbl.$w | cut -d' ' -f1")
            echo "$lbl written on $w: $x read on $r: $y" >> "$EV/${lbl}_xsum.log"
            [ -n "$x" ] && [ "$x" = "$y" ] || ok=0
        done
    done
    [ $ok = 1 ] && pass "$lbl: cross-node checksums match on all $NN ($(since $t0) s)" || fail "$lbl: cross-node checksum (see ${lbl}_xsum.log)"
}
mount_all plain none
dmesg_line=$(on $A 10 "dmesg | grep -E 'MXFS-MEMBERSHIP|members=' | tail -1"); echo "$dmesg_line" > "$EV/plain_membership_$A.log"

# --- 4/5. checksums, create and remote delete
xsum plain
t0=$(now)
on $A $IO_S "mkdir $MNT/many && for i in \$(seq 1 500); do echo \$i > $MNT/many/f\$i; done; sync; ls $MNT/many | wc -l" > "$EV/create_$A.log" 2>&1
nb=$(on $B $IO_S "ls $MNT/many | wc -l; rm -f $MNT/many/f*; ls $MNT/many | wc -l" 2>&1 | tr '\n' ' ')
nrest=""
for h in $(others $B); do nrest="$nrest $h:$(on $h $IO_S "ls $MNT/many | wc -l")"; done
echo "created on $A: $(tail -1 "$EV/create_$A.log"); on $B before/after rm: $nb; afterwards:$nrest" | tee "$EV/create_rm.log"
rest_ok=1
for h in $(others $B); do case " $nrest " in *" $h:0 "*) ;; *) rest_ok=0 ;; esac; done
[ "$(tail -1 "$EV/create_$A.log")" = 500 ] && [ "$nb" = "500 0 " ] && [ $rest_ok = 1 ] \
    && pass "500 created on $A, removed on $B, 0 left on every node ($(since $t0) s)" || fail "create/remote delete (see create_rm.log)"

# --- 6. chk_mxfs
umount_all plain
on $A $CHK_S "chk_mxfs $LUN; echo chk_rc=\$?" > "$EV/chk_$A.log" 2>&1
grep -q "chk_rc=0" "$EV/chk_$A.log" && pass "chk_mxfs clean" || fail "chk_mxfs (see chk_$A.log)"

# --- 7. peer= with multicast dropped
case $FAM in
    rpm)  blk="firewall-cmd --direct --add-rule ipv4 filter INPUT 0 -d 224.0.0.0/4 -j DROP && firewall-cmd --direct --add-rule ipv4 filter OUTPUT 0 -d 224.0.0.0/4 -j DROP"
          unblk="firewall-cmd --direct --remove-rule ipv4 filter INPUT 0 -d 224.0.0.0/4 -j DROP; firewall-cmd --direct --remove-rule ipv4 filter OUTPUT 0 -d 224.0.0.0/4 -j DROP" ;;
    # Debian 13 has nftables and no iptables command; its own table is
    # dropped whole to undo it
    *)    blk="if command -v iptables >/dev/null; then iptables -I INPUT -d 224.0.0.0/4 -j DROP && iptables -I OUTPUT -d 224.0.0.0/4 -j DROP;
            else nft add table inet mxfs_mcast && nft add chain inet mxfs_mcast in { type filter hook input priority 0 \; } && nft add chain inet mxfs_mcast out { type filter hook output priority 0 \; } && nft add rule inet mxfs_mcast in ip daddr 224.0.0.0/4 drop && nft add rule inet mxfs_mcast out ip daddr 224.0.0.0/4 drop; fi"
          unblk="if command -v iptables >/dev/null; then iptables -D INPUT -d 224.0.0.0/4 -j DROP; iptables -D OUTPUT -d 224.0.0.0/4 -j DROP;
            else nft delete table inet mxfs_mcast; fi" ;;
esac
MCAST_BLOCKED=1
every mcast_block 20 "$blk" || die "blocking multicast"
mount_all peer peer
xsum peer
umount_all peer
every mcast_unblock 20 "$unblk" && MCAST_BLOCKED=0 || fail "restoring multicast"

# --- 7b. Proxmox: peers=, the storage plugin, DKMS on every installed kernel
if [ $FAM = pve ]; then
    mount_all peers peers
    xsum peers
    umount_all peers
    every dkms 30 "dkms status mxfs; ls /lib/modules" || fail "dkms status"
    for h in $NODES; do
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
mount_all dio none
"$HERE/tests/dio_stable_writes_read.sh" "$(addr $A)" $MNT 64 > "$EV/dio_stable_writes_$A.log" 2>&1
grep -q "RESULT PASS" "$EV/dio_stable_writes_$A.log" && pass "O_DIRECT read with stable writes" || die "O_DIRECT read with stable writes (see dio_stable_writes_$A.log)"

# --- 9. SELinux
if [ $FAM = rpm ]; then
    # A new filesystem's root carries no label until restorecon gives it one,
    # exactly as on XFS; new files then inherit from their directory.  Every
    # node remounts after the relabel so none holds the root's old label.
    on $A 30 "echo root_before=\$(stat -c %C $MNT); restorecon -v $MNT; echo root_after=\$(stat -c %C $MNT)" > "$EV/selinux_root_$A.log" 2>&1
    umount_all dio
    mount_all selinux none
    every selinux 60 "
        echo enforce=\$(getenforce)
        echo module=\$(semodule -l | grep -x mxfs)
        echo root=\$(stat -c %C $MNT)
        f=$MNT/selinux.\$(hostname -s); echo x > \$f
        echo new_file=\$(stat -c %C \$f)
        chcon -t virt_image_t \$f && echo chcon=\$(stat -c %C \$f)
        # --input-logs: over ssh stdin is a pipe, and without it ausearch
        # counts that (empty) stream instead of the audit log
        echo avc=\$(ausearch --input-logs -m avc,user_avc,selinux_err -ts boot </dev/null 2>&1 | grep -c 'type=AVC')" || fail "selinux commands"
    for h in $NODES; do
        grep -q "enforce=Enforcing" "$EV/selinux_$h.log" || fail "$h: SELinux is not enforcing"
        grep -q "module=mxfs" "$EV/selinux_$h.log" || fail "$h: the mxfs SELinux module is not installed"
        grep -q "root=.*unlabeled_t" "$EV/selinux_$h.log" && fail "$h: the relabeled root reads unlabeled_t"
        grep -q "new_file=.*unlabeled_t" "$EV/selinux_$h.log" && fail "$h: a new file is unlabeled_t"
        grep -q "chcon=.*virt_image_t" "$EV/selinux_$h.log" || fail "$h: chcon to virt_image_t did not stick"
        grep -q "avc=0" "$EV/selinux_$h.log" || fail "$h: AVC denials since boot"
    done
    # A's relabel as every peer sees it: at once, and after the peer drops its caches
    fa=$MNT/selinux.$(on $A 5 'hostname -s')
    for h in $(others $A); do
        lb1=$(on $h 20 "stat -c %C $fa")
        lb2=$(on $h 20 "echo 3 > /proc/sys/vm/drop_caches; stat -c %C $fa")
        echo "$A's virt_image_t file as seen from $h: at once $lb1, after drop_caches $lb2" | tee -a "$EV/selinux_cross.log"
        case "$lb2" in *virt_image_t*) ;; *) fail "$h does not read $A's label from the platter" ;; esac
    done
    say "SELinux: $(tr '\n' ' ' < "$EV/selinux_root_$A.log") $(grep -h 'root=\|new_file=' "$EV/selinux_$A.log" | tr '\n' ' ')"
    pass "SELinux checks ran (failures above, if any)"
    DIO_OR_SELINUX=selinux
else
    DIO_OR_SELINUX=dio
fi

# --- 10. reboot
x=$(on $A $IO_S "head -c 16777216 /dev/urandom > $MNT/marker && sync && md5sum < $MNT/marker | cut -d' ' -f1")
[ -n "$x" ] || fail "writing the marker"
umount_all $DIO_OR_SELINUX
reboot_all
every postboot 60 "
    echo kernel=\$(uname -r)
    echo module=\$(lsmod | grep -c '^mxfs ')
    $MODID
    for i in \$(seq 1 30); do [ -b $LUN ] && break; sleep 1; done; [ -b $LUN ] && echo lun=ok
    command -v firewall-cmd >/dev/null && echo firewalld=\$(systemctl is-active firewalld) ports=\$(firewall-cmd --list-ports | tr ' ' ,)
    true" || fail "postboot checks"
for h in $NODES; do
    [ -z "$KERNEL" ] || grep -qx "kernel=$KERNEL" "$EV/postboot_$h.log" || fail "$h did not boot back into $KERNEL"
    grep -q "module=1" "$EV/postboot_$h.log" || fail "$h: module not auto-loaded"
    is_dkms_build $h "$EV/postboot_$h.log" || fail "$h: the module auto-loaded at boot is not the DKMS build of $V"
    grep -q "lun=ok" "$EV/postboot_$h.log" || fail "$h: LUN not back after boot"
    grep -qx "force_transport=$FT" "$EV/postboot_$h.log" || fail "$h: auto-loaded with $(grep '^force_transport=' "$EV/postboot_$h.log"), not force_transport=$FT"
    # the README's firewall line opens 7602/udp for CAW's lock-release requests
    if [ $TRANSPORT = caw ] && grep -q '^firewalld=active' "$EV/postboot_$h.log"; then
        grep -q 'ports=.*7602/udp' "$EV/postboot_$h.log" || fail "$h: firewalld is active and 7602/udp (CAW lock-release requests) is not open"
    fi
done
mount_all postboot none
ys=""; marker_ok=1
for h in $NODES; do
    y=$(on $h $IO_S "md5sum < $MNT/marker | cut -d' ' -f1")
    ys="$ys $h $y"
    [ "$x" = "$y" ] || marker_ok=0
done
echo "marker before reboot $x, after:$ys" | tee "$EV/marker.log"
[ $marker_ok = 1 ] && pass "data intact across the reboot on all $NN" || fail "marker md5 after reboot"
umount_all postboot

if [ $FAILS = 0 ]; then say "RESULT PASS"; exit 0; fi
say "RESULT FAIL ($FAILS failed)"
exit 1
