#!/bin/bash
# MXFS LIO/tcm_loop shared-LUN setup — HOST side (clyde), no iSCSI.
#
# Builds the shared block device used by the test cluster entirely on the
# local host via LIO's loopback fabric (tcm_loop):
#
#   /home/steve/disk.img  ->  fileio backstore "mxfs"  ->  tcm_loop LUN 0  ->  /dev/sdX
#
# tcm_loop instantiates a virtual SCSI HBA inside the host kernel and maps the
# LIO backstore onto it, so the LUN shows up as a normal local SCSI disk on
# clyde.  No iSCSI initiator/target, no network.  That /dev/sdX is then passed
# straight into each VM with libvirt `device='lun'` passthrough (separate step).
#
# This path does NOT support SCSI COMPARE AND WRITE reliably (old LIO limitation)
# — it is intended for testing MXFS with the **TCP DLM** transport, which needs
# no CAW/PR.  Use SCST if you need CAW.
#
# Usage:
#   scripts/lio_tcm_setup.sh setup       # create backstore + loopback LUN
#   scripts/lio_tcm_setup.sh status      # show current config + device
#   scripts/lio_tcm_setup.sh teardown    # remove the LIO config (leaves disk.img)
#
# Idempotent: re-running setup reuses existing objects.

set -u

IMG="${MXFS_LIO_IMG:-/home/steve/disk.img}"
BSNAME="${MXFS_LIO_BSNAME:-mxfs}"          # backstore name == SCSI INQUIRY model
CORE=/sys/kernel/config/target/core
LOOP=/sys/kernel/config/target/loopback
# Stable name the VMs reference.  The kernel sdX letter and the by-id WWN both
# change across a teardown/re-setup (targetcli regenerates the backstore UUID),
# so we maintain one fixed symlink and re-point it on every setup.  VM XML uses
# /dev/mxfs-shared and never needs editing when the LIO stack is rebuilt.
SYMLINK=/dev/mxfs-shared

say()  { echo "$@"; }
fail() { echo "LIO_SETUP_FAIL: $*" >&2; exit 1; }

need_root() { [ "$(id -u)" -eq 0 ] && SUDO="" || SUDO="sudo"; }

# Symmetric guard to scst_setup.sh's release_lio(): SCST and LIO/tcm_loop cannot
# both export the same backing file — a double export corrupts the LUN.  If the
# SCST stack is currently holding the shared device, tear it down before we take
# the LUN over for tcm_loop (this is the intended "switch back to TCP-on-LIO"
# path from a CAW-on-SCST session).
release_scst() {
    local scstsetup="$(dirname "$0")/scst_setup.sh"
    local scstdev=/sys/kernel/scst_tgt/devices/mxfs
    if [ -d "$scstdev" ]; then
        say "NOTE: SCST is holding the shared LUN — tearing it down"
        say "      (TCP-on-LIO and CAW-on-SCST are mutually exclusive on $IMG)"
        [ -x "$scstsetup" ] && $SUDO "$scstsetup" teardown \
            || say "WARN: could not run scst_setup.sh teardown — check SCST manually"
    fi
}

load_modules() {
    for m in target_core_mod target_core_file tcm_loop; do
        $SUDO modprobe "$m" 2>/dev/null || fail "modprobe $m failed"
    done
    mount | grep -q ' /sys/kernel/config ' || $SUDO mount -t configfs none /sys/kernel/config \
        || fail "configfs not mounted and mount failed"
}

# Find the /dev/sdX that LIO is presenting for our backstore (vendor LIO-ORG,
# model == $BSNAME).  Empty if not present yet.
find_dev() {
    local b v mdl
    for b in /sys/block/sd*; do
        [ -e "$b/device/vendor" ] || continue
        v=$($SUDO cat "$b/device/vendor" 2>/dev/null | tr -d ' ')
        mdl=$($SUDO cat "$b/device/model" 2>/dev/null | tr -d ' ')
        if [ "$v" = "LIO-ORG" ] && [ "$mdl" = "$BSNAME" ]; then
            echo "/dev/$(basename "$b")"; return 0
        fi
    done
    return 1
}

# Locate an existing loopback target whose LUN maps our backstore.
find_loop_wwn() {
    local w
    for w in $($SUDO ls "$LOOP" 2>/dev/null | grep '^naa'); do
        if $SUDO ls -l "$LOOP/$w"/tpgt_*/lun/lun_*/ 2>/dev/null | grep -qE "fileio_[0-9]+/$BSNAME$"; then
            echo "$w"; return 0
        fi
    done
    return 1
}

setup() {
    [ -f "$IMG" ] || fail "backing file $IMG does not exist (create it first)"
    need_root
    release_scst
    load_modules

    # 1. fileio backstore over disk.img — WRITE-THROUGH (write_back=false =
    #    O_DSYNC data path) with WCE=1 advertised.  Two independent lessons
    #    from ccloop run a16ec5f2:
    #    - target_check_fua() only accepts the FUA bit on READ/WRITE CDBs when
    #      emulate_fua_write AND emulate_write_cache are both set.  With WCE=0
    #      every WRITE(16)+FUA from mxfs's release-drain was rejected ILLEGAL
    #      REQUEST -> rc=-5 (5461 rejections), so keep WCE=1.
    #    - With the default buffered (write_back=true) mode + WCE=1, guests
    #      re-probe DPOFUA and the guest xlog adds PREFLUSH/FUA to every iclog
    #      write; each SYNCHRONIZE CACHE then fsyncs the whole dirty backing
    #      file.  Measured on drc 8/tcp: write phases ~doubled (create 4.6->7.7s,
    #      rm gap 3.6->8s, verify unchanged) -> 24 rounds no longer fit the
    #      480s budget.  write_back=false makes every write O_DSYNC-durable so
    #      SYNC CACHE / FUA fsyncs are no-ops, keeping honest semantics AND
    #      run7-era pace.  (NVMe backing: per-write sync cost is negligible.)
    if ! $SUDO targetcli /backstores/fileio ls 2>/dev/null | grep -qE "o- $BSNAME "; then
        $SUDO targetcli /backstores/fileio create name="$BSNAME" file_or_dev="$IMG" write_back=false \
            || fail "backstore create failed"
        $SUDO targetcli "/backstores/fileio/$BSNAME" set attribute emulate_write_cache=1 \
            || say "WARN: could not set emulate_write_cache=1"
        say "backstore created: fileio/$BSNAME -> $IMG"
    else
        say "backstore already present: fileio/$BSNAME"
    fi

    # 2. tcm_loop target + LUN 0 mapping (this is what makes /dev/sdX appear).
    local WWN
    if WWN=$(find_loop_wwn); then
        say "loopback target already maps $BSNAME: $WWN"
    else
        local out
        out=$($SUDO targetcli /loopback create 2>&1) || fail "loopback create failed: $out"
        WWN=$(echo "$out" | grep -oE 'naa\.[0-9a-f]+' | head -1)
        [ -n "$WWN" ] || fail "could not parse loopback WWN from: $out"
        $SUDO targetcli "/loopback/$WWN/luns" create "/backstores/fileio/$BSNAME" \
            || fail "LUN mapping failed"
        say "loopback target created: $WWN, LUN0 -> $BSNAME"
    fi

    # 3. persist so it survives a target service restart.
    $SUDO targetcli saveconfig >/dev/null 2>&1 || say "WARN: saveconfig failed"

    # 4. settle + discover the device (rescan the tcm_loop host if needed).
    local dev i
    for i in $(seq 1 10); do
        dev=$(find_dev) && break
        for h in /sys/class/scsi_host/host*; do
            echo '- - -' | $SUDO tee "$h/scan" >/dev/null 2>&1 || true
        done
        sleep 1
    done
    dev=$(find_dev) || fail "LUN created but no /dev/sdX appeared (vendor LIO-ORG model $BSNAME)"

    # 5. (re)point the stable symlink the VMs reference.
    $SUDO ln -sfn "$dev" "$SYMLINK" || say "WARN: could not create $SYMLINK"
    say "stable symlink: $SYMLINK -> $dev"

    say "LIO_SETUP_OK device=$dev symlink=$SYMLINK backstore=$BSNAME wwn=${WWN:-?} img=$IMG"
}

status() {
    need_root
    if [ ! -d "$LOOP" ]; then say "LIO target not loaded / no config"; return 0; fi
    say "=== backstores/fileio ==="
    $SUDO targetcli /backstores/fileio ls 2>/dev/null
    say "=== loopback ==="
    $SUDO targetcli /loopback ls 2>/dev/null
    local dev
    if dev=$(find_dev); then
        say "=== host device ==="
        say "$dev  ($($SUDO cat /sys/block/$(basename "$dev")/size 2>/dev/null | awk '{print $1*512/1024/1024/1024" GiB"}'))"
    else
        say "no host /dev/sdX presented for backstore $BSNAME"
    fi
}

teardown() {
    need_root
    local WWN
    if WWN=$(find_loop_wwn); then
        $SUDO targetcli "/loopback/$WWN/tpgt1/luns" delete 0 2>/dev/null \
            || $SUDO targetcli "/loopback/$WWN/luns" delete 0 2>/dev/null || true
        $SUDO targetcli /loopback delete "$WWN" 2>/dev/null || true
        say "removed loopback target $WWN"
    fi
    if $SUDO targetcli /backstores/fileio ls 2>/dev/null | grep -qE "o- $BSNAME "; then
        $SUDO targetcli /backstores/fileio delete "$BSNAME" 2>/dev/null || true
        say "removed backstore $BSNAME"
    fi
    [ -L "$SYMLINK" ] && $SUDO rm -f "$SYMLINK"
    $SUDO targetcli saveconfig >/dev/null 2>&1 || true
    say "LIO_TEARDOWN_OK (disk.img left intact: $IMG)"
}

case "${1:-}" in
    setup)    setup ;;
    status)   status ;;
    teardown) teardown ;;
    *) echo "usage: $0 {setup|status|teardown}" >&2; exit 2 ;;
esac
